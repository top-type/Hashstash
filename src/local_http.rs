//! HTTP serving for the loopback faucet and cold signer. Each connection must
//! send every request head within a deadline, which also ends idle keep-alive
//! connections, and only a bounded number of connections are served at once.
//! At that bound a new connection takes the place of the one idle longest, so
//! connections held open never keep another client out.
use axum::Router;
use hyper::{
    Request,
    body::Incoming,
    server::conn::http1,
    service::{Service, service_fn},
};
use hyper_util::{
    rt::{TokioIo, TokioTimer},
    service::TowerToHyperService,
};
use std::{
    collections::BTreeMap,
    future::Future,
    io::ErrorKind,
    pin::pin,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    net::TcpListener,
    sync::{Notify, watch},
    task::JoinSet,
};

/// How long a connection may take to send a request head, counted from when
/// it opens or finishes its previous response, so idle keep-alive time counts.
pub const HEAD_TIMEOUT: Duration = Duration::from_secs(5);

/// One served connection as admission sees it.
struct Slot {
    /// Set while the connection handles a request.
    busy: Arc<AtomicBool>,
    /// When it was accepted or last finished handling a request.
    idle_since: Instant,
    /// Asks it to give way to a newer connection.
    evict: Arc<Notify>,
}

/// The connections being served, by accept order.
#[derive(Default)]
struct Slots(Mutex<BTreeMap<u64, Slot>>);
impl Slots {
    /// Admits connection `id` while fewer than `limit` are served. At the
    /// limit the connection idle longest, between requests or never used, is
    /// closed in its favour; only when every connection is handling a request
    /// is the new one refused.
    fn admit(&self, id: u64, limit: usize) -> Option<(Arc<AtomicBool>, Arc<Notify>)> {
        let mut open = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if open.len() >= limit {
            let victim = open
                .iter()
                .filter(|(_, slot)| !slot.busy.load(Ordering::Acquire))
                .min_by_key(|(_, slot)| slot.idle_since)
                .map(|(id, _)| *id)?;
            if let Some(slot) = open.remove(&victim) {
                slot.evict.notify_one();
            }
        }
        let slot = Slot {
            busy: Arc::default(),
            idle_since: Instant::now(),
            evict: Arc::default(),
        };
        let handles = (slot.busy.clone(), slot.evict.clone());
        open.insert(id, slot);
        Some(handles)
    }
    fn idle(&self, id: u64) {
        let mut open = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(slot) = open.get_mut(&id) {
            slot.idle_since = Instant::now();
        }
    }
    fn close(&self, id: u64) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&id);
    }
}

/// Marks a connection busy while it handles one request.
struct Handling {
    slots: Arc<Slots>,
    id: u64,
    busy: Arc<AtomicBool>,
}
impl Drop for Handling {
    fn drop(&mut self) {
        self.slots.idle(self.id);
        self.busy.store(false, Ordering::Release);
    }
}

/// Serves `routes` until `shutdown` completes, then lets open requests finish.
/// `axum::serve` builds hyper without a timer, so hyper's header timeout never
/// runs there and a silent or partial connection stays open indefinitely.
/// Here a connection must send each request head within `head`, and at most
/// `connections` are served at once. Beyond that a new connection replaces
/// the one idle longest, which is closed at once, so a client keeps a
/// connection only while it uses it. Only when every connection is handling
/// a request is the new one closed instead, as soon as it is accepted.
pub async fn serve(
    listener: TcpListener,
    routes: Router,
    connections: usize,
    head: Duration,
    shutdown: impl Future<Output = ()> + Send,
) {
    let slots = Arc::new(Slots::default());
    let (closing, closed) = watch::channel(());
    let mut served = JoinSet::new();
    let mut shutdown = pin!(shutdown);
    let mut id = 0u64;
    loop {
        let stream = tokio::select! {
            () = &mut shutdown => break,
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => stream,
                Err(error) => {
                    // One client's failed handshake is skipped. Anything else,
                    // such as running out of descriptors, would otherwise spin.
                    if !matches!(
                        error.kind(),
                        ErrorKind::ConnectionAborted
                            | ErrorKind::ConnectionReset
                            | ErrorKind::ConnectionRefused
                    ) {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                    continue;
                }
            },
        };
        while served.try_join_next().is_some() {}
        id = id.wrapping_add(1);
        let Some((busy, evict)) = slots.admit(id, connections) else {
            drop(stream);
            continue;
        };
        let service = {
            let (routes, slots, busy) = (
                TowerToHyperService::new(routes.clone()),
                slots.clone(),
                busy.clone(),
            );
            service_fn(move |request: Request<Incoming>| {
                busy.store(true, Ordering::Release);
                let handling = Handling {
                    slots: slots.clone(),
                    id,
                    busy: busy.clone(),
                };
                let response = routes.call(request);
                async move {
                    let _handling = handling;
                    response.await
                }
            })
        };
        let (slots, mut closed) = (slots.clone(), closed.clone());
        served.spawn(async move {
            let mut builder = http1::Builder::new();
            builder.timer(TokioTimer::new()).header_read_timeout(head);
            let mut connection = pin!(builder.serve_connection(TokioIo::new(stream), service));
            tokio::select! {
                _ = connection.as_mut() => {}
                () = evict.notified() => {
                    // A newer connection took this idle one's place. Nothing
                    // starts while this runs, as the connection is not polled;
                    // a request that started after it was chosen finishes.
                    if busy.load(Ordering::Acquire) {
                        connection.as_mut().graceful_shutdown();
                        let _ = connection.as_mut().await;
                    }
                }
                _ = closed.changed() => {
                    // Finish a request in progress; an idle connection closes.
                    connection.as_mut().graceful_shutdown();
                    let _ = connection.as_mut().await;
                }
            }
            slots.close(id);
        });
    }
    drop(listener);
    drop(closing);
    while served.join_next().await.is_some() {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;
    use std::net::SocketAddr;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpStream,
        sync::{Semaphore, mpsc, oneshot},
        time::Instant,
    };

    /// A server whose `/wait` requests report that they started and then
    /// wait for a permit from the returned semaphore.
    async fn server(
        connections: usize,
        head: Duration,
    ) -> (
        SocketAddr,
        oneshot::Sender<()>,
        tokio::task::JoinHandle<()>,
        Arc<Semaphore>,
        mpsc::UnboundedReceiver<()>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let release = Arc::new(Semaphore::new(0));
        let (started, waiting) = mpsc::unbounded_channel();
        let gate = release.clone();
        let routes = Router::new().route("/", get(|| async { "ok" })).route(
            "/wait",
            get(move || {
                let (gate, started) = (gate.clone(), started.clone());
                async move {
                    started.send(()).unwrap();
                    gate.acquire().await.unwrap().forget();
                    "waited"
                }
            }),
        );
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(serve(listener, routes, connections, head, async {
            let _ = stopped.await;
        }));
        (address, stop, task, release, waiting)
    }

    /// Sends a keep-alive GET for `path` and reads its whole response.
    async fn exchange(stream: &mut TcpStream, path: &str) -> String {
        stream
            .write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
            .await
            .unwrap();
        response(stream).await
    }

    async fn response(stream: &mut TcpStream) -> String {
        let mut received = Vec::new();
        loop {
            let text = String::from_utf8_lossy(&received).into_owned();
            if let Some((head, body)) = text.split_once("\r\n\r\n") {
                let length = head
                    .lines()
                    .find_map(|line| {
                        let line = line.to_ascii_lowercase();
                        line.strip_prefix("content-length:")
                            .map(|value| value.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                if body.len() >= length {
                    return text;
                }
            }
            let mut buffer = [0; 512];
            let read = stream.read(&mut buffer).await.unwrap();
            assert!(read > 0, "closed before the response");
            received.extend_from_slice(&buffer[..read]);
        }
    }

    /// Reads until the server closes the connection, returning what it sent
    /// and when it closed.
    async fn until_closed(stream: &mut TcpStream) -> (Vec<u8>, Instant) {
        let mut received = Vec::new();
        let mut buffer = [0; 1024];
        loop {
            match stream.read(&mut buffer).await {
                Ok(0) | Err(_) => return (received, Instant::now()),
                Ok(read) => received.extend_from_slice(&buffer[..read]),
            }
        }
    }

    #[tokio::test]
    async fn partial_heads_and_idle_keep_alive_connections_close_after_the_head_timeout() {
        let head = Duration::from_millis(400);
        let (address, stop, task, ..) = server(4, head).await;
        // A partial head, a silent connection, and a keep-alive connection
        // after its response are each closed once the head deadline passes.
        let started = Instant::now();
        let mut partial = TcpStream::connect(address).await.unwrap();
        partial
            .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n")
            .await
            .unwrap();
        let mut silent = TcpStream::connect(address).await.unwrap();
        let mut reused = TcpStream::connect(address).await.unwrap();
        reused
            .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        while !response.ends_with(b"\r\n\r\nok") {
            let mut buffer = [0; 512];
            let read = reused.read(&mut buffer).await.unwrap();
            assert!(read > 0, "closed before the response");
            response.extend_from_slice(&buffer[..read]);
        }
        assert!(response.starts_with(b"HTTP/1.1 200 OK"));
        let answered = Instant::now();
        for stream in [&mut partial, &mut silent] {
            let (received, closed) =
                tokio::time::timeout(Duration::from_secs(5), until_closed(stream))
                    .await
                    .expect("connection was held past the head timeout");
            assert!(received.is_empty());
            assert!(closed - started >= head - Duration::from_millis(50));
        }
        let (received, closed) =
            tokio::time::timeout(Duration::from_secs(5), until_closed(&mut reused))
                .await
                .expect("idle keep-alive connection was held past the head timeout");
        assert!(received.is_empty());
        assert!(closed - answered >= head - Duration::from_millis(50));
        stop.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn at_the_cap_a_new_connection_replaces_the_one_idle_longest() {
        let (address, stop, task, release, mut waiting) = server(2, Duration::from_secs(30)).await;
        // Accepted in order: one connection never sends anything, and the
        // other has finished a request since.
        let mut silent = TcpStream::connect(address).await.unwrap();
        let mut used = TcpStream::connect(address).await.unwrap();
        assert!(
            exchange(&mut used, "/")
                .await
                .starts_with("HTTP/1.1 200 OK")
        );
        // Holding both open does not keep a third out. It takes the place of
        // the one idle longest, closed unanswered long before the head timeout.
        let mut third = TcpStream::connect(address).await.unwrap();
        let (received, _) = tokio::time::timeout(Duration::from_secs(5), until_closed(&mut silent))
            .await
            .expect("the connection idle longest was kept");
        assert!(received.is_empty());
        assert!(
            exchange(&mut third, "/")
                .await
                .starts_with("HTTP/1.1 200 OK")
        );
        // A keep-alive connection idle since its response gives way the same way.
        let mut fourth = TcpStream::connect(address).await.unwrap();
        let (received, _) = tokio::time::timeout(Duration::from_secs(5), until_closed(&mut used))
            .await
            .expect("the connection idle longest was kept");
        assert!(received.is_empty());
        assert!(
            exchange(&mut fourth, "/")
                .await
                .starts_with("HTTP/1.1 200 OK")
        );
        // While every connection is handling a request, a new one is closed
        // at once instead, and the requests in progress still complete.
        for stream in [&mut third, &mut fourth] {
            stream
                .write_all(b"GET /wait HTTP/1.1\r\nHost: x\r\n\r\n")
                .await
                .unwrap();
        }
        for _ in 0..2 {
            tokio::time::timeout(Duration::from_secs(5), waiting.recv())
                .await
                .unwrap()
                .unwrap();
        }
        let mut refused = TcpStream::connect(address).await.unwrap();
        let (received, _) =
            tokio::time::timeout(Duration::from_secs(5), until_closed(&mut refused))
                .await
                .expect("a connection was admitted while every one was busy");
        assert!(received.is_empty());
        release.add_permits(2);
        for stream in [&mut third, &mut fourth] {
            let answer = tokio::time::timeout(Duration::from_secs(5), response(stream))
                .await
                .unwrap();
            assert!(answer.starts_with("HTTP/1.1 200 OK") && answer.ends_with("waited"));
        }
        // Shutdown closes idle connections and returns.
        stop.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
        for stream in [&mut third, &mut fourth] {
            let (received, _) = tokio::time::timeout(Duration::from_secs(5), until_closed(stream))
                .await
                .unwrap();
            assert!(received.is_empty());
        }
    }
}
