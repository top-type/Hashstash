//! HTTP serving for the loopback faucet and cold signer. Each connection must
//! send every request head within a deadline, which also ends idle keep-alive
//! connections, and only a bounded number of connections are served at once.
use axum::Router;
use hyper::server::conn::http1;
use hyper_util::{
    rt::{TokioIo, TokioTimer},
    service::TowerToHyperService,
};
use std::{future::Future, io::ErrorKind, pin::pin, sync::Arc, time::Duration};
use tokio::{
    net::TcpListener,
    sync::{Semaphore, watch},
    task::JoinSet,
};

/// How long a connection may take to send a request head, counted from when
/// it opens or finishes its previous response, so idle keep-alive time counts.
pub const HEAD_TIMEOUT: Duration = Duration::from_secs(5);

/// Serves `routes` until `shutdown` completes, then lets open requests finish.
/// `axum::serve` builds hyper without a timer, so hyper's header timeout never
/// runs there and a silent or partial connection stays open indefinitely.
/// Here a connection must send each request head within `head`, and at most
/// `connections` are served at once; a connection beyond that is closed as
/// soon as it is accepted, before any byte is read.
pub async fn serve(
    listener: TcpListener,
    routes: Router,
    connections: usize,
    head: Duration,
    shutdown: impl Future<Output = ()> + Send,
) {
    let permits = Arc::new(Semaphore::new(connections));
    let (closing, closed) = watch::channel(());
    let mut served = JoinSet::new();
    let mut shutdown = pin!(shutdown);
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
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            drop(stream);
            continue;
        };
        let service = TowerToHyperService::new(routes.clone());
        let mut closed = closed.clone();
        served.spawn(async move {
            let _permit = permit;
            let mut builder = http1::Builder::new();
            builder.timer(TokioTimer::new()).header_read_timeout(head);
            let mut connection = pin!(builder.serve_connection(TokioIo::new(stream), service));
            tokio::select! {
                _ = connection.as_mut() => {}
                _ = closed.changed() => {
                    // Finish a request in progress; an idle connection closes.
                    connection.as_mut().graceful_shutdown();
                    let _ = connection.as_mut().await;
                }
            }
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
        sync::oneshot,
        time::Instant,
    };

    async fn server(
        connections: usize,
        head: Duration,
    ) -> (SocketAddr, oneshot::Sender<()>, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let routes = Router::new().route("/", get(|| async { "ok" }));
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(serve(listener, routes, connections, head, async {
            let _ = stopped.await;
        }));
        (address, stop, task)
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
        let (address, stop, task) = server(4, head).await;
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
    async fn connections_beyond_the_cap_close_at_once_until_one_frees() {
        let (address, stop, task) = server(2, Duration::from_secs(30)).await;
        let mut held = Vec::new();
        for _ in 0..2 {
            held.push(TcpStream::connect(address).await.unwrap());
        }
        // Accepted in order, so the third is the one over the cap. It is
        // closed long before the head timeout.
        let mut refused = TcpStream::connect(address).await.unwrap();
        let (received, _) =
            tokio::time::timeout(Duration::from_secs(5), until_closed(&mut refused))
                .await
                .expect("a connection over the cap was held");
        assert!(received.is_empty());
        // Admitted connections are still served.
        held[0]
            .write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let (answer, _) = tokio::time::timeout(Duration::from_secs(5), until_closed(&mut held[0]))
            .await
            .unwrap();
        assert!(answer.starts_with(b"HTTP/1.1 200 OK"));
        // That connection's slot is free again for a new one.
        let mut next = None;
        for _ in 0..50 {
            let mut stream = TcpStream::connect(address).await.unwrap();
            stream
                .write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            let (answer, _) =
                tokio::time::timeout(Duration::from_secs(5), until_closed(&mut stream))
                    .await
                    .unwrap();
            if !answer.is_empty() {
                next = Some(answer);
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(next.unwrap().starts_with(b"HTTP/1.1 200 OK"));
        // Shutdown closes idle connections and returns.
        stop.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
        let (received, _) =
            tokio::time::timeout(Duration::from_secs(5), until_closed(&mut held[1]))
                .await
                .unwrap();
        assert!(received.is_empty());
    }
}
