//! Explorer worker supervision: failed and panicking updates are retried on a
//! timer, without waiting for another block, and never end the worker.
use super::*;

fn indexed_tip(database: &Path) -> Option<String> {
    let path = crate::local_files::sidecar(database, "explorer.sqlite");
    let db =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .ok()?;
    db.query_row("SELECT value FROM explorer_meta WHERE key='tip'", [], |r| {
        r.get(0)
    })
    .ok()
}

fn eventually(mut condition: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if condition() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    condition()
}

#[test]
fn failed_and_panicking_updates_retry_without_another_notification() {
    let directory = tempfile::tempdir().unwrap();
    let config = Config::devnet();
    let miner = crypto::public_key(&[71; 32]).unwrap();
    let node = Node::open(
        &directory.path().join("chain.sqlite"),
        config.clone(),
        miner,
    )
    .unwrap();
    // A second index of the same node, driven only by this test's notifications.
    let database = directory.path().join("index.sqlite");
    let mut explorer = Explorer::open(&database, &lock_inner(&node.inner).chain).unwrap();
    explorer.retry_delay = Duration::from_millis(50);
    let faults = Arc::new(Mutex::new(VecDeque::from(["error", "panic", "error"])));
    let injected = faults.clone();
    explorer.hooks.before_apply = Some(Box::new(move || {
        let fault = injected.lock().unwrap().pop_front();
        match fault {
            Some("panic") => panic!("injected explorer panic"),
            Some(_) => bail!("injected explorer failure"),
            None => Ok(()),
        }
    }));
    let worker = ExplorerWorker::start(explorer, Arc::downgrade(&node.inner), config);
    let genesis = hex::encode(node.read_view().unwrap().chain.tip_hash());
    assert_eq!(indexed_tip(&database), Some(genesis));
    node.mine(1_000_000).unwrap();
    let tip = hex::encode(node.read_view().unwrap().chain.tip_hash());
    // The only notification. Each failure, and the panic, waits for its retry
    // time; an idle chain used to leave the index behind until another block.
    worker.notify();
    assert!(
        eventually(|| indexed_tip(&database).as_deref() == Some(tip.as_str())),
        "index stayed at {:?}",
        indexed_tip(&database)
    );
    assert!(faults.lock().unwrap().is_empty());
    assert!(!worker.thread.as_ref().unwrap().is_finished());
    // The same worker keeps following the chain.
    node.mine(1_000_000).unwrap();
    let next = hex::encode(node.read_view().unwrap().chain.tip_hash());
    worker.notify();
    assert!(eventually(
        || indexed_tip(&database).as_deref() == Some(next.as_str())
    ));
    drop(worker);
}

#[test]
fn a_stopped_worker_is_reported_once() {
    let (sender, receiver) = mpsc::sync_channel(1);
    drop(receiver);
    let worker = ExplorerWorker {
        sender: Some(sender),
        thread: None,
        gone: AtomicBool::new(false),
    };
    worker.notify();
    assert!(worker.gone.load(Ordering::Relaxed));
    // Later notifications neither block nor log again.
    worker.notify();
    assert!(worker.gone.load(Ordering::Relaxed));
}
