//! Failure injection for local ledger transactions. No node or signer is used.
use super::*;

fn private_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    dir
}

fn deposit() -> Deposit {
    Deposit {
        id: "01".repeat(32),
        sender: "02".repeat(32),
        remaining: 250u32.into(),
        deadline: 3700,
        height: 1,
        block: "03".repeat(32),
        state: "queued".into(),
    }
}

fn payment(refund: bool) -> Outgoing {
    Outgoing {
        id: 0,
        deposit: deposit().id,
        slot: if refund { None } else { Some(1) },
        amount: Amount::from(if refund { 247u32 } else { 100u32 }),
        service: Amount::from(if refund { 0u32 } else { 1u32 }),
        cap: 10u32.into(),
        nonce: 0,
        expiry: 20,
        height: 2,
        txid: "04".repeat(32),
        raw: "journalled bytes; not a transaction fixture".into(),
    }
}

fn snapshot(ledger: &Ledger) -> Vec<Vec<Vec<String>>> {
    [
        "SELECT * FROM meta ORDER BY k",
        "SELECT * FROM deposits ORDER BY id",
        "SELECT * FROM slots ORDER BY id",
        "SELECT * FROM outbox ORDER BY id",
    ]
    .into_iter()
    .map(|sql| {
        let mut statement = ledger.db.prepare(sql).unwrap();
        let count = statement.column_count();
        statement
            .query_map([], |row| {
                (0..count)
                    .map(|i| row.get_ref(i).map(|v| format!("{v:?}")))
                    .collect::<rusqlite::Result<Vec<_>>>()
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
    })
    .collect()
}

fn inject(ledger: &Ledger, trigger: &str) {
    ledger
        .db
        .execute_batch(&format!(
            "CREATE TEMP TRIGGER fail_write {trigger} BEGIN SELECT RAISE(ABORT,'injected write failure'); END;"
        ))
        .unwrap();
}

fn seeded(path: &Path) -> Ledger {
    let mut ledger = Ledger::open(path, "failure-injection").unwrap();
    ledger
        .add(&deposit(), &["first".into(), "second".into()], 100)
        .unwrap();
    ledger
        .db
        .execute("UPDATE slots SET state='ready' WHERE id=1", [])
        .unwrap();
    ledger
}

#[test]
fn deposit_and_every_slot_survive_or_roll_back_together() {
    let dir = private_dir();
    let path = dir.path().join("ledger.sqlite");
    let mut ledger = Ledger::open(&path, "failure-injection").unwrap();
    let before = snapshot(&ledger);
    inject(&ledger, "BEFORE INSERT ON slots WHEN NEW.address='second'");
    assert!(
        ledger
            .add(&deposit(), &["first".into(), "second".into()], 100)
            .is_err()
    );
    assert_eq!(snapshot(&ledger), before);
    drop(ledger);
    let mut ledger = Ledger::open(&path, "failure-injection").unwrap();
    assert_eq!(snapshot(&ledger), before);
    ledger
        .add(&deposit(), &["first".into(), "second".into()], 100)
        .unwrap();
    assert_eq!(ledger.deposits().unwrap().len(), 1);
    let slots: u32 = ledger
        .db
        .query_row("SELECT COUNT(*) FROM slots", [], |row| row.get(0))
        .unwrap();
    assert_eq!(slots, 2);
}

#[test]
fn journal_failure_never_leaves_a_payment_without_its_slot_reservation() {
    let dir = private_dir();
    let path = dir.path().join("ledger.sqlite");
    let mut ledger = seeded(&path);
    let before = snapshot(&ledger);
    inject(&ledger, "BEFORE UPDATE OF state ON slots");
    let outgoing = payment(false);
    assert!(ledger.journal(&outgoing).is_err());
    assert_eq!(snapshot(&ledger), before);
    drop(ledger);
    let mut ledger = Ledger::open(&path, "failure-injection").unwrap();
    assert_eq!(snapshot(&ledger), before);
    ledger.journal(&outgoing).unwrap();
    assert_eq!(ledger.pending().unwrap().unwrap().raw, outgoing.raw);
    let slot: String = ledger
        .db
        .query_row("SELECT state FROM slots WHERE id=1", [], |row| row.get(0))
        .unwrap();
    assert_eq!(slot, "pending");
}

#[test]
fn payout_and_refund_settlement_are_atomic_at_every_write_stage() {
    for refund in [false, true] {
        for stage in [
            "BEFORE UPDATE ON deposits",
            "BEFORE UPDATE ON outbox",
            "BEFORE UPDATE ON slots",
            "BEFORE INSERT ON meta WHEN NEW.k='last_nonce'",
        ] {
            let dir = private_dir();
            let path = dir.path().join("ledger.sqlite");
            let mut ledger = seeded(&path);
            ledger.journal(&payment(refund)).unwrap();
            let outgoing = ledger.pending().unwrap().unwrap();
            let before = snapshot(&ledger);
            inject(&ledger, stage);
            assert!(
                ledger
                    .settle(&outgoing, &3u32.into(), 3, &"05".repeat(32))
                    .is_err(),
                "refund={refund}, stage={stage}"
            );
            assert_eq!(snapshot(&ledger), before, "refund={refund}, stage={stage}");
            drop(ledger);
            let mut ledger = Ledger::open(&path, "failure-injection").unwrap();
            assert_eq!(snapshot(&ledger), before, "refund={refund}, stage={stage}");
            let resumed = ledger.pending().unwrap().unwrap();
            assert_eq!(resumed.raw, outgoing.raw);
            assert_eq!(resumed.nonce, outgoing.nonce);
            ledger
                .settle(&resumed, &3u32.into(), 3, &"05".repeat(32))
                .unwrap();
            assert!(ledger.pending().unwrap().is_none());
            assert_eq!(
                ledger.deposits().unwrap()[0].remaining,
                Amount::from(if refund { 0u32 } else { 146u32 })
            );
            assert_eq!(ledger.get("last_nonce").unwrap().as_deref(), Some("1"));
            let states: Vec<String> = ledger
                .db
                .prepare("SELECT state FROM slots ORDER BY id")
                .unwrap()
                .query_map([], |row| row.get(0))
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap();
            assert_eq!(
                states,
                if refund {
                    vec!["cancelled", "cancelled"]
                } else {
                    vec!["paid", "queued"]
                }
            );
            let settled = snapshot(&ledger);
            drop(ledger);
            let ledger = Ledger::open(&path, "failure-injection").unwrap();
            assert_eq!(snapshot(&ledger), settled);
            assert!(ledger.pending().unwrap().is_none());
        }
    }
}

#[test]
fn expiry_failure_preserves_pending_bytes_and_retry_does_not_debit_balance() {
    let dir = private_dir();
    let path = dir.path().join("ledger.sqlite");
    let mut ledger = seeded(&path);
    ledger.journal(&payment(false)).unwrap();
    let outgoing = ledger.pending().unwrap().unwrap();
    let before = snapshot(&ledger);
    inject(&ledger, "BEFORE UPDATE ON slots");
    assert!(ledger.expire(&outgoing).is_err());
    assert_eq!(snapshot(&ledger), before);
    drop(ledger);
    let mut ledger = Ledger::open(&path, "failure-injection").unwrap();
    assert_eq!(snapshot(&ledger), before);
    let resumed = ledger.pending().unwrap().unwrap();
    assert_eq!(resumed.raw, outgoing.raw);
    ledger.expire(&resumed).unwrap();
    assert!(ledger.pending().unwrap().is_none());
    assert_eq!(ledger.deposits().unwrap()[0].remaining, 250u32.into());
    assert_eq!(ledger.get("last_nonce").unwrap(), None);
    let mut replacement = payment(false);
    replacement.expiry = 40;
    replacement.height = 22;
    replacement.txid = "06".repeat(32);
    replacement.raw = "replacement with same unused nonce and a later expiry".into();
    ledger.journal(&replacement).unwrap();
    let next = ledger.pending().unwrap().unwrap();
    assert_eq!(next.nonce, outgoing.nonce);
    assert_eq!(next.raw, replacement.raw);
    assert_eq!(ledger.deposits().unwrap()[0].remaining, 250u32.into());
}
