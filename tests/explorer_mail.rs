use hashstash::{address, codec, config::Config, crypto, node::Node, types::*, wallet};
use serde_json::{Value, json};

fn key(n: u8) -> PublicKey {
    crypto::public_key(&[n; 32]).unwrap()
}
fn config() -> Config {
    let mut c = Config::testnet();
    c.network = "isolated-global-mail-index-tests".into();
    c.initial_bits = 0x2003ffff;
    c.limit_bits = c.initial_bits;
    c.validate().unwrap();
    c
}
fn read(node: &Node, method: &str, params: Value) -> Value {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        match node.rpc(method, params.clone()) {
            Ok(value) => return value,
            Err(e)
                if e.to_string().contains("index is updating")
                    && std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(std::time::Duration::from_millis(5))
            }
            Err(e) => panic!("{method}: {e}"),
        }
    }
}
fn envelope() -> Vec<u8> {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/mail-v2.json")).unwrap();
    hex::decode(fixture["data_hex"].as_str().unwrap()).unwrap()
}
fn authenticate_record(record: &Value, chain_id: Hash) -> Transaction {
    let transaction = wallet::decode_signed(record["raw"].as_str().unwrap()).unwrap();
    assert_eq!(record["raw"], wallet::signed_hex(&transaction));
    assert_eq!(
        record["txid"],
        hex::encode(codec::transaction_id(&transaction))
    );
    assert_eq!(
        record["sender_public_key"],
        hex::encode(transaction.body.sender)
    );
    assert_eq!(
        record["sender"],
        address::encode(&transaction.body.sender, &chain_id).unwrap()
    );
    assert_eq!(record["nonce"], transaction.body.nonce.to_string());
    assert_eq!(record["data_hex"], hex::encode(&transaction.body.data));
    assert_eq!(
        record["operation"],
        serde_json::to_value(&transaction.body.operation).unwrap()
    );
    transaction
}
fn signed(c: &Config, nonce: u64, operation: Operation, data: Vec<u8>) -> Transaction {
    crypto::sign(
        &TransactionBody {
            sender: key(91),
            nonce,
            fee: 4u32.into(),
            anchor: hashstash::codec::block_hash(&hashstash::codec::genesis_block(c).unwrap()),
            expiry_blocks: 1000,
            operation,
            data,
        },
        &[91; 32],
    )
    .unwrap()
}
fn message(_node: &Node, c: &Config, nonce: u64) -> Transaction {
    signed(
        c,
        nonce,
        Operation::TransferExact {
            recipient: key(91),
            amount: 1u32.into(),
        },
        envelope(),
    )
}

#[test]
fn canonical_mail_carries_payments_stash_actions_and_proposals_without_recipient_filtering() {
    let dir = tempfile::tempdir().unwrap();
    let c = config();
    c.validate().unwrap();
    let n = Node::open(&dir.path().join("all-actions.sqlite"), c.clone(), key(91)).unwrap();
    for _ in 0..200 {
        if n.status().unwrap()["phase"] == "auction" {
            break;
        }
        n.mine(1_000_000).unwrap();
    }
    assert_eq!(n.status().unwrap()["phase"], "auction");
    for _ in 0..8 {
        n.mine(1_000_000).unwrap();
    }
    let mut actions = vec![
        Operation::TransferExact {
            recipient: key(92),
            amount: 25u32.into(),
        },
        Operation::Deposit {
            amount: 80u32.into(),

            decision: None,
            outcome: None,
        },
    ];
    let mut expected = Vec::new();
    for (nonce, operation) in actions.iter().enumerate() {
        let transaction = signed(&c, nonce as u64, operation.clone(), envelope());
        expected.push(hex::encode(codec::transaction_id(&transaction)));
        n.submit_transaction(transaction).unwrap();
        assert_eq!(n.mine(1_000_000).unwrap().transactions.len(), 1);
    }
    let account = n
        .rpc("account", json!({"key":hex::encode(key(91))}))
        .unwrap();
    let shares = Amount::parse_bytes(
        account["account"]["shares"].as_str().unwrap().as_bytes(),
        10,
    )
    .unwrap();
    actions.push(Operation::Redeem {
        shares: shares / 10u32,

        decision: None,
        outcome: None,
    });
    actions.push(Operation::Propose {
        round: n.status().unwrap()["auction_round"].as_u64().unwrap(),
        description: [8; 32],
        proposal: Proposal::Grant {
            payments: vec![hashstash::types::GrantPayment {
                recipient: key(93),
                amount: 1u32.into(),
            }],
        },
        support: 10u32.into(),
    });
    for (nonce, operation) in actions.iter().enumerate().skip(2) {
        let transaction = signed(&c, nonce as u64, operation.clone(), envelope());
        expected.push(hex::encode(codec::transaction_id(&transaction)));
        n.submit_transaction(transaction).unwrap();
        assert_eq!(n.mine(1_000_000).unwrap().transactions.len(), 1);
    }
    let feed = read(&n, "explorer_mail", json!({}));
    let messages = feed["messages"].as_array().unwrap();
    assert_eq!(messages.len(), actions.len());
    for (position, message) in messages.iter().enumerate() {
        authenticate_record(message, c.chain_id());
        assert_eq!(message["txid"], expected[position]);
        assert_eq!(
            message["operation"],
            serde_json::to_value(&actions[position]).unwrap()
        );
        let lookup = read(
            &n,
            "explorer_transaction",
            json!({"txid":expected[position]}),
        );
        assert_eq!(lookup["transaction"]["status"], "confirmed");
        assert_eq!(lookup["transaction"]["operation"], message["operation"]);
        assert_eq!(lookup["transaction"]["data_hex"], message["data_hex"]);
        assert!(
            message.get("recipient").is_none(),
            "the encrypted recipient is never exposed"
        );
    }
    assert_eq!(
        messages
            .iter()
            .map(|m| m["kind"].as_str().unwrap())
            .collect::<Vec<_>>(),
        vec!["transfer", "deposit", "redeem", "propose"]
    );
    let forged = signed(&c, 4, actions[0].clone(), envelope());
    let mut forged_body = forged.clone();
    forged_body.body.anchor[0] ^= 1;
    assert!(n.submit_transaction(forged_body).is_err());
    let mut forged_signature = forged;
    forged_signature.signature[0] ^= 1;
    assert!(n.submit_transaction(forged_signature).is_err());
    assert_eq!(
        read(&n, "explorer_mail", json!({}))["messages"],
        feed["messages"]
    );
}

#[test]
fn global_mail_scans_beyond_page_boundary_through_tip_growth_and_rebuilds() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mail.sqlite");
    let c = config();
    let n = Node::open(&path, c.clone(), key(91)).unwrap();
    n.mine(1_000_000).unwrap();
    let mut expected = Vec::new();
    for block in 0..18 {
        for offset in 0..3 {
            let t = message(&n, &c, block * 3 + offset);
            expected.push(hex::encode(codec::transaction_id(&t)));
            n.submit_transaction(t).unwrap();
        }
        assert_eq!(n.mine(1_000_000).unwrap().transactions.len(), 3);
    }
    let first = read(&n, "explorer_mail", json!({"limit":50}));
    assert_eq!(first["messages"].as_array().unwrap().len(), 50);
    assert_eq!(first["has_more"], true);
    n.mine(1_000_000).unwrap();
    let second = read(
        &n,
        "explorer_mail",
        json!({"limit":50,"after":first["next_cursor"],"anchor":first["anchor"]}),
    );
    assert_eq!(second["messages"].as_array().unwrap().len(), 4);
    assert_eq!(second["has_more"], false);
    assert!(second["next_cursor"].is_null());
    assert_ne!(
        first["anchor"], second["anchor"],
        "advancing the tip preserves a canonical cursor anchor"
    );
    let actual: Vec<_> = first["messages"]
        .as_array()
        .unwrap()
        .iter()
        .chain(second["messages"].as_array().unwrap())
        .map(|m| {
            authenticate_record(m, c.chain_id());
            m["txid"].as_str().unwrap().to_owned()
        })
        .collect();
    assert_eq!(actual, expected);
    let third_tx = message(&n, &c, 54);
    let third_id = hex::encode(codec::transaction_id(&third_tx));
    n.submit_transaction(third_tx).unwrap();
    assert!(
        read(
            &n,
            "explorer_mail",
            json!({"after":second["scan_cursor"],"anchor":second["anchor"]})
        )["messages"]
            .as_array()
            .unwrap()
            .is_empty(),
        "mempool is never disclosed through mail discovery"
    );
    n.mine(1_000_000).unwrap();
    let third = read(
        &n,
        "explorer_mail",
        json!({"after":second["scan_cursor"],"anchor":second["anchor"]}),
    );
    assert_eq!(third["messages"].as_array().unwrap().len(), 1);
    assert_eq!(third["messages"][0]["txid"], third_id);
    let root = n.status().unwrap()["state_root"].clone();
    drop(n);
    let db = rusqlite::Connection::open(path.with_extension("explorer.sqlite")).unwrap();
    // Simulate the prior projection: authentic canonical transactions exist,
    // but the derived mail records contain no signed bytes for browsers to check.
    db.execute(
        "UPDATE explorer_mail SET record=json_remove(record,'$.raw')",
        [],
    )
    .unwrap();
    db.execute(
        "UPDATE explorer_meta SET value='22-all-transaction-mail' WHERE key='schema'",
        [],
    )
    .unwrap();
    let unsigned: String = db
        .query_row("SELECT record FROM explorer_mail LIMIT 1", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert!(
        serde_json::from_str::<Value>(&unsigned)
            .unwrap()
            .get("raw")
            .is_none()
    );
    drop(db);
    let rebuilt = Node::open(&path, c.clone(), key(91)).unwrap();
    let replay = read(
        &rebuilt,
        "explorer_mail",
        json!({"after":second["scan_cursor"],"anchor":second["anchor"]}),
    );
    assert_eq!(replay, third);
    authenticate_record(&replay["messages"][0], c.chain_id());
    assert_eq!(rebuilt.status().unwrap()["state_root"], root);
}

#[test]
fn replaced_mail_anchor_fails_closed_and_replacement_messages_are_discovered() {
    let dir = tempfile::tempdir().unwrap();
    let c = config();
    let a = Node::open(&dir.path().join("a.sqlite"), c.clone(), key(91)).unwrap();
    let b = Node::open(&dir.path().join("b.sqlite"), c.clone(), key(92)).unwrap();
    for _ in 0..2 {
        b.submit_block(a.mine(1_000_000).unwrap()).unwrap();
    }
    a.submit_transaction(message(&a, &c, 0)).unwrap();
    a.mine(1_000_000).unwrap();
    let old = read(&a, "explorer_mail", json!({}));
    assert_eq!(old["messages"].as_array().unwrap().len(), 1);
    let replacement = message(&b, &c, 0);
    // A different signed envelope changes the txid while retaining valid v2 framing.
    let mut replacement_body = replacement.body;
    replacement_body.fee = 101u32.into();
    let replacement = crypto::sign(&replacement_body, &[91; 32]).unwrap();
    let replacement_id = hex::encode(codec::transaction_id(&replacement));
    b.submit_transaction(replacement).unwrap();
    for _ in 0..3 {
        a.submit_block(b.mine(1_000_000).unwrap()).unwrap();
    }
    let new = read(&a, "explorer_mail", json!({}));
    assert_eq!(new["messages"].as_array().unwrap().len(), 1);
    assert_eq!(new["messages"][0]["txid"], replacement_id);
    assert_ne!(old["messages"][0]["txid"], new["messages"][0]["txid"]);
    let error = a
        .rpc(
            "explorer_mail",
            json!({"after":old["scan_cursor"],"anchor":old["anchor"]}),
        )
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("Mail scan anchor is no longer canonical")
    );
}
