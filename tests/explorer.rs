use hashstash::{
    address,
    chain::Chain,
    codec,
    config::Config,
    crypto,
    node::{self, Node, ServerOptions},
    state,
    types::*,
};
use serde_json::{Value, json};
use std::net::SocketAddr;

trait ExplorerRpc {
    fn explorer_rpc(&self, method: &str, params: Value) -> anyhow::Result<Value>;
}
impl ExplorerRpc for Node {
    fn explorer_rpc(&self, method: &str, params: Value) -> anyhow::Result<Value> {
        let until = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let result = self.rpc(method, params.clone());
            if result
                .as_ref()
                .is_err_and(|error| error.to_string().contains("index is updating"))
                && std::time::Instant::now() < until
            {
                std::thread::sleep(std::time::Duration::from_millis(5));
            } else {
                return result;
            }
        }
    }
}

const SECRET: [u8; 32] = [91; 32];

#[test]
fn canonical_work_rewards_remain_complete_without_stale_support() {
    let dir = tempfile::tempdir().unwrap();
    let mut c = Config::testnet();
    c.genesis_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32
        - 1;
    let node = Node::open(&dir.path().join("canonical.sqlite"), c, owner()).unwrap();
    let block = node.mine(1_000_000).unwrap();
    let value = node
        .explorer_rpc(
            "explorer_block",
            json!({"hash":hex::encode(codec::block_hash(&block))}),
        )
        .unwrap();
    let rewards = &value["block"]["rewards"];
    assert_eq!(rewards["complete"], true);
    assert_eq!(rewards["miner_total"], rewards["subsidy"]);
    assert!(rewards["miner_total"].as_str().is_some());
    assert!(rewards.get("stale_finder").is_none());
    assert!(rewards.get("stale_includer").is_none());
    assert!(rewards.get("stale_revenue").is_none());
}
fn owner() -> PublicKey {
    crypto::public_key(&SECRET).unwrap()
}
fn key(n: u8) -> PublicKey {
    crypto::public_key(&[n; 32]).unwrap()
}
fn config(_with_governance: bool) -> Config {
    let mut c = Config::testnet();
    c.network = "isolated-explorer-tests".into();
    c.initial_bits = 0x2003ffff;
    c.limit_bits = c.initial_bits;
    c.validate().unwrap();
    c
}
fn tx(node: &Node, c: &Config, operation: Operation, offset: u64, data: Vec<u8>) -> Transaction {
    let nonce = node
        .rpc("account", json!({"key":hex::encode(owner())}))
        .unwrap()["account"]["nonce"]
        .as_u64()
        .unwrap()
        + offset;
    crypto::sign(
        &TransactionBody {
            chain_id: c.chain_id(),
            sender: owner(),
            nonce,
            fee: 3u32.into(),
            expiry_height: node.status().unwrap()["height"].as_u64().unwrap() + 100,
            operation,
            data,
        },
        &SECRET,
    )
    .unwrap()
}
fn transfer(node: &Node, c: &Config, n: u8, offset: u64) -> Transaction {
    tx(
        node,
        c,
        Operation::TransferExact {
            recipient: key(n),
            amount: 25u32.into(),
        },
        offset,
        b"<script>unsafe text only</script>\0\xff".to_vec(),
    )
}
fn lookup(node: &Node, id: Hash) -> Value {
    node.explorer_rpc("explorer_transaction", json!({"txid":hex::encode(id)}))
        .unwrap()["transaction"]
        .clone()
}

#[test]
fn exact_fees_pagination_pending_restart_and_canonical_reorg() {
    let dir = tempfile::tempdir().unwrap();
    let c = config(false);
    let path = dir.path().join("a.sqlite");
    let a = Node::open(&path, c.clone(), owner()).unwrap();
    let b = Node::open(&dir.path().join("b.sqlite"), c.clone(), key(93)).unwrap();
    let genesis = a
        .explorer_rpc("explorer_block", json!({"height":0}))
        .unwrap();
    assert!(genesis["block"]["miner"].is_null());
    for _ in 0..8 {
        let block = a.mine(1_000_000).unwrap();
        b.submit_block(block).unwrap();
    }
    let first = transfer(&a, &c, 92, 0);
    let first_id = codec::transaction_id(&first);
    a.submit_transaction(first.clone()).unwrap();
    assert_eq!(lookup(&a, first_id)["status"], "pending");
    let second = transfer(&a, &c, 94, 1);
    let second_id = codec::transaction_id(&second);
    a.submit_transaction(second).unwrap();
    let old_block = a.mine(1_000_000).unwrap();
    let confirmed = lookup(&a, first_id);
    assert_eq!(confirmed["status"], "confirmed");
    assert_eq!(confirmed["fee"], "3");
    assert_eq!(confirmed["minimum_fee"], "2");
    assert_eq!(confirmed["extra_fee"], "1");
    assert_eq!(confirmed["amount"], "25");
    assert_eq!(
        confirmed["data_hex"],
        hex::encode(b"<script>unsafe text only</script>\0\xff")
    );
    let page = a
        .explorer_rpc("explorer_transactions", json!({"limit":1}))
        .unwrap();
    assert_eq!(page["transactions"][0]["txid"], hex::encode(second_id));
    let next = a
        .explorer_rpc(
            "explorer_transactions",
            json!({"limit":1,"before":page["next_cursor"]}),
        )
        .unwrap();
    assert_eq!(next["transactions"][0]["txid"], hex::encode(first_id));
    let account = a
        .explorer_rpc(
            "explorer_account",
            json!({"address":address::encode(&key(92),&c.chain_id()).unwrap()}),
        )
        .unwrap();
    assert_eq!(account["account"]["ordinary"], "25");
    assert_eq!(account["history"][0]["role"], "recipient");
    for _ in 0..3 {
        a.submit_block(b.mine(1_000_000).unwrap()).unwrap();
    }
    assert_eq!(lookup(&a, first_id)["status"], "pending");
    assert_eq!(
        a.explorer_rpc(
            "explorer_block",
            json!({"hash":hex::encode(codec::block_hash(&old_block))})
        )
        .unwrap()["block"]["status"],
        "orphaned"
    );
    a.mine(1_000_000).unwrap();
    assert_eq!(lookup(&a, first_id)["status"], "confirmed");
    let tip = a.status().unwrap()["tip"].clone();
    drop(a);
    let a = Node::open(&path, c.clone(), owner()).unwrap();
    assert_eq!(
        a.explorer_rpc("explorer_blocks", json!({})).unwrap()["tip"],
        tip
    );
    assert_eq!(lookup(&a, first_id)["fee"], "3");
    drop(a);
    std::fs::remove_file(path.with_extension("explorer.sqlite")).unwrap();
    let a = Node::open(&path, c.clone(), owner()).unwrap();
    assert_eq!(lookup(&a, first_id)["status"], "confirmed");
    for p in [
        json!({"limit":0}),
        json!({"limit":51}),
        json!({"before":"1:9999999999999"}),
        json!({"before":"bogus"}),
        json!({"limit":"5"}),
        json!({"unknown":true}),
    ] {
        assert!(a.explorer_rpc("explorer_transactions", p).is_err());
    }
    assert!(
        a.explorer_rpc("explorer_block", json!({"height":-1}))
            .is_err()
    );
    assert!(
        a.explorer_rpc("explorer_transaction", json!({"txid":"00"}))
            .is_err()
    );
    assert!(
        a.explorer_rpc("explorer_transaction", json!({"txid":hex::encode([0;32])}))
            .is_err()
    );
    let unused = a
        .explorer_rpc(
            "explorer_account",
            json!({"address":address::encode(&key(95),&c.chain_id()).unwrap()}),
        )
        .unwrap();
    assert!(unused["account"].is_null());
}

#[test]
fn governance_evidence_contributions_same_height_proposals_and_reorg() {
    let dir = tempfile::tempdir().unwrap();
    let c = config(true);
    let a = Node::open(&dir.path().join("a.sqlite"), c.clone(), owner()).unwrap();
    let b = Node::open(&dir.path().join("b.sqlite"), c.clone(), key(93)).unwrap();
    for _ in 0..200 {
        if a.status().unwrap()["phase"] == "auction" {
            break;
        }
        let block = a.mine(1_000_000).unwrap();
        b.submit_block(block).unwrap();
    }
    for _ in 0..6 {
        let block = a.mine(1_000_000).unwrap();
        b.submit_block(block).unwrap();
    }
    a.submit_transaction(tx(
        &a,
        &c,
        Operation::Deposit {
            amount: 1000u32.into(),

            decision: None,
            outcome: None,
        },
        0,
        vec![],
    ))
    .unwrap();
    let deposit_block = a.mine(1_000_000).unwrap();
    b.submit_block(deposit_block).unwrap();
    let round = a.status().unwrap()["auction_round"].as_u64().unwrap();
    let old = a.status().unwrap()["settings"]["lead"].as_u64().unwrap();
    let actions = [
        Proposal::Parameter {
            parameter: Parameter::Lead,
            old,
            new: old * 2,
        },
        Proposal::Grant {
            payments: vec![hashstash::types::GrantPayment {
                recipient: key(96),
                // Exceeds the winning bid and fees, so PASS draws reserve and
                // has a curved market rather than a fee-buffer-funded flat tie.
                amount: 100u32.into(),
            }],
        },
    ];
    let ids = actions
        .iter()
        .map(|p| state::proposal_id(&c.chain_id(), round, &[7; 32], p))
        .collect::<Vec<_>>();
    for (i, p) in actions.into_iter().enumerate() {
        a.submit_transaction(tx(
            &a,
            &c,
            Operation::Propose {
                round,
                description: [7; 32],
                proposal: p,
                support: Amount::from(10 + i as u64),
            },
            i as u64,
            vec![],
        ))
        .unwrap();
    }
    a.mine(1_000_000).unwrap();
    let page = a
        .explorer_rpc("explorer_governance", json!({"limit":1}))
        .unwrap();
    assert_eq!(page["proposals"][0]["id"], hex::encode(ids[1]));
    let next = a
        .explorer_rpc(
            "explorer_governance",
            json!({"limit":1,"proposal_before":page["proposal_next_cursor"]}),
        )
        .unwrap();
    assert_eq!(next["proposals"][0]["id"], hex::encode(ids[0]));
    for _ in 0..40 {
        if a.status().unwrap()["phase"] == "governance" {
            break;
        }
        a.mine(1_000_000).unwrap();
    }
    let gov = a.rpc("governance", json!({})).unwrap();
    let decision: Hash = serde_json::from_value(gov["phase"]["Governance"]["id"].clone()).unwrap();
    let live = a
        .explorer_rpc("explorer_governance", json!({"limit":1}))
        .unwrap();
    assert_eq!(live["decisions"][0]["id"], hex::encode(decision));
    let started_height = a.status().unwrap()["height"].as_u64().unwrap();
    assert_eq!(live["decisions"][0]["started_height"], started_height);
    assert_eq!(
        live["decisions"][0]["started"],
        started_height * c.initial.interval
    );
    assert_eq!(live["decisions"][0]["time_unit"], "blocks");
    assert_eq!(live["decisions"][0]["observed_blocks"], 0);
    assert_eq!(live["decisions"][0]["leading_blocks"], 0);
    assert_eq!(
        live["decisions"][0]["blocks_remaining"],
        c.initial.decision_blocks
    );
    assert!(live["next_before_height"].is_u64());
    let older = a
        .explorer_rpc(
            "explorer_governance",
            json!({"limit":1,"before_height":live["next_before_height"]}),
        )
        .unwrap();
    assert!(older["decisions"].as_array().unwrap().is_empty());
    let trade = tx(
        &a,
        &c,
        Operation::Deposit {
            amount: 256u32.into(),

            decision: Some(decision),
            outcome: Some(Outcome::Pass),
        },
        0,
        vec![],
    );
    let trade_id = codec::transaction_id(&trade);
    a.submit_transaction(trade).unwrap();
    a.mine(1_000_000).unwrap();
    assert_eq!(lookup(&a, trade_id)["settlement"]["effect"], "conditional");
    for _ in 0..80 {
        if a.status().unwrap()["phase"] == "rest" {
            break;
        }
        a.mine(1_000_000).unwrap();
    }
    let detail = a
        .explorer_rpc(
            "explorer_governance",
            json!({"proposal":hex::encode(ids[1])}),
        )
        .unwrap();
    assert_eq!(detail["decisions"][0]["outcome"], "pass");
    assert_eq!(detail["decisions"][0]["started_height"], started_height);
    assert_eq!(detail["contributions"].as_array().unwrap().len(), 1);
    let decision_record = &detail["decisions"][0];
    assert_eq!(
        decision_record["observed_blocks"],
        c.initial.decision_blocks
    );
    assert_eq!(decision_record["blocks_remaining"], 0);
    assert!(decision_record["leading_blocks"].as_u64().unwrap() > c.initial.decision_blocks / 2);
    assert!(decision_record.get("pass_average").is_none());
    assert_eq!(lookup(&a, trade_id)["settlement"]["effect"], "survived");
    let grant_address = address::encode(&key(96), &c.chain_id()).unwrap();
    let granted = a
        .explorer_rpc("explorer_account", json!({"address":grant_address}))
        .unwrap();
    assert_eq!(granted["account"]["ordinary"], "100");
    assert_eq!(granted["history"][0]["kind"], "governance_grant");
    assert_eq!(granted["history"][0]["amount"], "100");
    assert_eq!(granted["history"][0]["proposal"], hex::encode(ids[1]));
    assert_eq!(granted["history"][0]["settlement"]["effect"], "survived");
    assert!(granted["history"][0].get("txid").is_none());
    let target = a.status().unwrap()["height"].as_u64().unwrap() + 3;
    while b.status().unwrap()["height"].as_u64().unwrap() < target {
        a.submit_block(b.mine(1_000_000).unwrap()).unwrap();
    }
    let history = a.explorer_rpc("explorer_governance", json!({})).unwrap();
    assert!(history["decisions"].as_array().unwrap().is_empty());
    assert!(history["proposals"].as_array().unwrap().is_empty());
    assert!(history["contributions"].as_array().unwrap().is_empty());
    assert_eq!(lookup(&a, trade_id)["status"], "orphaned");
    let detached = a
        .explorer_rpc("explorer_account", json!({"address":grant_address}))
        .unwrap();
    assert!(detached["account"].is_null());
    assert!(detached["history"].as_array().unwrap().is_empty());
}

#[test]
fn held_reader_does_not_block_publication_and_sidecar_identity_is_rebuilt() {
    use std::{sync::mpsc, time::Duration};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("chain.sqlite");
    let c = config(false);
    let a = Node::open(&path, c.clone(), owner()).unwrap();
    a.mine(1_000_000).unwrap();
    let reader = rusqlite::Connection::open_with_flags(
        path.with_extension("explorer.sqlite"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    reader.execute_batch("BEGIN").unwrap();
    let before: u64 = reader
        .query_row("SELECT COUNT(*) FROM explorer_blocks", [], |r| r.get(0))
        .unwrap();
    let (send, recv) = mpsc::channel();
    let writer = a.clone();
    let task = std::thread::spawn(move || {
        send.send(writer.mine(1_000_000)).unwrap();
    });
    recv.recv_timeout(Duration::from_secs(5))
        .expect("reader must not block canonical publication")
        .unwrap();
    task.join().unwrap();
    assert_eq!(
        reader
            .query_row::<u64, _, _>("SELECT COUNT(*) FROM explorer_blocks", [], |r| r.get(0))
            .unwrap(),
        before
    );
    assert_eq!(
        a.explorer_rpc("explorer_blocks", json!({})).unwrap()["height"],
        2
    );
    drop(reader);
    let status = a.status().unwrap();
    for _ in 0..20 {
        let result = a
            .explorer_rpc("explorer_blocks", json!({"limit":2}))
            .unwrap();
        assert_eq!(result["blocks"][0]["hash"], result["tip"]);
        assert_eq!(result["state_root"], result["blocks"][0]["state_root"]);
    }
    assert_eq!(a.status().unwrap(), status);
    drop(a);
    // A previously used derived database cannot leak another network's rows.
    let sidecar = path.with_extension("explorer.sqlite");
    let old = rusqlite::Connection::open(&sidecar).unwrap();
    old.execute(
        "UPDATE explorer_meta SET value='obsolete-network' WHERE key='chain'",
        [],
    )
    .unwrap();
    drop(old);
    let a = Node::open(&path, c, owner()).unwrap();
    assert_eq!(
        a.explorer_rpc("explorer_blocks", json!({})).unwrap()["chain_id"],
        status["chain_id"]
    );
    assert_eq!(
        a.explorer_rpc("explorer_blocks", json!({})).unwrap()["height"],
        2
    );
}

#[test]
fn stalled_index_writer_does_not_delay_canonical_publication() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("chain.sqlite");
    let node = Node::open(&path, config(false), owner()).unwrap();
    let locked = rusqlite::Connection::open(path.with_extension("explorer.sqlite")).unwrap();
    locked.execute_batch("BEGIN IMMEDIATE").unwrap();
    let candidate = Chain::mine(node.template().unwrap(), 1_000_000).unwrap();
    let expected = hex::encode(codec::block_hash(&candidate));
    let (send, receive) = std::sync::mpsc::channel();
    let submitter = node.clone();
    let task = std::thread::spawn(move || {
        send.send(submitter.submit_block(candidate)).unwrap();
    });
    // Hold the write transaction throughout this assertion: a synchronous
    // publisher would have to wait for the index writer's busy timeout.
    let accepted = receive.recv_timeout(std::time::Duration::from_millis(300));
    let published = node.status().unwrap();
    assert!(node.rpc("explorer_blocks", json!({})).is_err());
    locked.execute_batch("ROLLBACK").unwrap();
    assert!(
        accepted
            .expect("derived SQL must not block block publication")
            .unwrap()
    );
    task.join().unwrap();
    assert_eq!(published["tip"], expected);
    assert_eq!(
        node.explorer_rpc("explorer_blocks", json!({})).unwrap()["tip"],
        expected
    );
}

#[test]
fn deep_worker_reorg_replays_from_genesis_after_checkpoint_eviction() {
    let dir = tempfile::tempdir().unwrap();
    let c = config(false);
    let a = Node::open(&dir.path().join("deep-a.sqlite"), c.clone(), owner()).unwrap();
    let b = Node::open(&dir.path().join("deep-b.sqlite"), c.clone(), key(93)).unwrap();
    b.submit_block(a.mine(1_000_000).unwrap()).unwrap();
    let old_transfer = transfer(&a, &c, 92, 0);
    let id = codec::transaction_id(&old_transfer);
    a.submit_transaction(old_transfer).unwrap();
    a.mine(1_000_000).unwrap();
    for _ in 0..220 {
        a.mine(1_000_000).unwrap();
    }
    let old_tip = a
        .explorer_rpc("explorer_blocks", json!({"limit":1}))
        .unwrap()["tip"]
        .clone();
    assert_eq!(lookup(&a, id)["status"], "confirmed");
    // Both active branches share only height 1, well outside the worker's last
    // 128 states. All losing transactions have expired before reconnection.
    for _ in 0..225 {
        a.submit_block(b.mine(1_000_000).unwrap()).unwrap();
    }
    let current = a
        .explorer_rpc("explorer_blocks", json!({"limit":50}))
        .unwrap();
    let peer = b
        .explorer_rpc("explorer_blocks", json!({"limit":50}))
        .unwrap();
    assert_eq!(current["tip"], peer["tip"]);
    assert_eq!(current["state_root"], peer["state_root"]);
    assert_eq!(current["blocks"], peer["blocks"]);
    assert_eq!(
        a.explorer_rpc("explorer_block", json!({"hash":old_tip}))
            .unwrap()["block"]["status"],
        "orphaned"
    );
    assert_eq!(lookup(&a, id)["status"], "orphaned");
    let recipient = address::encode(&key(92), &c.chain_id()).unwrap();
    let account = a
        .explorer_rpc("explorer_account", json!({"address":recipient}))
        .unwrap();
    assert!(account["account"].is_null());
    assert!(account["history"].as_array().unwrap().is_empty());
    let miner = address::encode(&owner(), &c.chain_id()).unwrap();
    let account = a
        .explorer_rpc("explorer_account", json!({"address":miner}))
        .unwrap();
    assert_eq!(account["history"].as_array().unwrap().len(), 1);
    assert_eq!(account["history"][0]["height"], 1);
    assert_eq!(
        account["account"],
        b.explorer_rpc("explorer_account", json!({"address":miner}))
            .unwrap()["account"]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn public_explorer_is_read_only_and_index_failure_does_not_stop_chain() {
    let dir = tempfile::tempdir().unwrap();
    let c = config(false);
    let path = dir.path().join("a.sqlite");
    let n = Node::open(&path, c.clone(), owner()).unwrap();
    let zero: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let server = node::serve(
        n.clone(),
        ServerOptions {
            rpc: zero,
            public_web: Some(zero),
            p2p: zero,
            stratum: zero,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let client = reqwest::Client::new();
    let base = format!("http://{}", server.public_web.unwrap());
    for method in [
        "explorer_blocks",
        "explorer_transactions",
        "explorer_governance",
    ] {
        let response: Value = client
            .post(format!("{base}/rpc"))
            .json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":{}}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(response["result"]["chain_id"].is_string(), "{response}");
    }
    let denied = client
        .post(format!("{base}/rpc"))
        .json(&json!({"jsonrpc":"2.0","id":1,"method":"getblock","params":{}}))
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 403);
    assert_eq!(
        client
            .get(format!("{base}/explorer.js"))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    server.stop().await;
    drop(n);
    // An unusable derived database is not a chain-consensus dependency.
    let bad = dir.path().join("broken.sqlite");
    std::fs::create_dir(bad.with_extension("explorer.sqlite")).unwrap();
    let node = Node::open(&bad, c, owner()).unwrap();
    node.mine(1_000_000).unwrap();
    assert_eq!(node.status().unwrap()["height"], 1);
    assert!(node.explorer_rpc("explorer_blocks", json!({})).is_err());
}

#[test]
fn governed_whole_fee_rpc_and_explorer_match_exact_signed_fee() {
    for percent in [0u64, 37, 100] {
        let dir = tempfile::tempdir().unwrap();
        let mut c = Config::devnet();
        c.initial.miner_fee_percent = Some(percent);
        c.initial_bits = 0x2003ffff;
        c.limit_bits = c.initial_bits;
        c.validate().unwrap();
        let node = Node::open(&dir.path().join("chain.sqlite"), c.clone(), owner()).unwrap();
        for _ in 0..8 {
            node.mine(1_000_000).unwrap();
        }
        let operation = Operation::TransferExact {
            recipient: key(92),
            amount: 25u32.into(),
        };
        let quote = node
            .rpc(
                "fee_quote",
                json!({"sender":hex::encode(owner()),"operation":operation,"extra_fee":"7"}),
            )
            .unwrap();
        let required: u64 = quote["fee"].as_str().unwrap().parse().unwrap();
        let miner = required * percent / 100;
        assert_eq!(quote["miner_fee"], miner.to_string());
        assert_eq!(quote["revenue_fee"], (required - miner).to_string());
        assert_eq!(quote["miner_fee_percent"], percent);
        assert_eq!(
            required,
            quote["minimum_fee"]
                .as_str()
                .unwrap()
                .parse::<u64>()
                .unwrap()
                + 7
        );
        let transaction = crypto::sign(
            &TransactionBody {
                data: Vec::new(),
                chain_id: c.chain_id(),
                sender: owner(),
                nonce: 0,
                fee: required.into(),
                expiry_height: 100,
                operation,
            },
            &SECRET,
        )
        .unwrap();
        node.submit_transaction(transaction).unwrap();
        let block = node.mine(1_000_000).unwrap();
        let view = node
            .explorer_rpc("explorer_block", json!({"height":block.height}))
            .unwrap();
        let rewards = &view["block"]["rewards"];
        assert_eq!(rewards["transaction_fees"], required.to_string());
        assert_eq!(rewards["extra_fees"], "7");
        assert_eq!(rewards["minimum_fees"], (required - 7).to_string());
        assert_eq!(rewards["miner_fees"], miner.to_string());
        assert_eq!(rewards["revenue_fees"], (required - miner).to_string());
        let subsidy: u64 = rewards["subsidy"].as_str().unwrap().parse().unwrap();
        assert_eq!(rewards["miner_total"], (subsidy + miner).to_string());
    }
}
