use hashstash::{config::Config, crypto, node::Node, state, types::*};
use serde_json::json;

#[test]
fn governance_snapshot_keeps_current_proposal_after_more_than_one_page_of_history() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = Config::devnet();
    config.initial_bits = 0x2000ffff;
    config.limit_bits = 0x2000ffff;
    config.initial.block_bytes = 262144;
    let secret = [91; 32];
    let public = crypto::public_key(&secret).unwrap();
    let node = Node::open(
        &directory.path().join("snapshot-history.db"),
        config.clone(),
        public,
    )
    .unwrap();
    let submit = |nonce, operation| {
        let transaction = crypto::sign(
            &TransactionBody {
                data: Vec::new(),
                chain_id: config.chain_id(),
                sender: public,
                nonce,
                fee: 1u32.into(),
                expiry_height: 10_000,
                operation,
            },
            &secret,
        )
        .unwrap();
        node.submit_transaction(transaction).unwrap();
    };
    for _ in 0..100 {
        node.mine(100_000).unwrap();
    }
    submit(
        0,
        Operation::Deposit {
            amount: 20u32.into(),
            min_shares: 1u32.into(),
            decision: None,
            outcome: None,
        },
    );
    node.mine(100_000).unwrap();
    let proposal = Proposal::Parameter {
        parameter: Parameter::Lead,
        old: config.initial.lead,
        new: config.initial.lead * 2,
    };
    let mut largest_old = ZERO_HASH;
    for index in 0..129u32 {
        let mut description = [0; 32];
        description[..4].copy_from_slice(&index.to_le_bytes());
        largest_old = largest_old.max(state::proposal_id(
            &config.chain_id(),
            0,
            &description,
            &proposal,
        ));
        submit(
            index as u64 + 1,
            Operation::Propose {
                round: 0,
                description,
                proposal: proposal.clone(),
                support: 1u32.into(),
            },
        );
    }
    node.mine(100_000).unwrap();
    for _ in 0..500 {
        if node.status().unwrap()["auction_round"] == 1 {
            break;
        }
        node.mine(100_000).unwrap();
    }
    assert_eq!(node.status().unwrap()["auction_round"], 1);
    // Choose a valid new description whose proposal sorts beyond every historical
    // entry, making the old unfiltered first-page behavior fail deterministically.
    let (description, current_id) = (0..100_000u32)
        .find_map(|index| {
            let mut description = [0; 32];
            description[..4].copy_from_slice(&index.to_le_bytes());
            let id = state::proposal_id(&config.chain_id(), 1, &description, &proposal);
            (id > largest_old).then_some((description, id))
        })
        .expect("description search exhausted");
    submit(
        130,
        Operation::Propose {
            round: 1,
            description,
            proposal,
            support: 1u32.into(),
        },
    );
    node.mine(100_000).unwrap();
    let auction = node
        .rpc("snapshot", json!({"key":hex::encode(public)}))
        .unwrap();
    assert_eq!(auction["proposals"].as_array().unwrap().len(), 1);
    for _ in 0..10 {
        if node.status().unwrap()["phase"] == "governance" {
            break;
        }
        node.mine(100_000).unwrap();
    }
    assert_eq!(node.status().unwrap()["phase"], "governance");
    let unfiltered = node.rpc("proposals", json!({})).unwrap();
    assert_eq!(unfiltered.as_array().unwrap().len(), 128);
    assert!(
        !unfiltered
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["id"] == hex::encode(current_id))
    );
    let snapshot = node
        .rpc("snapshot", json!({"key":hex::encode(public)}))
        .unwrap();
    assert_eq!(snapshot["proposals"].as_array().unwrap().len(), 1);
    assert_eq!(snapshot["proposals"][0]["id"], hex::encode(current_id));
    assert_eq!(snapshot["proposals"][0]["proposal"]["round"], 1);
    assert_eq!(
        snapshot["status"]["state_root"],
        snapshot["governance"]["state_root"]
    );
    assert!(!snapshot["pass"].is_null());
    assert!(!snapshot["fail"].is_null());
}
