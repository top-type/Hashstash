use hashstash::{address, codec, cold, crypto, types::*, wallet};
use reqwest::{Client, StatusCode};
use serde_json::{Value, json};

const PHRASE: &str = "Exact characters, spaces and Unicode: 雪 ";

#[tokio::test]
async fn large_transaction_review_uses_record_capacity_while_control_requests_stay_small() {
    let signer = Signer::start().await;
    let sender = signer.unlock(PHRASE).await;
    let mut expected = body(sender, payment());
    expected.data = vec![1; 96 * 1024];
    let envelope = serde_json::to_value(wallet::unsigned(&expected)).unwrap();
    assert!(serde_json::to_vec(&envelope).unwrap().len() > cold::MAX_CONTROL_REQUEST);
    let reviewed = signer.ok("review", envelope).await;
    let signed = signer
        .ok("sign", json!({"review_token":reviewed["review_token"]}))
        .await;
    assert_eq!(
        wallet::decode_signed(signed["raw"].as_str().unwrap())
            .unwrap()
            .body,
        expected
    );
    assert_eq!(
        signer
            .post(
                "unlock",
                json!({"passphrase":"a".repeat(cold::MAX_CONTROL_REQUEST)})
            )
            .await
            .status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    signer.server.stop().await;
}

#[tokio::test]
async fn data_review_exposes_full_bytes_and_changed_data_invalidates_prior_approval() {
    let signer = Signer::start().await;
    let sender = signer.unlock(PHRASE).await;
    let data: Vec<u8> = (0..=255).collect();
    let mut expected = body(sender, payment());
    expected.data = data.clone();
    let old = signer
        .ok(
            "review",
            serde_json::to_value(wallet::unsigned(&expected)).unwrap(),
        )
        .await;
    let fields = old["fields"].as_array().unwrap();
    assert!(
        fields
            .iter()
            .any(|field| field["label"] == "Data bytes" && field["value"] == "256")
    );
    assert!(
        fields
            .iter()
            .any(|field| field["label"] == "Data hex" && field["value"] == hex::encode(&data))
    );
    assert_eq!(old["body"], hex::encode(codec::encode(&expected)));
    let changed_data = b"<img src=x onerror=alert(1)>\0\xff".to_vec();
    expected.data = changed_data.clone();
    let updated = signer
        .ok(
            "review",
            serde_json::to_value(wallet::unsigned(&expected)).unwrap(),
        )
        .await;
    assert_ne!(updated["review_token"], old["review_token"]);
    assert_eq!(
        signer
            .post("sign", json!({"review_token":old["review_token"]}))
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    let fields = updated["fields"].as_array().unwrap();
    assert!(
        fields
            .iter()
            .any(|field| field["label"] == "Data hex"
                && field["value"] == hex::encode(&changed_data))
    );
    let signed = signer
        .ok("sign", json!({"review_token":updated["review_token"]}))
        .await;
    let transaction = wallet::decode_signed(signed["raw"].as_str().unwrap()).unwrap();
    assert_eq!(transaction.body, expected);
    assert_eq!(transaction.body.data, changed_data);
    signer.server.stop().await;
}

struct Signer {
    server: cold::ColdServer,
    client: Client,
    base: String,
    token: String,
}

impl Signer {
    async fn start() -> Self {
        Self::with_chain(None).await
    }

    async fn with_chain(chain: Option<Hash>) -> Self {
        let server = cold::serve_with_chain("127.0.0.1:0".parse().unwrap(), chain)
            .await
            .unwrap();
        let base = format!("http://{}", server.address);
        let client = Client::new();
        let session: Value = client
            .get(format!("{base}/api/session"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(session["unlocked"], false);
        assert!(session["public_key"].is_null());
        Self {
            server,
            client,
            base,
            token: session["token"].as_str().unwrap().into(),
        }
    }

    async fn post(&self, path: &str, body: Value) -> reqwest::Response {
        self.client
            .post(format!("{}/api/{path}", self.base))
            .header("Origin", &self.base)
            .header("X-Hashstash-Cold-Token", &self.token)
            .json(&body)
            .send()
            .await
            .unwrap()
    }

    async fn ok(&self, path: &str, body: Value) -> Value {
        self.post(path, body)
            .await
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap()
    }

    async fn unlock(&self, phrase: &str) -> PublicKey {
        let value = self.ok("unlock", json!({"passphrase":phrase})).await;
        assert_eq!(
            value["watch"]["format"],
            if value["chain_id"].is_null() {
                "hashstash-watch-v1"
            } else {
                "hashstash-watch-v2"
            }
        );
        assert_eq!(value["watch"]["public_key"], value["public_key"]);
        let key: PublicKey = hex::decode(value["public_key"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(
            key,
            crypto::public_key(&wallet::derive_secret(phrase).unwrap()).unwrap()
        );
        key
    }
}

#[tokio::test]
async fn configured_network_formats_addresses_and_rejects_another_full_chain() {
    let chain = [9; 32];
    let signer = Signer::with_chain(Some(chain)).await;
    let sender = signer.unlock(PHRASE).await;
    let recipient = crypto::public_key(&[30; 32]).unwrap();
    let expected = body(
        sender,
        Operation::TransferExact {
            recipient,
            amount: 4u32.into(),
        },
    );
    let review = signer
        .ok(
            "review",
            serde_json::to_value(wallet::unsigned(&expected)).unwrap(),
        )
        .await;
    assert_eq!(review["address"], address::encode(&sender, &chain).unwrap());
    assert_eq!(review["chain_id"], hex::encode(chain));
    assert_eq!(
        review["watch"],
        json!({"format":"hashstash-watch-v2","address":address::encode(&sender,&chain).unwrap(),"public_key":hex::encode(sender),"chain_id":hex::encode(chain)})
    );
    let fields = review["fields"].as_array().unwrap();
    assert!(
        fields
            .iter()
            .any(|f| f["label"] == "Sender"
                && f["value"] == address::encode(&sender, &chain).unwrap())
    );
    assert!(
        fields.iter().any(|f| f["label"] == "Recipient"
            && f["value"] == address::encode(&recipient, &chain).unwrap())
    );
    assert_eq!(
        address::decode(review["address"].as_str().unwrap(), &chain).unwrap(),
        sender
    );
    // Full transaction chain checking remains stronger than the display fingerprint.
    let mut alien = expected.clone();
    alien.chain_id[31] ^= 1;
    assert_eq!(address::hrp(&alien.chain_id), address::hrp(&chain));
    assert_eq!(
        signer
            .post(
                "review",
                serde_json::to_value(wallet::unsigned(&alien)).unwrap()
            )
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        signer
            .post("sign", json!({"review_token":review["review_token"]}))
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    let updated = signer
        .ok("network", json!({"chain_id":hex::encode([10;32])}))
        .await;
    assert_eq!(updated["public_key"], hex::encode(sender));
    assert_ne!(updated["address"], review["address"]);
    assert_eq!(
        address::decode(updated["address"].as_str().unwrap(), &[10; 32]).unwrap(),
        sender
    );
    assert_eq!(
        signer
            .post(
                "review",
                serde_json::to_value(wallet::unsigned(&expected)).unwrap()
            )
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    signer.server.stop().await;
}

#[tokio::test]
async fn network_changes_invalidate_review_and_persist_across_key_changes() {
    let signer = Signer::start().await;
    let sender = signer.unlock(PHRASE).await;
    let expected = body(sender, payment());
    let review = signer
        .ok(
            "review",
            serde_json::to_value(wallet::unsigned(&expected)).unwrap(),
        )
        .await;
    assert_eq!(review["chain_id"], hex::encode(expected.chain_id));
    assert_eq!(review["watch"]["format"], "hashstash-watch-v2");
    let mut other = expected.clone();
    other.chain_id = [10; 32];
    let configured = signer
        .ok("network", json!({"chain_id":hex::encode(other.chain_id)}))
        .await;
    assert_eq!(
        configured["address"],
        address::encode(&sender, &other.chain_id).unwrap()
    );
    assert_eq!(
        signer
            .post("sign", json!({"review_token":review["review_token"]}))
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    let review = signer
        .ok(
            "review",
            serde_json::to_value(wallet::unsigned(&other)).unwrap(),
        )
        .await;
    for invalid in [
        json!({"chain_id":"00"}),
        json!({"chain_id":"z".repeat(64)}),
        json!({"chain_id":hex::encode([11;32]),"ignored":true}),
    ] {
        assert_eq!(
            signer.post("network", invalid).await.status(),
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(
        signer
            .post("sign", json!({"review_token":review["review_token"]}))
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    let locked = signer.ok("lock", json!({})).await;
    assert_eq!(locked["chain_id"], hex::encode(other.chain_id));
    assert!(locked["address"].is_null());
    assert_eq!(signer.unlock(PHRASE).await, sender);
    let imported = signer
        .ok("import", json!({"private_key":hex::encode([41;32])}))
        .await;
    let imported_public = crypto::public_key(&[41; 32]).unwrap();
    assert_eq!(imported["chain_id"], hex::encode(other.chain_id));
    assert_eq!(
        imported["address"],
        address::encode(&imported_public, &other.chain_id).unwrap()
    );
    signer.server.stop().await;
}

fn body(sender: PublicKey, operation: Operation) -> TransactionBody {
    TransactionBody {
        data: Vec::new(),
        chain_id: [9; 32],
        sender,
        nonce: 9_007_199_254_740_993,
        expiry_height: 9_007_199_254_740_999,
        fee: (Amount::from(1u32) << 128usize) + 17u32,
        operation,
    }
}

fn payment() -> Operation {
    Operation::TransferExact {
        recipient: crypto::public_key(&[30; 32]).unwrap(),
        amount: 23u32.into(),
    }
}

#[tokio::test]
async fn exact_fee_review_signs_total_and_rejects_ambiguous_envelopes() {
    let signer = Signer::with_chain(Some([9; 32])).await;
    let sender = signer.unlock(PHRASE).await;
    let operation = Operation::TransferExact {
        recipient: crypto::public_key(&[30; 32]).unwrap(),
        amount: 101u32.into(),
    };
    let mut expected = body(sender, operation.clone());
    expected.fee = 20u32.into();
    let review = signer
        .ok(
            "review",
            serde_json::to_value(wallet::unsigned(&expected)).unwrap(),
        )
        .await;
    let fields = review["fields"].as_array().unwrap();
    for (label, value) in [
        ("Fee · HASH", "20"),
        ("Recipient receives · HASH", "101"),
        ("Total debit · HASH", "121"),
    ] {
        assert!(
            fields
                .iter()
                .any(|field| field["label"] == label && field["value"] == value)
        );
    }
    assert!(
        !fields
            .iter()
            .any(|field| field["label"] == "Account creation maximum · HASH")
    );
    let signed = signer
        .ok("sign", json!({"review_token":review["review_token"]}))
        .await;
    assert_eq!(
        wallet::decode_signed(signed["raw"].as_str().unwrap())
            .unwrap()
            .body,
        expected
    );

    let reviewed = signer
        .ok(
            "review",
            serde_json::to_value(wallet::unsigned(&expected)).unwrap(),
        )
        .await;
    let mut ambiguous = serde_json::to_value(wallet::unsigned(&expected)).unwrap();
    ambiguous["max_fee"] = json!("20");
    assert_eq!(
        signer.post("review", ambiguous).await.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        signer
            .post("sign", json!({"review_token":reviewed["review_token"]}))
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    signer.server.stop().await;
}

#[tokio::test]
async fn signer_binds_only_to_loopback() {
    assert!(cold::serve("0.0.0.0:0".parse().unwrap()).await.is_err());
    assert!(cold::serve("192.0.2.1:0".parse().unwrap()).await.is_err());
}

#[tokio::test]
async fn local_api_requires_host_origin_and_session_and_limits_input() {
    let signer = Signer::start().await;
    let good = signer.client.get(&signer.base).send().await.unwrap();
    assert_eq!(good.status(), StatusCode::OK);
    assert_eq!(good.headers()["cache-control"], "no-store");
    assert_eq!(good.headers()["x-content-type-options"], "nosniff");
    assert!(
        good.headers()["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("frame-ancestors 'none'")
    );
    assert!(!good.headers().contains_key("access-control-allow-origin"));
    for (header, value) in [
        ("Host", "evil.example"),
        ("Origin", "https://evil.example"),
        ("Sec-Fetch-Site", "cross-site"),
    ] {
        assert_eq!(
            signer
                .client
                .get(format!("{}/api/session", signer.base))
                .header(header, value)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
    }
    assert_eq!(
        signer
            .client
            .post(format!("{}/api/unlock", signer.base))
            .json(&json!({"passphrase":PHRASE}))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        signer
            .client
            .post(format!("{}/api/unlock", signer.base))
            .header("Origin", &signer.base)
            .header("X-Hashstash-Cold-Token", "wrong")
            .json(&json!({"passphrase":PHRASE}))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        signer
            .client
            .post(format!("{}/api/unlock", signer.base))
            .header("X-Hashstash-Cold-Token", &signer.token)
            .json(&json!({"passphrase":PHRASE}))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        signer
            .post(
                "unlock",
                json!({"passphrase":"a".repeat(cold::MAX_CONTROL_REQUEST)})
            )
            .await
            .status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert_eq!(
        signer
            .post("unlock", json!({"passphrase":PHRASE,"extra":"no"}))
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    let session: Value = signer
        .client
        .get(format!("{}/api/session", signer.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(session["unlocked"], false);
    signer.server.stop().await;
}

#[tokio::test]
async fn all_operations_sign_the_exact_reviewed_bytes_with_exact_large_fields() {
    let signer = Signer::start().await;
    let sender = signer.unlock(PHRASE).await;
    let recipient = crypto::public_key(&[27; 32]).unwrap();
    let mut operations = vec![
        Operation::TransferExact {
            recipient,
            amount: 23u32.into(),
        },
        Operation::Deposit {
            amount: 23u32.into(),

            decision: None,
            outcome: None,
        },
        Operation::Redeem {
            shares: 23u32.into(),

            decision: Some([5; 32]),
            outcome: Some(Outcome::Pass),
        },
        Operation::Propose {
            round: 9_007_199_254_740_993,
            description: [3; 32],
            proposal: Proposal::Grant {
                payments: vec![hashstash::types::GrantPayment {
                    recipient,
                    amount: 23u32.into(),
                }],
            },
            support: 19u32.into(),
        },
        Operation::Support {
            round: 9_007_199_254_740_993,
            proposal: [3; 32],
            amount: 23u32.into(),
        },
        Operation::Refund {
            round: 9_007_199_254_740_993,
            proposal: [3; 32],
        },
    ];
    for parameter in [
        Parameter::BlockBytes,
        Parameter::Lead,
        Parameter::Rest,
        Parameter::DecisionBlocks,
        Parameter::MaxPriceChangeBps,
    ] {
        operations.push(Operation::Propose {
            round: 3,
            description: [3; 32],
            proposal: Proposal::Parameter {
                parameter,
                old: 9_007_199_254_740_993,
                new: 18_014_398_509_481_986,
            },
            support: 19u32.into(),
        });
    }
    for (old, new) in [(50, 0), (50, 75), (50, 100), (0, 1), (100, 60)] {
        operations.push(Operation::Propose {
            round: 3,
            description: [3; 32],
            proposal: Proposal::Parameter {
                parameter: Parameter::MinerFeePercent,
                old,
                new,
            },
            support: 19u32.into(),
        });
    }
    for operation in operations {
        let expected = body(sender, operation);
        let reviewed = signer
            .ok(
                "review",
                serde_json::to_value(wallet::unsigned(&expected)).unwrap(),
            )
            .await;
        assert_eq!(
            reviewed["fields"],
            serde_json::to_value(wallet::review(&expected)).unwrap()
        );
        assert!(
            reviewed["fields"]
                .as_array()
                .unwrap()
                .iter()
                .any(|field| field["label"] == "Nonce" && field["value"] == "9007199254740993")
        );
        let signed = signer
            .ok("sign", json!({"review_token":reviewed["review_token"]}))
            .await;
        let transaction = wallet::decode_signed(signed["raw"].as_str().unwrap()).unwrap();
        assert_eq!(transaction.body, expected);
        assert_eq!(
            signed["txid"],
            hex::encode(codec::transaction_id(&transaction))
        );
        crypto::verify(&transaction).unwrap();
        assert_eq!(
            signer
                .post("sign", json!({"review_token":reviewed["review_token"]}))
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
    signer.server.stop().await;
}

#[tokio::test]
async fn invalid_fee_share_proposals_cannot_be_reviewed_or_signed() {
    let signer = Signer::start().await;
    let sender = signer.unlock(PHRASE).await;
    for (old, new) in [(101, 75), (50, 101), (0, 0), (50, 50), (100, 100)] {
        let invalid = body(
            sender,
            Operation::Propose {
                round: 3,
                description: [3; 32],
                proposal: Proposal::Parameter {
                    parameter: Parameter::MinerFeePercent,
                    old,
                    new,
                },
                support: 19u32.into(),
            },
        );
        assert_eq!(
            signer
                .post(
                    "review",
                    serde_json::to_value(wallet::unsigned(&invalid)).unwrap()
                )
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            signer
                .post("sign", json!({"review_token":"unreviewed"}))
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
    signer.server.stop().await;
}

#[tokio::test]
async fn edits_failed_reviews_lock_and_import_invalidate_old_signatures() {
    let signer = Signer::start().await;
    let sender = signer.unlock(PHRASE).await;
    let envelope = serde_json::to_value(wallet::unsigned(&body(sender, payment()))).unwrap();
    let first = signer.ok("review", envelope.clone()).await;
    let second = signer.ok("review", envelope.clone()).await;
    assert_ne!(first["review_token"], second["review_token"]);
    assert_eq!(
        signer
            .post("sign", json!({"review_token":first["review_token"]}))
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    let alien = body(crypto::public_key(&[28; 32]).unwrap(), payment());
    assert_eq!(
        signer
            .post(
                "review",
                serde_json::to_value(wallet::unsigned(&alien)).unwrap()
            )
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        signer
            .post("sign", json!({"review_token":second["review_token"]}))
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    for reset in ["cancel", "lock"] {
        let review = signer.ok("review", envelope.clone()).await;
        signer.ok(reset, json!({})).await;
        assert_eq!(
            signer
                .post("sign", json!({"review_token":review["review_token"]}))
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(
        signer.post("review", envelope.clone()).await.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(signer.unlock(PHRASE).await, sender);
    let review = signer.ok("review", envelope.clone()).await;
    assert_ne!(signer.unlock("another exact phrase").await, sender);
    assert_eq!(
        signer
            .post("sign", json!({"review_token":review["review_token"]}))
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        signer.post("review", envelope.clone()).await.status(),
        StatusCode::BAD_REQUEST
    );
    signer.unlock(PHRASE).await;
    let review = signer.ok("review", envelope.clone()).await;
    let mut metadata = envelope.clone();
    metadata["amount"] = json!("1");
    assert_eq!(
        signer.post("review", metadata).await.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        signer
            .post("sign", json!({"review_token":review["review_token"]}))
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    let review = signer.ok("review", envelope).await;
    assert_eq!(
        signer
            .post("unlock", json!({"passphrase":""}))
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        signer
            .post("sign", json!({"review_token":review["review_token"]}))
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    signer.server.stop().await;
}

#[tokio::test]
async fn actual_cold_http_signing_round_trip_broadcasts_and_mines() {
    use hashstash::{config::Config, node::Node};
    let signer = Signer::start().await;
    let sender = signer.unlock(PHRASE).await;
    let directory = tempfile::tempdir().unwrap();
    let node = Node::open(
        &directory.path().join("offline.db"),
        Config::devnet(),
        sender,
    )
    .unwrap()
    .with_watch_key(sender)
    .unwrap();
    for _ in 0..12 {
        node.mine(100_000).unwrap();
    }
    let recipient = crypto::public_key(&[29; 32]).unwrap();
    let unsigned = node.rpc("preparetransaction",json!({"sender":hex::encode(sender),"extra_fee":"1","operation":Operation::TransferExact{recipient,amount:5u32.into(),}})).unwrap();
    let mut unsigned = unsigned;
    unsigned.as_object_mut().unwrap().remove("fee_quote");
    let reviewed = signer.ok("review", unsigned).await;
    let signed = signer
        .ok("sign", json!({"review_token":reviewed["review_token"]}))
        .await;
    let accepted = node
        .rpc("broadcasttransaction", json!({"raw":signed["raw"]}))
        .unwrap();
    assert_eq!(accepted["transaction_id"], signed["txid"]);
    node.mine(100_000).unwrap();
    assert_eq!(
        node.rpc("account", json!({"key":hex::encode(recipient)}))
            .unwrap()["account"]["ordinary"],
        "5"
    );
    assert_eq!(
        node.rpc("account", json!({"key":hex::encode(sender)}))
            .unwrap()["account"]["nonce"],
        1
    );
    assert_eq!(node.status().unwrap()["mempool"], 0);
    signer.server.stop().await;
}

#[tokio::test]
async fn importing_private_keys_signs_and_invalidates_previous_reviews() {
    let signer = Signer::start().await;
    let old_sender = signer.unlock(PHRASE).await;
    let old = signer
        .ok(
            "review",
            serde_json::to_value(wallet::unsigned(&body(old_sender, payment()))).unwrap(),
        )
        .await;
    let private = [41u8; 32];
    let sender = crypto::public_key(&private).unwrap();
    let imported = signer
        .ok(
            "import",
            json!({"private_key":format!(" {} ",hex::encode(private))}),
        )
        .await;
    assert_eq!(imported["public_key"], hex::encode(sender));
    assert_eq!(imported["watch"]["public_key"], hex::encode(sender));
    assert_eq!(
        signer
            .post("sign", json!({"review_token":old["review_token"]}))
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    let expected = body(sender, payment());
    let reviewed = signer
        .ok(
            "review",
            serde_json::to_value(wallet::unsigned(&expected)).unwrap(),
        )
        .await;
    let signed = signer
        .ok("sign", json!({"review_token":reviewed["review_token"]}))
        .await;
    assert_eq!(
        wallet::decode_signed(signed["raw"].as_str().unwrap())
            .unwrap()
            .body,
        expected
    );
    for invalid in ["bad key".to_string(), "00".repeat(32), "ff".repeat(32)] {
        let reviewed = signer
            .ok(
                "review",
                serde_json::to_value(wallet::unsigned(&expected)).unwrap(),
            )
            .await;
        assert_eq!(
            signer
                .post("import", json!({"private_key":invalid}))
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            signer
                .post("sign", json!({"review_token":reviewed["review_token"]}))
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );
        signer
            .ok("import", json!({"private_key":hex::encode(private)}))
            .await;
    }
    signer.server.stop().await;
}

#[tokio::test]
async fn malformed_operations_cannot_be_approved_offline() {
    let signer = Signer::start().await;
    let sender = signer.unlock(PHRASE).await;
    let current = body(sender, payment());
    let mut invalid = Vec::new();
    for operation in [
        Operation::TransferExact {
            recipient: [255; 32],
            amount: 1u32.into(),
        },
        Operation::TransferExact {
            recipient: crypto::public_key(&[30; 32]).unwrap(),
            amount: Amount::from(1u32) << 512usize,
        },
    ] {
        invalid.push(body(sender, operation));
    }
    for transaction in invalid {
        let previous = signer
            .ok(
                "review",
                serde_json::to_value(wallet::unsigned(&current)).unwrap(),
            )
            .await;
        assert_eq!(
            signer
                .post(
                    "review",
                    serde_json::to_value(wallet::unsigned(&transaction)).unwrap()
                )
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            signer
                .post("sign", json!({"review_token":previous["review_token"]}))
                .await
                .status(),
            StatusCode::BAD_REQUEST,
            "invalid review must revoke the previous approval"
        );
    }
    signer.server.stop().await;
}
