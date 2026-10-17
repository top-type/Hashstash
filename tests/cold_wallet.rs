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
    let envelope = serde_json::to_value(wallet::unsigned(&expected, &[9; 32])).unwrap();
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
            serde_json::to_value(wallet::unsigned(&expected, &[9; 32])).unwrap(),
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
            serde_json::to_value(wallet::unsigned(&expected, &[9; 32])).unwrap(),
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
    /// Reviews need an operator-selected network; fixtures use [9; 32].
    async fn start() -> Self {
        Self::with_chain(Some([9; 32])).await
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
        // Loopback is shared by every local account: the token is handed
        // only to whoever started the signer, never over HTTP.
        assert!(session.get("token").is_none());
        Self {
            token: server.token().into(),
            server,
            client,
            base,
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

    /// Restores a legacy v1 passphrase account; cheap for review fixtures.
    async fn unlock(&self, phrase: &str) -> PublicKey {
        let value = self
            .ok(
                "unlock",
                json!({"passphrase":phrase,"scheme":wallet::PASSPHRASE_SCHEME}),
            )
            .await;
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
async fn configured_network_formats_addresses_and_rejects_mismatched_export_context() {
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
            serde_json::to_value(wallet::unsigned(&expected, &[9; 32])).unwrap(),
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
    // Unsigned display context is checked in full, but does not prove anchor ancestry.
    let mut alien_chain = chain;
    alien_chain[31] ^= 1;
    assert_eq!(address::hrp(&alien_chain), address::hrp(&chain));
    let alien = wallet::unsigned(&expected, &alien_chain);
    assert_eq!(
        signer
            .post("review", serde_json::to_value(alien).unwrap())
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
                serde_json::to_value(wallet::unsigned(&expected, &[9; 32])).unwrap()
            )
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    signer.server.stop().await;
}

#[tokio::test]
async fn network_changes_invalidate_review_and_persist_across_key_changes() {
    let signer = Signer::with_chain(None).await;
    let sender = signer.unlock(PHRASE).await;
    let expected = body(sender, payment());
    let envelope = serde_json::to_value(wallet::unsigned(&expected, &[9; 32])).unwrap();
    // Unsigned export context is never adopted as the signer's network.
    let refused = signer.post("review", envelope.clone()).await;
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    assert!(
        refused.text().await.unwrap().contains("Select this signer's network"),
        "review without a selected network must explain the requirement"
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
    assert!(session["chain_id"].is_null());
    signer
        .ok("network", json!({"chain_id":hex::encode([9;32])}))
        .await;
    let review = signer.ok("review", envelope).await;
    assert_eq!(review["chain_id"], hex::encode([9; 32]));
    assert_eq!(review["watch"]["format"], "hashstash-watch-v2");
    let other_chain = [10; 32];
    let configured = signer
        .ok("network", json!({"chain_id":hex::encode(other_chain)}))
        .await;
    assert_eq!(
        configured["address"],
        address::encode(&sender, &other_chain).unwrap()
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
            serde_json::to_value(wallet::unsigned(&expected, &other_chain)).unwrap(),
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
    assert_eq!(locked["chain_id"], hex::encode(other_chain));
    assert!(locked["address"].is_null());
    assert_eq!(signer.unlock(PHRASE).await, sender);
    let imported = signer
        .ok("import", json!({"private_key":hex::encode([41;32])}))
        .await;
    let imported_public = crypto::public_key(&[41; 32]).unwrap();
    assert_eq!(imported["chain_id"], hex::encode(other_chain));
    assert_eq!(
        imported["address"],
        address::encode(&imported_public, &other_chain).unwrap()
    );
    signer.server.stop().await;
}

fn body(sender: PublicKey, operation: Operation) -> TransactionBody {
    TransactionBody {
        data: Vec::new(),
        sender,
        nonce: 9_007_199_254_740_993,
        anchor: [0; 32],
        // The longest lifetime signable without an extra confirmation.
        expiry_blocks: wallet::LONG_LIFETIME_BLOCKS,
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
            serde_json::to_value(wallet::unsigned(&expected, &[9; 32])).unwrap(),
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
            serde_json::to_value(wallet::unsigned(&expected, &[9; 32])).unwrap(),
        )
        .await;
    let mut ambiguous = serde_json::to_value(wallet::unsigned(&expected, &[9; 32])).unwrap();
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
                serde_json::to_value(wallet::unsigned(&expected, &[9; 32])).unwrap(),
            )
            .await;
        assert_eq!(
            reviewed["fields"],
            serde_json::to_value(wallet::review(&expected, Some(&[9; 32]))).unwrap()
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
                    serde_json::to_value(wallet::unsigned(&invalid, &[9; 32])).unwrap()
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
    let envelope =
        serde_json::to_value(wallet::unsigned(&body(sender, payment()), &[9; 32])).unwrap();
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
                serde_json::to_value(wallet::unsigned(&alien, &[9; 32])).unwrap()
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
            .post(
                "unlock",
                json!({"passphrase":"","scheme":wallet::PASSPHRASE_SCHEME})
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
    signer.server.stop().await;
}

#[tokio::test]
async fn actual_cold_http_signing_round_trip_broadcasts_and_mines() {
    use hashstash::{config::Config, node::Node};
    let signer = Signer::with_chain(Some(Config::devnet().chain_id())).await;
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
            serde_json::to_value(wallet::unsigned(&body(old_sender, payment()), &[9; 32])).unwrap(),
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
            serde_json::to_value(wallet::unsigned(&expected, &[9; 32])).unwrap(),
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
                serde_json::to_value(wallet::unsigned(&expected, &[9; 32])).unwrap(),
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
                serde_json::to_value(wallet::unsigned(&current, &[9; 32])).unwrap(),
            )
            .await;
        assert_eq!(
            signer
                .post(
                    "review",
                    serde_json::to_value(wallet::unsigned(&transaction, &[9; 32])).unwrap()
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

fn v2_vector(index: usize) -> (String, Hash, String) {
    let document: Value = serde_json::from_str(include_str!("data/passphrase-v2.json")).unwrap();
    let vector = &document["vectors"][index];
    (
        vector["passphrase"].as_str().unwrap().into(),
        hex::decode(vector["chain_id"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
        vector["public_key"].as_str().unwrap().into(),
    )
}

#[tokio::test]
async fn passphrases_need_an_explicit_scheme_and_v2_belongs_to_the_selected_network() {
    let (phrase, chain, public) = v2_vector(0);
    let signer = Signer::with_chain(None).await;
    for request in [
        json!({"passphrase":phrase}),
        json!({"passphrase":phrase,"scheme":"hashstash-passphrase-v3"}),
        json!({"passphrase":phrase,"scheme":wallet::PASSPHRASE_V2_SCHEME}),
    ] {
        assert_eq!(
            signer.post("unlock", request).await.status(),
            StatusCode::BAD_REQUEST,
            "no legacy default, unknown scheme, or v2 without a network"
        );
    }
    signer
        .ok("network", json!({"chain_id":hex::encode(chain)}))
        .await;
    assert_eq!(
        signer
            .post(
                "unlock",
                json!({"passphrase":"fifteen bytes!!","scheme":wallet::PASSPHRASE_V2_SCHEME})
            )
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    let opened = signer
        .ok(
            "unlock",
            json!({"passphrase":phrase,"scheme":wallet::PASSPHRASE_V2_SCHEME}),
        )
        .await;
    assert_eq!(opened["public_key"], public);
    let legacy = crypto::public_key(&wallet::derive_secret(&phrase).unwrap()).unwrap();
    assert_ne!(opened["public_key"], hex::encode(legacy));
    let sender: PublicKey = hex::decode(&public).unwrap().try_into().unwrap();
    let review = signer
        .ok(
            "review",
            serde_json::to_value(wallet::unsigned(&body(sender, payment()), &chain)).unwrap(),
        )
        .await;
    // Re-selecting the same network keeps the key; another network locks it.
    let same = signer
        .ok("network", json!({"chain_id":hex::encode(chain)}))
        .await;
    assert_eq!(same["public_key"], public);
    let other = signer
        .ok("network", json!({"chain_id":hex::encode([40;32])}))
        .await;
    assert_eq!(other["unlocked"], false);
    assert!(other["public_key"].is_null());
    assert_eq!(
        signer
            .post("sign", json!({"review_token":review["review_token"]}))
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    // Legacy v1 still restores its exact account and survives network changes.
    let restored = signer
        .ok(
            "unlock",
            json!({"passphrase":phrase,"scheme":wallet::PASSPHRASE_SCHEME}),
        )
        .await;
    assert_eq!(restored["public_key"], hex::encode(legacy));
    let moved = signer
        .ok("network", json!({"chain_id":hex::encode(chain)}))
        .await;
    assert_eq!(moved["public_key"], hex::encode(legacy));
    signer.server.stop().await;
}

#[tokio::test]
async fn generated_keys_are_random_return_one_backup_and_sign() {
    let signer = Signer::start().await;
    let first = signer.ok("generate", json!({})).await;
    let second = signer.ok("generate", json!({})).await;
    assert_ne!(first["public_key"], second["public_key"]);
    let backup = &second["backup"];
    assert_eq!(backup["format"], "hashstash-private-v1");
    assert_eq!(backup["public_key"], second["public_key"]);
    let secret: [u8; 32] = hex::decode(backup["private_key"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let sender = crypto::public_key(&secret).unwrap();
    assert_eq!(second["public_key"], hex::encode(sender));
    assert_eq!(second["watch"]["format"], "hashstash-watch-v2");
    let session: Value = signer
        .client
        .get(format!("{}/api/session", signer.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(session.get("backup").is_none(), "status never carries the private key");
    assert_eq!(session["public_key"], hex::encode(sender));
    assert_eq!(session["backup_pending"], true);
    // Until the operator saves it (for example after a page reload), the backup
    // can be fetched again; afterwards the signer no longer releases the key.
    assert_eq!(signer.ok("backup", json!({})).await["backup"], *backup);
    let saved = signer.ok("backup", json!({"saved":true})).await;
    assert_eq!(saved["backup_pending"], false);
    assert_eq!(saved["public_key"], hex::encode(sender));
    for request in [json!({}), json!({"saved":true}), json!({"saved":true,"x":1})] {
        assert_eq!(
            signer.post("backup", request).await.status(),
            StatusCode::BAD_REQUEST
        );
    }
    let expected = body(sender, payment());
    let review = signer
        .ok(
            "review",
            serde_json::to_value(wallet::unsigned(&expected, &[9; 32])).unwrap(),
        )
        .await;
    let signed = signer
        .ok("sign", json!({"review_token":review["review_token"]}))
        .await;
    assert_eq!(
        wallet::decode_signed(signed["raw"].as_str().unwrap())
            .unwrap()
            .body,
        expected
    );
    // The restored backup is the same account.
    let restored = signer
        .ok("import", json!({"private_key":backup["private_key"]}))
        .await;
    assert_eq!(restored["public_key"], hex::encode(sender));
    assert_eq!(restored["backup_pending"], false);
    signer.ok("generate", json!({})).await;
    signer.ok("lock", json!({})).await;
    assert_eq!(
        signer.post("backup", json!({})).await.status(),
        StatusCode::BAD_REQUEST,
        "locking discards the pending key and its backup"
    );
    signer.server.stop().await;
}

#[tokio::test]
async fn long_lifetimes_need_explicit_confirmation_before_signing() {
    let signer = Signer::start().await;
    let sender = signer.unlock(PHRASE).await;
    let mut expected = body(sender, payment());
    let short = signer
        .ok(
            "review",
            serde_json::to_value(wallet::unsigned(&expected, &[9; 32])).unwrap(),
        )
        .await;
    assert_eq!(short["confirm_lifetime"], false);
    assert!(
        !short["fields"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["label"] == "Lifetime warning")
    );
    for lifetime in [wallet::LONG_LIFETIME_BLOCKS + 1, u64::MAX] {
        expected.expiry_blocks = lifetime;
        let review = signer
            .ok(
                "review",
                serde_json::to_value(wallet::unsigned(&expected, &[9; 32])).unwrap(),
            )
            .await;
        assert_eq!(review["confirm_lifetime"], true);
        assert!(review["fields"].as_array().unwrap().iter().any(|f| {
            f["label"] == "Lifetime warning" && f["value"].as_str().unwrap().contains(&lifetime.to_string())
        }));
        for unconfirmed in [
            json!({"review_token":review["review_token"]}),
            json!({"review_token":review["review_token"],"confirm_lifetime":false}),
        ] {
            let refused = signer.post("sign", unconfirmed).await;
            assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
            assert!(refused.text().await.unwrap().contains("Confirm the long"));
        }
        // A refused confirmation keeps the review, so the operator can confirm it.
        let signed = signer
            .ok(
                "sign",
                json!({"review_token":review["review_token"],"confirm_lifetime":true}),
            )
            .await;
        let transaction = wallet::decode_signed(signed["raw"].as_str().unwrap()).unwrap();
        assert_eq!(transaction.body.expiry_blocks, lifetime);
    }
    signer.server.stop().await;
}

#[tokio::test]
async fn review_requests_have_a_finite_configurable_limit() {
    let limit = 2 * cold::MAX_CONTROL_REQUEST;
    let server = cold::serve_with_limits("127.0.0.1:0".parse().unwrap(), Some([9; 32]), limit)
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
    assert_eq!(session["max_review_bytes"], limit);
    let signer = Signer {
        token: server.token().into(),
        server,
        client,
        base,
    };
    let sender = signer.unlock(PHRASE).await;
    let mut expected = body(sender, payment());
    expected.data = vec![7; cold::MAX_CONTROL_REQUEST / 2];
    signer
        .ok(
            "review",
            serde_json::to_value(wallet::unsigned(&expected, &[9; 32])).unwrap(),
        )
        .await;
    expected.data = vec![7; limit];
    assert_eq!(
        signer
            .post(
                "review",
                serde_json::to_value(wallet::unsigned(&expected, &[9; 32])).unwrap()
            )
            .await
            .status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert!(
        cold::serve_with_limits(
            "127.0.0.1:0".parse().unwrap(),
            None,
            cold::MAX_CONTROL_REQUEST - 1
        )
        .await
        .is_err()
    );
    let default = Signer::start().await;
    let session: Value = default
        .client
        .get(format!("{}/api/session", default.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(session["max_review_bytes"], cold::DEFAULT_MAX_REVIEW_REQUEST);
    assert_eq!(
        session["idle_lock_seconds"],
        cold::DEFAULT_IDLE_LOCK.as_secs()
    );
    default.server.stop().await;
    signer.server.stop().await;
}

#[tokio::test]
async fn proposal_review_reports_whether_text_matches_the_signed_description() {
    use sha2::{Digest, Sha256};
    let signer = Signer::start().await;
    let sender = signer.unlock(PHRASE).await;
    let text = "Pay the shared explorer host";
    let proposal = |description: Hash| Operation::Propose {
        round: 3,
        description,
        proposal: Proposal::Grant {
            payments: vec![hashstash::types::GrantPayment {
                recipient: crypto::public_key(&[30; 32]).unwrap(),
                amount: 5u32.into(),
            }],
        },
        support: 1u32.into(),
    };
    for (description, verdict) in [
        (Sha256::digest(text.as_bytes()).into(), "Matches the description hash"),
        ([3; 32], "Does not match the description hash"),
    ] {
        let mut expected = body(sender, proposal(description));
        expected.data = text.as_bytes().to_vec();
        let review = signer
            .ok(
                "review",
                serde_json::to_value(wallet::unsigned(&expected, &[9; 32])).unwrap(),
            )
            .await;
        assert!(
            review["fields"]
                .as_array()
                .unwrap()
                .iter()
                .any(|f| f["label"] == "Rationale" && f["value"] == verdict)
        );
    }
    signer.server.stop().await;
}

#[tokio::test]
async fn session_token_reaches_only_the_launcher_and_idle_wallets_lock() {
    use std::time::Duration;
    // Another local account can reach loopback and send any header, so the
    // session endpoint and page never carry the token; the launch URL does.
    let chosen = "5a".repeat(32);
    let options = |token: Option<String>, idle_lock| cold::ColdOptions {
        chain_id: Some([9; 32]),
        token,
        idle_lock,
        ..cold::ColdOptions::default()
    };
    let loopback = || "127.0.0.1:0".parse().unwrap();
    for bad in ["5A".repeat(32), "5a".repeat(31), "zz".repeat(32)] {
        let refused =
            cold::serve_with_options(loopback(), options(Some(bad), cold::DEFAULT_IDLE_LOCK));
        assert!(refused.await.is_err());
    }
    assert!(
        cold::serve_with_options(loopback(), options(None, Duration::ZERO))
            .await
            .is_err()
    );
    let idle = Duration::from_millis(800);
    let server = cold::serve_with_options(loopback(), options(Some(chosen.clone()), idle))
        .await
        .unwrap();
    let base = format!("http://{}", server.address);
    assert_eq!(server.token(), chosen);
    assert_eq!(server.launch_url(), format!("{base}/#token={chosen}"));
    let client = Client::new();
    for path in ["/", "/app.js", "/api/session"] {
        let text = client
            .get(format!("{base}{path}"))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert!(!text.contains(&chosen), "{path}");
    }
    let signer = Signer {
        token: server.token().into(),
        server,
        client,
        base,
    };
    let sender = signer.unlock(PHRASE).await;
    let envelope =
        serde_json::to_value(wallet::unsigned(&body(sender, payment()), &[9; 32])).unwrap();
    let reviewed = signer.ok("review", envelope.clone()).await;
    // Left unused, the open wallet and its review lock themselves.
    tokio::time::sleep(idle * 3).await;
    let refused = signer
        .post("sign", json!({"review_token":reviewed["review_token"]}))
        .await;
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    let text = refused.text().await.unwrap();
    assert!(text.contains("locked after a period without use"), "{text}");
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
    assert_eq!(session["idle_locked"], true);
    // Opening a wallet clears the notice, and use keeps it open.
    signer.unlock(PHRASE).await;
    for _ in 0..3 {
        tokio::time::sleep(idle / 4).await;
        signer.ok("review", envelope.clone()).await;
    }
    // Locking by hand clears the notice; a request then needs a wallet.
    signer.ok("lock", json!({})).await;
    let text = signer
        .post("review", envelope.clone())
        .await
        .text()
        .await
        .unwrap();
    assert!(text.contains("Open a wallet first"), "{text}");
    // The signer also wipes a forgotten key while no request arrives at all.
    signer.unlock(PHRASE).await;
    tokio::time::sleep(idle * 3).await;
    let text = signer
        .post("review", envelope)
        .await
        .text()
        .await
        .unwrap();
    assert!(text.contains("locked after a period without use"), "{text}");
    signer.server.stop().await;
}
