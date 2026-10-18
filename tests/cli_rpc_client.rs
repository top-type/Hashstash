//! The command-line RPC client trusts only the endpoint the user named, bounds
//! every reply, and signs nothing the endpoint chose beyond local ceilings.
use hashstash::{
    crypto,
    node::{self, RpcClient, RpcLimits, ScanBudget},
    types::{Operation, TransactionBody},
    wallet,
};
use serde_json::{Value, json};
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

/// A one-route HTTP endpoint answering each JSON-RPC method from a closure.
struct Mock {
    address: SocketAddr,
    methods: Arc<Mutex<Vec<String>>>,
}
impl Mock {
    fn url(&self) -> String {
        format!("http://{}/rpc", self.address)
    }
    fn methods(&self) -> Vec<String> {
        self.methods.lock().unwrap().clone()
    }
}

async fn mock(
    delay: Duration,
    reply: impl Fn(&str, &Value) -> Vec<u8> + Send + Sync + 'static,
) -> Mock {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let methods = Arc::new(Mutex::new(Vec::new()));
    let (seen, reply) = (methods.clone(), Arc::new(reply));
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let (seen, reply) = (seen.clone(), reply.clone());
            tokio::spawn(async move {
                let Some(request) = read_request(&mut stream).await else {
                    return;
                };
                let method = request["method"].as_str().unwrap_or_default().to_owned();
                seen.lock().unwrap().push(method.clone());
                let response = reply(&method, &request["params"]);
                tokio::time::sleep(delay).await;
                let _ = stream.write_all(&response).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    Mock { address, methods }
}

async fn read_request(stream: &mut TcpStream) -> Option<Value> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(end) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            let headers = String::from_utf8_lossy(&buffer[..end]).to_ascii_lowercase();
            let length = headers
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .and_then(|value| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            while buffer.len() < end + 4 + length {
                let read = stream.read(&mut chunk).await.ok()?;
                if read == 0 {
                    return None;
                }
                buffer.extend_from_slice(&chunk[..read]);
            }
            return serde_json::from_slice(&buffer[end + 4..end + 4 + length]).ok();
        }
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
}

fn http(status: &str, headers: &str, body: &[u8]) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);
    response
}

fn result(value: Value) -> Vec<u8> {
    http(
        "200 OK",
        "",
        &serde_json::to_vec(&json!({"jsonrpc":"2.0","id":1,"result":value})).unwrap(),
    )
}

async fn cli(arguments: &[String], environment: &[(&str, String)]) -> std::process::Output {
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_hashstash"));
    command.args(arguments).kill_on_drop(true);
    for name in [
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
        "NO_PROXY",
        "no_proxy",
    ] {
        command.env_remove(name);
    }
    for (name, value) in environment {
        command.env(name, value);
    }
    #[cfg(windows)]
    command.creation_flags(0x0800_0000);
    tokio::time::timeout(Duration::from_secs(60), command.output())
        .await
        .expect("CLI exceeded 60 seconds")
        .unwrap()
}

fn args(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| (*item).to_owned()).collect()
}

/// The network the mock endpoints report and fixtures are signed for.
const CHAIN: [u8; 32] = [5; 32];

fn signed_transfer(secret: [u8; 32], nonce: u64) -> hashstash::types::Transaction {
    signed_transfer_for(&CHAIN, secret, nonce)
}

fn signed_transfer_for(
    chain: &[u8; 32],
    secret: [u8; 32],
    nonce: u64,
) -> hashstash::types::Transaction {
    let body = TransactionBody {
        sender: crypto::public_key(&secret).unwrap(),
        nonce,
        fee: 1u32.into(),
        anchor: [3; 32],
        expiry_blocks: 2,
        operation: Operation::TransferExact {
            recipient: crypto::public_key(&[6; 32]).unwrap(),
            amount: 1u32.into(),
        },
        data: Vec::new(),
    };
    crypto::sign(chain, &body, &secret).unwrap()
}

#[test]
fn plain_http_is_limited_to_loopback_literals_without_an_explicit_opt_in() {
    for allowed in [
        "http://127.0.0.1:18480/rpc",
        "http://127.8.9.10/rpc",
        "http://[::1]:18480/rpc",
        "https://node.example/rpc",
        "https://203.0.113.5:18483/rpc",
    ] {
        RpcClient::new(allowed, false).unwrap();
    }
    for refused in [
        "http://203.0.113.5:18483/rpc",
        "http://0.0.0.0:18480/rpc",
        "http://localhost:18480/rpc",
        "http://node.example/rpc",
        "http://user:secret@127.0.0.1/rpc",
        "http://user@127.0.0.1/rpc",
        "http://127.0.0.1/rpc?method=status",
        "http://127.0.0.1/rpc#status",
        "ftp://127.0.0.1/rpc",
        "file:///rpc",
        "127.0.0.1:18480",
    ] {
        assert!(RpcClient::new(refused, false).is_err(), "{refused}");
    }
    // The opt-in admits only the plaintext transport, never credentials or queries.
    let insecure = RpcClient::new("http://203.0.113.5:18483/rpc", true).unwrap();
    assert!(!insecure.is_loopback());
    assert!(RpcClient::new("http://user@203.0.113.5/rpc", true).is_err());
    assert!(RpcClient::new("http://203.0.113.5/rpc?x=1", true).is_err());
    assert!(
        RpcClient::new("http://127.0.0.1/rpc", false)
            .unwrap()
            .is_loopback()
    );
    assert!(
        RpcClient::new("http://[::1]/rpc", false)
            .unwrap()
            .is_loopback()
    );
    assert!(
        !RpcClient::new("https://127.0.0.1.example/rpc", false)
            .unwrap()
            .is_loopback()
    );
}

#[tokio::test]
async fn legacy_call_rpc_applies_the_same_transport_policy() {
    let error = node::call_rpc("http://203.0.113.5:9/rpc", "status", json!({}))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("loopback"), "{error}");
}

#[tokio::test]
async fn redirects_are_refused_instead_of_reposting_the_request() {
    let target = mock(Duration::ZERO, |_, _| result(json!({"redirected":true}))).await;
    for status in [
        "307 Temporary Redirect",
        "308 Permanent Redirect",
        "302 Found",
    ] {
        let location = format!("Location: {}\r\n", target.url());
        let redirecting = mock(Duration::ZERO, move |_, _| http(status, &location, b"")).await;
        let client = RpcClient::new(&redirecting.url(), false).unwrap();
        let error = client
            .call(
                "broadcasttransaction",
                json!({"raw":"00"}),
                RpcLimits::SMALL,
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("redirect"), "{status}: {error}");
        assert_eq!(redirecting.methods(), ["broadcasttransaction"]);
    }
    assert!(target.methods().is_empty(), "a redirect was followed");
}

#[tokio::test]
async fn environment_proxies_never_intercept_the_named_endpoint() {
    let endpoint = mock(Duration::ZERO, |_, _| result(json!({"from":"endpoint"}))).await;
    let proxy = mock(Duration::ZERO, |_, _| result(json!({"from":"proxy"}))).await;
    let proxy_url = format!("http://{}", proxy.address);
    let environment = [
        ("HTTP_PROXY", proxy_url.clone()),
        ("http_proxy", proxy_url.clone()),
        ("ALL_PROXY", proxy_url.clone()),
        ("all_proxy", proxy_url),
    ];
    let output = cli(
        &args(&["rpc", "--url", &endpoint.url(), "status"]),
        &environment,
    )
    .await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let reply: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(reply, json!({"from":"endpoint"}));
    assert_eq!(endpoint.methods(), ["status"]);
    assert!(
        proxy.methods().is_empty(),
        "the CLI used an environment proxy"
    );
}

#[test]
fn json_value_counter_counts_every_allocation_without_parsing() {
    assert_eq!(node::rpc_json_values(br#"{"a":[1,2,"x\"y"],"b":true}"#), 8);
    assert_eq!(node::rpc_json_values(b"[0,0,0]"), 4);
    assert_eq!(node::rpc_json_values(br#"[{"":0},{"":0}]"#), 7);
    assert_eq!(node::rpc_json_values(b" \"[,]{}\" "), 1);
    assert_eq!(node::rpc_json_values(b"-1.5e3"), 1);
    let echo = RpcLimits::echoing(&json!({"data_hex":"ab".repeat(1000)})).unwrap();
    assert!(echo.bytes > 4 * 2000 && echo.bytes < RpcLimits::FRAME.bytes);
    assert_eq!(echo.values, 2 * 3 + RpcLimits::SMALL.values);
}

#[tokio::test]
async fn small_replies_are_bounded_by_bytes_and_json_values() {
    let endpoint = mock(Duration::ZERO, |method, _| match method {
        "large" => result(json!("a".repeat(2 * 1024 * 1024))),
        "dense" => result(json!(vec![0u8; 100_000])),
        "objects" => result(json!(vec![json!({"":0}); 30_000])),
        _ => result(json!({"height":1})),
    })
    .await;
    let client = RpcClient::new(&endpoint.url(), false).unwrap();
    assert_eq!(
        client
            .call("status", json!({}), RpcLimits::SMALL)
            .await
            .unwrap(),
        json!({"height":1})
    );
    for method in ["large", "dense", "objects"] {
        let error = client
            .call(method, json!({}), RpcLimits::SMALL)
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("RPC response"),
            "{method}: {error}"
        );
        // A caller that asked for an arbitrary method still gets the full frame.
        client
            .call(method, json!({}), RpcLimits::FRAME)
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn pending_nonce_discovery_counts_only_signed_rows_and_is_bounded() {
    let secret = [21u8; 32];
    let sender = crypto::public_key(&secret).unwrap();
    let own = [signed_transfer(secret, 4), signed_transfer(secret, 3)];
    let other = signed_transfer([22; 32], 9);
    let row = |tx: &hashstash::types::Transaction| json!({"txid":hex::encode(hashstash::codec::transaction_id(tx)),"raw":wallet::signed_hex(tx)});
    let rows = vec![row(&own[0]), row(&other), row(&own[1])];
    let honest = mock(Duration::ZERO, move |method, params| match method {
        "account" => result(json!({"account":{"nonce":3}})),
        "mempool" if params["offset"] == 0 => result(json!(rows)),
        _ => result(json!([])),
    })
    .await;
    let client = RpcClient::new(&honest.url(), false).unwrap();
    assert_eq!(
        client
            .pending_nonce(&CHAIN, &sender, ScanBudget::DEFAULT)
            .await
            .unwrap(),
        node::PendingNonce {
            nonce: 5,
            account_nonce: 3,
            pending: Some(2)
        }
    );

    // An endpoint that reports its pending nonce is not scanned, so no raw
    // pending record of any governed size is downloaded.
    let reporting = mock(Duration::ZERO, |method, _| match method {
        "account" => result(json!({"account":{"nonce":3},"pending_nonce":7})),
        _ => http("500 Internal Server Error", "", b""),
    })
    .await;
    assert_eq!(
        RpcClient::new(&reporting.url(), false)
            .unwrap()
            .pending_nonce(&CHAIN, &sender, ScanBudget::DEFAULT)
            .await
            .unwrap(),
        node::PendingNonce {
            nonce: 7,
            account_nonce: 3,
            pending: None
        }
    );
    assert_eq!(reporting.methods(), ["account"]);
    // Current endpoints report it as a decimal string, like snapshot does.
    let decimal = mock(Duration::ZERO, |method, _| match method {
        "account" => result(json!({"account":{"nonce":3},"pending_nonce":"8"})),
        _ => http("500 Internal Server Error", "", b""),
    })
    .await;
    assert_eq!(
        RpcClient::new(&decimal.url(), false)
            .unwrap()
            .pending_nonce(&CHAIN, &sender, ScanBudget::DEFAULT)
            .await
            .unwrap()
            .nonce,
        8
    );
    // A reported pending nonce below the account nonce, or one that is not a
    // canonical u64, is refused.
    for reported in [
        json!(2),
        json!("2"),
        json!("08"),
        json!("+8"),
        json!("18446744073709551616"),
    ] {
        let behind = mock(Duration::ZERO, move |_, _| {
            result(json!({"account":{"nonce":3},"pending_nonce":reported.clone()}))
        })
        .await;
        assert!(
            RpcClient::new(&behind.url(), false)
                .unwrap()
                .pending_nonce(&CHAIN, &sender, ScanBudget::DEFAULT)
                .await
                .is_err()
        );
    }

    // Unsigned or forged rows cannot raise the nonce.
    let mut forged = signed_transfer(secret, 40);
    forged.signature[0] ^= 1;
    let forged_row = row(&forged);
    let forging = mock(Duration::ZERO, move |method, params| match method {
        "account" => result(json!({"account":{"nonce":3}})),
        "mempool" if params["offset"] == 0 => result(json!([forged_row])),
        _ => result(json!([])),
    })
    .await;
    assert!(
        RpcClient::new(&forging.url(), false)
            .unwrap()
            .pending_nonce(&CHAIN, &sender, ScanBudget::DEFAULT)
            .await
            .is_err()
    );
    // Neither can a row signed for another network.
    let foreign_row = row(&signed_transfer_for(&[6; 32], secret, 40));
    let foreign = mock(Duration::ZERO, move |method, params| match method {
        "account" => result(json!({"account":{"nonce":3}})),
        "mempool" if params["offset"] == 0 => result(json!([foreign_row])),
        _ => result(json!([])),
    })
    .await;
    assert!(
        RpcClient::new(&foreign.url(), false)
            .unwrap()
            .pending_nonce(&CHAIN, &sender, ScanBudget::DEFAULT)
            .await
            .is_err()
    );

    // One-row pages forever: the byte budget ends the scan.
    let endless_row = row(&other);
    let endless = mock(Duration::ZERO, move |method, _| match method {
        "account" => result(json!({"account":{"nonce":3}})),
        _ => result(json!([endless_row])),
    })
    .await;
    let budget = ScanBudget {
        bytes: 16 * 1024,
        time: Duration::from_secs(60),
    };
    let error = RpcClient::new(&endless.url(), false)
        .unwrap()
        .pending_nonce(&CHAIN, &sender, budget)
        .await
        .unwrap_err();
    assert!(format!("{error:#}").contains("--nonce"), "{error:#}");
    let pages = endless.methods().len() - 1;
    assert!((2..64).contains(&pages), "{pages} pages");

    // Slow one-row pages: the time budget ends the scan.
    let slow_row = row(&other);
    let slow = mock(Duration::from_millis(200), move |method, _| match method {
        "account" => result(json!({"account":{"nonce":3}})),
        _ => result(json!([slow_row])),
    })
    .await;
    let started = std::time::Instant::now();
    let error = RpcClient::new(&slow.url(), false)
        .unwrap()
        .pending_nonce(
            &CHAIN,
            &sender,
            ScanBudget {
                bytes: ScanBudget::DEFAULT.bytes,
                time: Duration::from_secs(1),
            },
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("seconds"), "{error}");
    assert!(started.elapsed() < Duration::from_secs(10));
}

/// The same loopback mock, reached through a host name, counts as remote.
fn remote(mock: &Mock) -> RpcClient {
    let url = format!("http://localhost:{}/rpc", mock.address.port());
    let client = RpcClient::new(&url, true).unwrap();
    assert!(!client.is_loopback());
    client
}

#[tokio::test]
async fn a_remote_pending_nonce_above_the_account_needs_consecutive_signed_rows() {
    let secret = [35u8; 32];
    let sender = crypto::public_key(&secret).unwrap();
    let row = |tx: &hashstash::types::Transaction| json!({"txid":hex::encode(hashstash::codec::transaction_id(tx)),"raw":wallet::signed_hex(tx)});
    let endpoint = |claimed: u64, rows: Vec<Value>| {
        mock(Duration::ZERO, move |method, params| match method {
            "account" => result(json!({"account":{"nonce":3},"pending_nonce":claimed})),
            "mempool" if params["offset"] == 0 => result(json!(rows)),
            _ => result(json!([])),
        })
    };
    // A bare claim plants nonce 4 with no signed transaction behind it.
    let bare = endpoint(4, Vec::new()).await;
    let error = remote(&bare)
        .pending_nonce(&CHAIN, &sender, ScanBudget::DEFAULT)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("--nonce"), "{error}");
    // A withheld nonce-4 transaction cannot justify 5 while nonce 3 is unused.
    let gap = endpoint(5, vec![row(&signed_transfer(secret, 4))]).await;
    assert!(
        remote(&gap)
            .pending_nonce(&CHAIN, &sender, ScanBudget::DEFAULT)
            .await
            .is_err()
    );
    let consecutive = vec![
        row(&signed_transfer(secret, 4)),
        row(&signed_transfer(secret, 3)),
    ];
    let justified = endpoint(5, consecutive.clone()).await;
    assert_eq!(
        remote(&justified)
            .pending_nonce(&CHAIN, &sender, ScanBudget::DEFAULT)
            .await
            .unwrap(),
        node::PendingNonce {
            nonce: 5,
            account_nonce: 3,
            pending: Some(2)
        }
    );
    // A loopback endpoint and a claim equal to the account nonce scan nothing.
    let local = endpoint(5, consecutive).await;
    let found = RpcClient::new(&local.url(), false)
        .unwrap()
        .pending_nonce(&CHAIN, &sender, ScanBudget::DEFAULT)
        .await
        .unwrap();
    assert_eq!((found.nonce, found.pending), (5, None));
    let current = endpoint(3, Vec::new()).await;
    let found = remote(&current)
        .pending_nonce(&CHAIN, &sender, ScanBudget::DEFAULT)
        .await
        .unwrap();
    assert_eq!((found.nonce, found.pending), (3, None));
    assert_eq!(local.methods(), ["account"]);
    assert_eq!(current.methods(), ["account"]);
}

#[tokio::test]
async fn a_remote_endpoint_cannot_choose_the_nonce_of_a_long_lifetime() {
    let chain = hex::encode([36u8; 32]);
    let status = json!({"chain_id":chain,"tip":hex::encode([37u8; 32]),"height":9});
    let endpoint = mock(Duration::ZERO, move |method, _| match method {
        "status" => result(status.clone()),
        _ => http("500 Internal Server Error", "", b""),
    })
    .await;
    let directory = tempfile::tempdir().unwrap();
    let out = directory.path().join("unsigned.json");
    let sender = hex::encode(crypto::public_key(&[38; 32]).unwrap());
    let operation = serde_json::to_string(&Operation::TransferExact {
        recipient: crypto::public_key(&[39; 32]).unwrap(),
        amount: 1u32.into(),
    })
    .unwrap();
    let url = format!("http://localhost:{}/rpc", endpoint.address.port());
    let prepare = |extra: &[&str]| {
        let mut command = args(&[
            "prepare",
            "--url",
            &url,
            "--insecure-http",
            "--chain-id",
            &chain,
            "--sender",
            &sender,
            "--operation",
            &operation,
            "--out",
            out.to_str().unwrap(),
        ]);
        command.extend(args(extra));
        command
    };
    let refused = cli(&prepare(&["--expiry-blocks", "500"]), &[]).await;
    assert!(!refused.status.success());
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("pass --nonce"),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );
    assert_eq!(endpoint.methods(), ["status"]);
    // An explicit nonce, or the default lifetime, proceeds to the endpoint.
    for extra in [&["--expiry-blocks", "500", "--nonce", "0"][..], &[][..]] {
        let output = cli(&prepare(extra), &[]).await;
        assert!(!output.status.success());
        assert!(!String::from_utf8_lossy(&output.stderr).contains("pass --nonce"));
    }
    assert!(endpoint.methods().len() > 3, "{:?}", endpoint.methods());
    assert!(!out.exists());
}

#[tokio::test]
async fn broadcast_rejects_an_endpoint_reporting_another_transaction_id() {
    let transaction = signed_transfer([23; 32], 0);
    let id = hex::encode(hashstash::codec::transaction_id(&transaction));
    let honest_id = id.clone();
    let honest = mock(Duration::ZERO, move |_, _| {
        result(json!({"transaction_id":honest_id}))
    })
    .await;
    let forged = mock(Duration::ZERO, |_, _| {
        result(json!({"transaction_id":hex::encode([0u8; 32])}))
    })
    .await;
    let raw = wallet::signed_hex(&transaction);
    let accepted = cli(
        &args(&["broadcast", "--url", &honest.url(), "--raw", &raw]),
        &[],
    )
    .await;
    assert!(
        accepted.status.success(),
        "{}",
        String::from_utf8_lossy(&accepted.stderr)
    );
    let reply: Value = serde_json::from_slice(&accepted.stdout).unwrap();
    assert_eq!(reply["transaction_id"], id);
    let rejected = cli(
        &args(&["broadcast", "--url", &forged.url(), "--raw", &raw]),
        &[],
    )
    .await;
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("transaction ID"));
}

#[tokio::test]
async fn remote_plain_http_and_unpinned_remote_networks_are_refused_before_any_request() {
    let directory = tempfile::tempdir().unwrap();
    let key = directory.path().join("key.json");
    std::fs::write(
        &key,
        serde_json::to_vec(&json!({"secret":hex::encode([24u8; 32])})).unwrap(),
    )
    .unwrap();
    let key = key.to_str().unwrap();
    let recipient = hex::encode(crypto::public_key(&[6; 32]).unwrap());
    let raw = wallet::signed_hex(&signed_transfer([24; 32], 0));
    let remote = "http://203.0.113.5:9/rpc";
    for command in [
        args(&[
            "transfer",
            "--url",
            remote,
            "--key",
            key,
            "--recipient",
            &recipient,
            "--amount",
            "1",
        ]),
        args(&[
            "prepare",
            "--url",
            remote,
            "--sender",
            &recipient,
            "--operation",
            "{}",
            "--out",
            "x.json",
        ]),
        args(&["rpc", "--url", remote, "status"]),
        args(&["mine", "--url", remote]),
        args(&["broadcast", "--url", remote, "--raw", &raw]),
    ] {
        let output = cli(&command, &[]).await;
        assert!(!output.status.success(), "{command:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("--insecure-http"),
            "{command:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[tokio::test]
async fn sign_reviews_bodies_and_unsigned_exports_on_stderr() {
    let directory = tempfile::tempdir().unwrap();
    let secret = [25u8; 32];
    let sender = crypto::public_key(&secret).unwrap();
    let recipient = crypto::public_key(&[26; 32]).unwrap();
    let chain = [27u8; 32];
    let key = directory.path().join("key.json");
    std::fs::write(
        &key,
        serde_json::to_vec(&json!({"secret":hex::encode(secret)})).unwrap(),
    )
    .unwrap();
    let body = TransactionBody {
        sender,
        nonce: 2,
        fee: 30u32.into(),
        anchor: [28; 32],
        expiry_blocks: 500,
        operation: Operation::TransferExact {
            recipient,
            amount: 70u32.into(),
        },
        data: Vec::new(),
    };
    let export = directory.path().join("unsigned.json");
    std::fs::write(
        &export,
        serde_json::to_vec(&wallet::unsigned(&body, &chain)).unwrap(),
    )
    .unwrap();
    let raw_body = directory.path().join("body.json");
    std::fs::write(&raw_body, serde_json::to_vec(&body).unwrap()).unwrap();
    let sign = |input: &std::path::PathBuf, out: &std::path::PathBuf, network: Option<[u8; 32]>| {
        let mut command: Vec<String> = vec![
            "sign".into(),
            "--key".into(),
            key.to_str().unwrap().into(),
            "--body".into(),
            input.to_str().unwrap().into(),
            "--out".into(),
            out.to_str().unwrap().into(),
        ];
        if let Some(network) = network {
            command.extend(["--chain-id".into(), hex::encode(network)]);
        }
        command
    };
    // The operator names the network: it is never taken from the export, and
    // an export prepared for another network is refused.
    for (input, network) in [
        (&export, None),
        (&raw_body, None),
        (&export, Some([29; 32])),
    ] {
        let out = directory.path().join("refused.json");
        let output = cli(&sign(input, &out, network), &[]).await;
        assert!(!output.status.success(), "{output:?}");
        assert!(!out.exists());
    }
    for (index, input) in [&export, &raw_body].into_iter().enumerate() {
        let out = directory.path().join(format!("signed-{index}.json"));
        let output = cli(&sign(input, &out, Some(chain)), &[]).await;
        assert!(output.status.success(), "{output:?}");
        let review = String::from_utf8_lossy(&output.stderr);
        for expected in [
            "Signing transaction:",
            "Recipient receives: 70 atoms",
            "Fee: 30 atoms",
            "Total debit: 100 atoms",
            "Valid for · blocks: 500",
            "warning: lifetime of 500 blocks",
        ] {
            assert!(
                review.contains(expected),
                "{expected} missing from {review}"
            );
        }
        assert!(review.contains(&hashstash::address::encode(&recipient, &chain).unwrap()));
        assert!(review.contains(&format!("Network · signed: {}", hex::encode(chain))));
        let signed: hashstash::types::Transaction =
            serde_json::from_slice(&std::fs::read(out).unwrap()).unwrap();
        assert_eq!(signed.body, body);
        crypto::verify(&chain, &signed).unwrap();
        assert!(crypto::verify(&[29; 32], &signed).is_err());
    }
}

#[tokio::test]
async fn init_prints_and_accepts_an_explicit_genesis_time() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("network.json");
    let output = cli(
        &args(&[
            "init",
            "--config",
            path.to_str().unwrap(),
            "--genesis-time",
            "1800000000",
        ]),
        &[],
    )
    .await;
    assert!(output.status.success(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("Genesis time: 1800000000 (2027-01-15 08:00:00 UTC)")
    );
    let config: hashstash::config::Config =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(config.genesis_time, 1_800_000_000);
}

#[tokio::test]
async fn an_empty_stratum_password_file_is_refused_before_the_node_opens() {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("network.json");
    std::fs::write(
        &config,
        serde_json::to_vec(&hashstash::config::Config::devnet()).unwrap(),
    )
    .unwrap();
    let data = directory.path().join("chain.sqlite");
    let miner = hex::encode(crypto::public_key(&[29; 32]).unwrap());
    for contents in ["", "\r\n", "two words\n"] {
        let password = directory.path().join("password.txt");
        std::fs::write(&password, contents).unwrap();
        let output = cli(
            &args(&[
                "run",
                "--config",
                config.to_str().unwrap(),
                "--data",
                data.to_str().unwrap(),
                "--miner",
                &miner,
                "--rpc",
                "127.0.0.1:0",
                "--p2p",
                "127.0.0.1:0",
                "--stratum",
                "127.0.0.1:0",
                "--stratum-password-file",
                password.to_str().unwrap(),
            ]),
            &[],
        )
        .await;
        assert!(!output.status.success(), "{contents:?}");
        assert!(String::from_utf8_lossy(&output.stderr).contains("Stratum password"));
        assert!(!data.exists());
    }
}

#[tokio::test]
async fn shared_networks_need_calibration_before_untrusted_peers_reach_them() {
    let directory = tempfile::tempdir().unwrap();
    let path = |name: &str| directory.path().join(name).to_str().unwrap().to_owned();
    let slow = cli(
        &args(&["init", "--config", &path("slow.json"), "--preset", "slow"]),
        &[],
    )
    .await;
    assert!(!slow.status.success());
    assert!(String::from_utf8_lossy(&slow.stderr).contains("--hashrate"));
    assert!(!directory.path().join("slow.json").exists());
    // A production-denominated network that keeps the development limit.
    let mut config = hashstash::config::Config::slow_testnet();
    config.test_work = false;
    std::fs::write(path("easy.json"), serde_json::to_vec(&config).unwrap()).unwrap();
    let miner = hex::encode(crypto::public_key(&[29; 32]).unwrap());
    for exposure in [
        &["--peer-discovery", "--p2p", "127.0.0.1:0"][..],
        &["--p2p", "0.0.0.0:0"][..],
    ] {
        let mut run = args(&[
            "run",
            "--config",
            &path("easy.json"),
            "--data",
            &path("chain.sqlite"),
            "--miner",
            &miner,
            "--rpc",
            "127.0.0.1:0",
            "--no-stratum",
        ]);
        run.extend(args(exposure));
        // An installer's preflight refuses exactly what the service would.
        for preflight in [false, true] {
            let mut run = run.clone();
            if preflight {
                run.push("--preflight".into());
            }
            let output = cli(&run, &[]).await;
            assert!(!output.status.success(), "{exposure:?}");
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(stderr.contains("--allow-easy-target"), "{stderr}");
            assert!(stderr.contains("init --hashrate 73.4G or more"), "{stderr}");
        }
        run.push("--allow-easy-target".into());
        run.push("--preflight".into());
        let output = cli(&run, &[]).await;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stderr).contains("warning: "));
        assert!(!directory.path().join("chain.sqlite").exists());
    }
}

#[cfg(feature = "test-fixtures")]
mod funded {
    use super::*;
    use hashstash::{
        config::Config,
        node::{Node, ServerOptions},
    };

    fn options(public_web: bool) -> ServerOptions {
        let zero: SocketAddr = "127.0.0.1:0".parse().unwrap();
        ServerOptions {
            rpc: zero,
            public_web: public_web.then_some(zero),
            p2p: zero,
            stratum: zero,
            ..Default::default()
        }
    }

    fn successful(output: &std::process::Output) -> (String, String) {
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        (
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    }

    #[tokio::test]
    async fn automatic_fees_need_a_ceiling_and_prepare_pins_nonce_and_network() {
        let directory = tempfile::tempdir().unwrap();
        let secret = [31u8; 32];
        let sender = crypto::public_key(&secret).unwrap();
        let recipient = crypto::public_key(&[32; 32]).unwrap();
        let mut config = Config::testnet();
        config.initial.block_bytes = 1_000_000;
        // An honest but expensive rate stands in for an endpoint inflating it.
        config.initial.minimum_fee_rate = 2048;
        config.initial_bits = 0x1f7fffff;
        config.limit_bits = config.initial_bits;
        config.genesis_time = node::now().saturating_sub(3600) as u32;
        let chain_id = config.chain_id();
        let network = directory.path().join("network.json");
        std::fs::write(&network, serde_json::to_vec(&config).unwrap()).unwrap();
        let node = Node::open(&directory.path().join("chain.sqlite"), config, sender).unwrap();
        for _ in 0..20 {
            node.mine(1_000_000).unwrap();
        }
        let server = node::serve(node.clone(), options(false)).await.unwrap();
        let url = format!("http://{}/rpc", server.rpc);
        let key = directory.path().join("key.json");
        std::fs::write(
            &key,
            serde_json::to_vec(&json!({"secret":hex::encode(secret)})).unwrap(),
        )
        .unwrap();
        let transfer = |extra: &[&str]| {
            let mut command = args(&[
                "transfer",
                "--url",
                &url,
                "--key",
                key.to_str().unwrap(),
                "--recipient",
                &hex::encode(recipient),
                "--amount",
                "1",
            ]);
            command.extend(args(extra));
            command
        };
        for refused in [&[][..], &["--max-fee", "2000"][..]] {
            let output = cli(&transfer(refused), &[]).await;
            assert!(!output.status.success(), "{refused:?}");
            assert!(String::from_utf8_lossy(&output.stderr).contains("atom ceiling"));
        }
        assert_eq!(node.status().unwrap()["mempool"], 0);
        let (stdout, review) = successful(&cli(&transfer(&["--max-fee", "100000"]), &[]).await);
        let pending = node.rpc("mempool", json!({"format":"hex"})).unwrap();
        let sent: Value = serde_json::from_str(&stdout).unwrap();
        assert_eq!(sent["txid"], pending[0]["txid"]);
        let transaction =
            wallet::decode_signed(pending[0]["raw"].as_str().unwrap(), &chain_id).unwrap();
        assert!(transaction.body.fee > 2000u32.into());
        for expected in [
            format!("Fee: {} atoms", transaction.body.fee),
            "account creation 2048 atoms".into(),
            "ceiling 100000 atoms".into(),
            "Nonce source: account nonce 0 reported by the endpoint, pending nonce 0".into(),
            format!("Network · signed: {}", hex::encode(chain_id)),
        ] {
            assert!(
                review.contains(&expected),
                "{expected} missing from {review}"
            );
        }

        let operation = serde_json::to_string(&Operation::TransferExact {
            recipient,
            amount: 1u32.into(),
        })
        .unwrap();
        let prepare = |out: &str, extra: &[&str]| {
            let mut command = args(&[
                "prepare",
                "--url",
                &url,
                "--sender",
                &hex::encode(sender),
                "--operation",
                &operation,
                "--max-fee",
                "100000",
                "--out",
            ]);
            command.push(directory.path().join(out).to_str().unwrap().to_owned());
            command.extend(args(extra));
            command
        };
        // The honest node enforces a requested nonce, so the CLI's choice binds it.
        let wrong = cli(&prepare("wrong.json", &["--nonce", "9"]), &[]).await;
        assert!(!wrong.status.success());
        assert!(!directory.path().join("wrong.json").exists());
        let (_, review) = successful(&cli(&prepare("next.json", &[]), &[]).await);
        assert!(
            review.contains("account nonce 0 reported by the endpoint, pending nonce 1"),
            "{review}"
        );
        let envelope =
            serde_json::from_slice(&std::fs::read(directory.path().join("next.json")).unwrap())
                .unwrap();
        assert_eq!(wallet::decode_unsigned(&envelope).unwrap().nonce, 1);
        successful(&cli(&prepare("explicit.json", &["--nonce", "1"]), &[]).await);
        let other_network = cli(
            &prepare("other.json", &["--chain-id", &hex::encode([9u8; 32])]),
            &[],
        )
        .await;
        assert!(!other_network.status.success());
        assert!(String::from_utf8_lossy(&other_network.stderr).contains("not the selected"));
        assert!(!directory.path().join("other.json").exists());
        successful(
            &cli(
                &prepare("pinned.json", &["--config", network.to_str().unwrap()]),
                &[],
            )
            .await,
        );
        successful(
            &cli(
                &prepare("chain.json", &["--chain-id", &hex::encode(chain_id)]),
                &[],
            )
            .await,
        );

        // A second endpoint must hold the anchor on its canonical chain of this network.
        let (_, review) =
            successful(&cli(&prepare("anchored.json", &["--anchor-url", &url]), &[]).await);
        assert!(
            review.contains("Anchor check: a canonical block of this network at --anchor-url"),
            "{review}"
        );
        let status = node.status().unwrap();
        let (tip, height) = (status["tip"].clone(), status["height"].as_u64().unwrap());
        let chain = hex::encode(chain_id);
        for (case, network, block) in [
            (
                "foreign",
                hex::encode([9u8; 32]),
                json!({"hash":tip,"height":height,"status":"confirmed"}),
            ),
            (
                "height",
                chain.clone(),
                json!({"hash":tip,"height":height + 1,"status":"confirmed"}),
            ),
            (
                "orphaned",
                chain.clone(),
                json!({"hash":tip,"height":height,"status":"orphaned"}),
            ),
        ] {
            let anchor = mock(Duration::ZERO, move |method, _| match method {
                "status" => result(json!({"chain_id":network})),
                _ => result(json!({"block":block})),
            })
            .await;
            let out = format!("{case}.json");
            let output = cli(&prepare(&out, &["--anchor-url", &anchor.url()]), &[]).await;
            assert!(!output.status.success(), "{case}");
            assert!(
                String::from_utf8_lossy(&output.stderr).contains("--anchor-url"),
                "{case}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(!directory.path().join(&out).exists(), "{case}");
        }
        server.stop().await;
    }

    #[tokio::test]
    async fn transfer_works_through_the_public_listener_with_signed_hex() {
        let directory = tempfile::tempdir().unwrap();
        let secret = [33u8; 32];
        let sender = crypto::public_key(&secret).unwrap();
        let mut config = Config::devnet();
        config.genesis_time = node::now().saturating_sub(3600) as u32;
        let node = Node::open(&directory.path().join("chain.sqlite"), config, sender).unwrap();
        for _ in 0..20 {
            node.mine(100_000).unwrap();
        }
        let server = node::serve(node.clone(), options(true)).await.unwrap();
        let key = directory.path().join("key.json");
        std::fs::write(
            &key,
            serde_json::to_vec(&json!({"secret":hex::encode(secret)})).unwrap(),
        )
        .unwrap();
        let output = cli(
            &args(&[
                "transfer",
                "--url",
                &format!("http://{}/rpc", server.public_web.unwrap()),
                "--key",
                key.to_str().unwrap(),
                "--recipient",
                &hex::encode(crypto::public_key(&[34; 32]).unwrap()),
                "--amount",
                "1",
            ]),
            &[],
        )
        .await;
        let (stdout, _) = successful(&output);
        let sent: Value = serde_json::from_str(&stdout).unwrap();
        let pending = node.rpc("mempool", json!({"format":"hex"})).unwrap();
        assert_eq!(sent["txid"], pending[0]["txid"]);
        server.stop().await;
    }
}
