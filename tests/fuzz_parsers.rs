//! Seeded mutation fuzzing of every parser that reads hostile input, on the
//! stable toolchain. The targets, seeds and invariants are shared with the
//! cargo-fuzz crate in `fuzz/` (coverage-guided, nightly; see
//! docs/VALIDATION.md). Each in-process target gets a fixed, deterministic
//! budget here; inputs whose outcome label is new join the corpus, a cheap
//! stand-in for coverage feedback. Every input under `fuzz/regressions/` is
//! replayed. The two listener tests drive mutated Stratum lines and HTTP
//! requests through real sockets and require the node to stay healthy with
//! no panicked session. The mail envelope vectors that the browser's parser
//! must agree with (`fuzz/js/mail_envelope.cjs`) are checked against the node.
//!
//! Longer runs, with a random or chosen seed:
//!   HASHSTASH_FUZZ_SECONDS=300 cargo test --release --features test-fixtures \
//!     --test fuzz_parsers -- --ignored --nocapture fuzz_for_a_bounded_time
//! (optionally HASHSTASH_FUZZ_TARGETS=peer_wire,json and HASHSTASH_FUZZ_SEED=N).
//! They also start from any libFuzzer corpus under HASHSTASH_FUZZ_CORPUS
//! (default: `fuzz/corpus`); the ordinary runs never read one, because it is
//! untracked. A failing input is saved under HASHSTASH_FUZZ_ARTIFACTS
//! (default: the system temporary directory) as hexadecimal, ready for
//! `fuzz/regressions/`.
#[allow(dead_code)]
#[path = "../fuzz/src/lib.rs"]
mod targets;

use hashstash::{
    config::Config,
    crypto,
    node::{self, Node, Server, ServerOptions},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    panic::{AssertUnwindSafe, catch_unwind},
    path::{Path, PathBuf},
    sync::{
        Once,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use targets::{Run, TARGETS, Target};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpSocket, TcpStream},
    time::timeout,
};

/// The fixed seed of the deterministic runs in the ordinary suite.
const SEED: u64 = 0x6861_7368_7374_6173;
/// In-process inputs per unit of target cost in the ordinary suite.
const BUDGET: u64 = if cfg!(debug_assertions) {
    1_500
} else {
    24_000
};
/// One input that takes longer than this is reported as a hang.
const HANG: Duration = Duration::from_secs(30);
const MAX_CORPUS: usize = 4096;

/// splitmix64: small, fast and identical on every platform.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
    fn byte(&mut self) -> u8 {
        self.next() as u8
    }
}

const INTERESTING: &[u64] = &[
    0,
    1,
    2,
    9,
    16,
    32,
    64,
    0x7f,
    0x80,
    0xfa,
    0xfb,
    0xfc,
    0xfd,
    0xfe,
    0xff,
    0x100,
    0x7fff,
    0x8000,
    0xffff,
    0x1_0000,
    0x7fff_ffff,
    0x8000_0000,
    0xffff_ffff,
    0x1_0000_0000,
    i64::MAX as u64,
    u64::MAX,
];

/// Stack one to eight byte-level edits: bit flips, interesting bytes and
/// integers (both byte orders, all widths), insertions, deletions, copies,
/// dictionary tokens, crossover with another corpus entry, truncation and
/// replacement of decimal numbers.
fn mutate(
    rng: &mut Rng,
    input: &mut Vec<u8>,
    corpus: &[Vec<u8>],
    dictionary: &[&[u8]],
    max_len: usize,
) {
    for _ in 0..1usize << rng.below(4) {
        let len = input.len();
        match rng.below(14) {
            0 if len > 0 => {
                let at = rng.below(len);
                input[at] ^= 1 << rng.below(8);
            }
            1 if len > 0 => {
                let at = rng.below(len);
                input[at] = rng.byte();
            }
            2 if len > 0 => {
                let at = rng.below(len);
                input[at] = INTERESTING[rng.below(INTERESTING.len())] as u8;
            }
            3 if len > 0 => {
                let at = rng.below(len);
                input[at] = input[at].wrapping_add(rng.below(33) as u8).wrapping_sub(16);
            }
            4 => {
                let at = rng.below(len + 1);
                let bytes: Vec<u8> = (0..1 + rng.below(16)).map(|_| rng.byte()).collect();
                input.splice(at..at, bytes);
            }
            5 if len > 0 => {
                let at = rng.below(len);
                let count = 1 + rng.below((len - at).min(64));
                input.drain(at..at + count);
            }
            6 if len > 0 => {
                let from = rng.below(len);
                let count = 1 + rng.below((len - from).min(256));
                let chunk = input[from..from + count].to_vec();
                let at = rng.below(len + 1);
                input.splice(at..at, chunk);
            }
            7 if len > 0 => {
                let value = INTERESTING[rng.below(INTERESTING.len())];
                let width = [1, 2, 4, 8][rng.below(4)];
                let bytes = if rng.below(2) == 0 {
                    value.to_le_bytes()[..width].to_vec()
                } else {
                    value.to_be_bytes()[8 - width..].to_vec()
                };
                let at = rng.below(len);
                for (offset, byte) in bytes.into_iter().enumerate() {
                    if let Some(slot) = input.get_mut(at + offset) {
                        *slot = byte;
                    }
                }
            }
            8 if !dictionary.is_empty() => {
                let token = dictionary[rng.below(dictionary.len())];
                let at = rng.below(len + 1);
                input.splice(at..at, token.iter().copied());
            }
            9 if !dictionary.is_empty() && len > 0 => {
                let token = dictionary[rng.below(dictionary.len())];
                let at = rng.below(len);
                let end = (at + token.len()).min(len);
                input.splice(at..end, token.iter().copied());
            }
            10 if !corpus.is_empty() => {
                let other = &corpus[rng.below(corpus.len())];
                let cut = rng.below(len + 1);
                let from = rng.below(other.len() + 1);
                input.truncate(cut);
                input.extend_from_slice(&other[from..]);
            }
            11 if len > 0 => input.truncate(rng.below(len)),
            12 if len > 0 => {
                // A decimal number near a random point becomes another one.
                let at = rng.below(len);
                if let Some(start) = (at..len).find(|&i| input[i].is_ascii_digit()) {
                    let end = (start..len)
                        .find(|&i| !input[i].is_ascii_digit())
                        .unwrap_or(len);
                    let number = match rng.below(3) {
                        0 => INTERESTING[rng.below(INTERESTING.len())].to_string(),
                        1 => "9".repeat(1 + rng.below(80)),
                        _ => (rng.next() >> rng.below(64)).to_string(),
                    };
                    input.splice(start..end, number.into_bytes());
                }
            }
            13 if len > 1 => {
                let (a, b) = (rng.below(len), rng.below(len));
                input.swap(a, b);
            }
            _ => input.push(rng.byte()),
        }
    }
    input.truncate(max_len);
}

/// Outcome labels without the input they quote back, in quotes or in
/// parentheses such as another peer protocol generation's marker, or
/// numbers, hashes and keys. Quoted-back bytes can hold parentheses
/// themselves, so everything from the first `(` to the last `)` goes.
fn normalized(label: &str) -> String {
    let label = match label.find('(') {
        Some(open) => {
            let rest = label[open..]
                .rfind(')')
                .map_or("", |close| &label[open + close + 1..]);
            format!("{}{rest}", &label[..open])
        }
        None => label.to_owned(),
    };
    let mut unquoted = String::new();
    let mut quote = None;
    for c in label.chars() {
        match quote {
            Some(open) if c == open => quote = None,
            Some(_) => {}
            None if matches!(c, '"' | '`' | '\'') => quote = Some(c),
            None => unquoted.push(c),
        }
    }
    unquoted
        .split_whitespace()
        .map(|word| {
            if word.len() > 16 && word.bytes().all(|b| b.is_ascii_alphanumeric()) {
                "#".to_owned()
            } else {
                word.chars().filter(|c| !c.is_ascii_digit()).collect()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(96)
        .collect()
}

fn hex_digest(input: &[u8]) -> String {
    hex::encode(&Sha256::digest(input)[..8])
}

fn artifacts() -> PathBuf {
    std::env::var_os("HASHSTASH_FUZZ_ARTIFACTS")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("hashstash-fuzz-artifacts"))
}

/// Stop with everything needed to reproduce and keep a failing input.
fn failed(target: &Target, seed: u64, iteration: u64, input: &[u8], message: &str) -> ! {
    let directory = artifacts();
    let path = directory.join(format!("{}-{}.hex", target.name, hex_digest(input)));
    let saved = std::fs::create_dir_all(&directory)
        .and_then(|()| std::fs::write(&path, hex::encode(input)))
        .map_or_else(
            |error| format!("not saved: {error}"),
            |()| path.display().to_string(),
        );
    let shown = hex::encode(&input[..input.len().min(2048)]);
    panic!(
        "fuzz target {} failed on input {} (seed {seed:#x}, iteration {iteration}): {message}\n\
         input ({} bytes) saved to {saved}; keep it under fuzz/regressions/{}/ once fixed\n\
         input hex (first 2048 bytes): {shown}",
        target.name,
        hex_digest(input),
        input.len(),
        target.name
    );
}

fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|message| (*message).to_owned())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "non-string panic".into())
}

/// Run one input; `Err` carries a panic message or a hang.
fn execute(
    target: &Target,
    node: Option<&Node>,
    input: &[u8],
) -> Result<(String, Duration), String> {
    let started = Instant::now();
    let label = catch_unwind(AssertUnwindSafe(|| match target.run {
        Run::Bytes(run) => run(input),
        Run::Node(run) => run(node.expect("node target without fixture"), input),
    }))
    .map_err(|payload| panic_message(&*payload))?;
    let elapsed = started.elapsed();
    if elapsed > HANG {
        return Err(format!("one input took {elapsed:?}"));
    }
    Ok((label, elapsed))
}

/// Seeds from the target and its kept regressions, then the target's inputs
/// in the libFuzzer corpus directory `local`, if given. Only the long runs
/// read one: a corpus is local and untracked, so the ordinary suite starts
/// from tracked inputs alone.
fn initial_corpus(target: &Target, node: Option<&Node>, local: Option<&Path>) -> Vec<Vec<u8>> {
    let mut corpus = (target.seeds)(node);
    corpus.extend(regressions(target.name).into_iter().map(|(_, input)| input));
    if let Some(local) = local {
        corpus.extend(raw_files(&local.join(target.name)));
    }
    corpus
}

/// The libFuzzer corpus directory: HASHSTASH_FUZZ_CORPUS, as for
/// `write_seed_corpus`, or cargo-fuzz's `fuzz/corpus`.
fn libfuzzer_corpus() -> PathBuf {
    std::env::var_os("HASHSTASH_FUZZ_CORPUS").map_or_else(
        || Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/corpus"),
        PathBuf::from,
    )
}

fn raw_files(directory: &Path) -> Vec<Vec<u8>> {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = entries.flatten().map(|entry| entry.path()).collect();
    files.sort();
    files
        .into_iter()
        .filter_map(|path| std::fs::read(path).ok())
        .collect()
}

/// Kept failing inputs: hexadecimal files, `#` comment lines allowed.
fn regressions(name: &str) -> Vec<(PathBuf, Vec<u8>)> {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fuzz/regressions")
        .join(name);
    let Ok(entries) = std::fs::read_dir(&directory) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "hex"))
        .collect();
    files.sort();
    files
        .into_iter()
        .map(|path| {
            let text = std::fs::read_to_string(&path).unwrap();
            let digits: String = text
                .lines()
                .filter(|line| !line.trim_start().starts_with('#'))
                .flat_map(|line| line.chars().filter(|c| !c.is_whitespace()))
                .collect();
            let input =
                hex::decode(&digits).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
            (path, input)
        })
        .collect()
}

struct Summary {
    inputs: u64,
    corpus: usize,
    labels: usize,
    slowest: Duration,
}

/// Mutate from the starting corpus until `inputs` have run or `until` has passed.
fn fuzz(
    target: &Target,
    node: Option<&Node>,
    seed: u64,
    inputs: u64,
    until: Option<Instant>,
    local: Option<&Path>,
) -> Summary {
    let mut rng =
        Rng(seed ^ u64::from_le_bytes(Sha256::digest(target.name)[..8].try_into().unwrap()));
    let mut corpus = Vec::new();
    let mut labels = HashSet::new();
    let mut slowest = Duration::ZERO;
    // Printing each new outcome shows what a target's feedback distinguishes,
    // and what its seeds reach.
    let verbose = std::env::var_os("HASHSTASH_FUZZ_VERBOSE").is_some();
    for input in initial_corpus(target, node, local) {
        match execute(target, node, &input) {
            Ok((label, elapsed)) => {
                slowest = slowest.max(elapsed);
                if verbose {
                    eprintln!("{} seed: {label}", target.name);
                }
                labels.insert(normalized(&label));
                corpus.push(input);
            }
            Err(message) => failed(target, seed, 0, &input, &message),
        }
    }
    assert!(!corpus.is_empty(), "{} has no seeds", target.name);
    let mut count = 0;
    while count < inputs && until.is_none_or(|until| Instant::now() < until) {
        count += 1;
        let mut input = corpus[rng.below(corpus.len())].clone();
        mutate(
            &mut rng,
            &mut input,
            &corpus,
            target.dictionary,
            target.max_len,
        );
        match execute(target, node, &input) {
            Ok((label, elapsed)) => {
                slowest = slowest.max(elapsed);
                let label = normalized(&label);
                if verbose && !labels.contains(&label) {
                    eprintln!("{}: {label}", target.name);
                }
                if labels.insert(label) && corpus.len() < MAX_CORPUS {
                    corpus.push(input);
                }
            }
            Err(message) => failed(target, seed, count, &input, &message),
        }
    }
    Summary {
        inputs: count,
        corpus: corpus.len(),
        labels: labels.len(),
        slowest,
    }
}

/// The ordinary suite's fixed, deterministic budget for one target.
fn bounded(name: &str) {
    let target = targets::target(name);
    let directory = tempfile::tempdir().unwrap();
    let node = matches!(target.run, Run::Node(_)).then(|| targets::fixture_node(directory.path()));
    let summary = fuzz(
        target,
        node.as_ref(),
        SEED,
        BUDGET / u64::from(target.cost),
        None,
        None,
    );
    eprintln!(
        "{name}: {} inputs, {} outcomes, corpus {}, slowest {:?}",
        summary.inputs, summary.labels, summary.corpus, summary.slowest
    );
    assert!(summary.labels > 1, "{name} never left its first outcome");
}

#[test]
fn peer_wire() {
    bounded("peer_wire");
}
#[test]
fn codec_transaction() {
    bounded("codec_transaction");
}
#[test]
fn codec_block() {
    bounded("codec_block");
}
#[test]
fn json() {
    bounded("json");
}
#[test]
fn http_request() {
    bounded("http_request");
}
#[test]
fn rpc_params() {
    bounded("rpc_params");
}
#[test]
fn mail_envelope() {
    bounded("mail_envelope");
}
#[test]
fn plain_text() {
    bounded("plain_text");
}
#[test]
fn address() {
    bounded("address");
}
#[test]
fn signed_record() {
    bounded("signed_record");
}
#[test]
fn unsigned_envelope() {
    bounded("unsigned_envelope");
}
#[test]
fn peer_channel() {
    bounded("peer_channel");
}
#[test]
fn address_book() {
    bounded("address_book");
}
#[test]
fn stratum_session() {
    bounded("stratum_session");
}
#[test]
fn peer_sync() {
    bounded("peer_sync");
}
#[test]
fn peer_serve() {
    bounded("peer_serve");
}

/// A node target's seeds in order on one fixture node, as a run starts:
/// each normalized outcome, and the node's held-header counts after it.
fn seed_outcomes(name: &str) -> Vec<(String, (usize, usize, usize))> {
    let target = targets::target(name);
    let directory = tempfile::tempdir().unwrap();
    let node = targets::fixture_node(directory.path());
    (target.seeds)(Some(&node))
        .iter()
        .map(|seed| {
            let (label, _) = execute(target, Some(&node), seed)
                .unwrap_or_else(|message| panic!("a {name} seed failed: {message}"));
            (normalized(&label), node::fuzz::held_headers(&node).unwrap())
        })
        .collect()
}

/// `peer_sync` outcomes name why a header reply ended the header requests
/// first and outside parentheses, so the stable runner keeps inputs that
/// reach different failures of the held-header store; and its seeds hold
/// headers there, so the store's bounds are checked with headers in it (L079).
#[test]
fn peer_sync_seeds_hold_headers_and_name_header_errors() {
    let outcomes = seed_outcomes("peer_sync");
    let errors: HashSet<&str> = outcomes
        .iter()
        .filter_map(|(label, _)| label.split("header error: ").nth(1))
        .filter_map(|rest| rest.split(',').next())
        .filter(|error| *error != "none")
        .collect();
    assert!(
        errors.len() > 1,
        "header errors not told apart: {outcomes:#?}"
    );
    assert!(
        outcomes.iter().any(|(_, (held, _, _))| *held > 0),
        "no seed held a header: {outcomes:#?}"
    );
}

/// `peer_serve` seeds reach each branch of the node's inbound peer handler:
/// header rounds and their limit, a locator request and the push after it,
/// refused locators and chains, address requests, messages out of order,
/// and pushes that move the tip (L079).
#[test]
fn peer_serve_seeds_reach_each_branch_of_the_inbound_handler() {
    let outcomes = seed_outcomes("peer_serve");
    for expected in [
        "served; got several headers, sync: several locators, several blocks",
        "served; got one headers, several headers, sync",
        "served; got no headers, sync",
        "too many header requests",
        "no common ancestor",
        "invalid locator length",
        "different genesis configuration",
        "peer discovery disabled",
        "unexpected first peer message",
        "first peer message must be a locator request",
        "unexpected peer message type",
        "new tip",
    ] {
        assert!(
            outcomes.iter().any(|(label, _)| label.contains(expected)),
            "no seed reached {expected:?}: {outcomes:#?}"
        );
    }
}

/// The ordinary runs start from tracked inputs only, whatever libFuzzer
/// corpus a machine holds; the long runs add the selected corpus.
#[test]
fn only_long_runs_read_a_libfuzzer_corpus() {
    let target = targets::target("json");
    let local = tempfile::tempdir().unwrap();
    std::fs::create_dir(local.path().join(target.name)).unwrap();
    std::fs::write(local.path().join(target.name).join("found"), b"[\"found\"]").unwrap();
    let tracked = initial_corpus(target, None, None);
    let mut expected = (target.seeds)(None);
    expected.extend(regressions(target.name).into_iter().map(|(_, input)| input));
    assert_eq!(tracked, expected);
    let long = initial_corpus(target, None, Some(local.path()));
    assert_eq!(long.len(), tracked.len() + 1);
    assert_eq!(long.last().unwrap(), b"[\"found\"]");
}

/// Each target has its own bounded test above, a cargo-fuzz binary, a
/// manifest entry and a nightly CI job, and every regression directory names
/// a target.
#[test]
fn every_target_has_a_test_and_a_cargo_fuzz_binary() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let source = std::fs::read_to_string(root.join("tests/fuzz_parsers.rs")).unwrap();
    let manifest = std::fs::read_to_string(root.join("fuzz/Cargo.toml")).unwrap();
    let mut names = HashSet::new();
    for target in TARGETS {
        assert!(
            names.insert(target.name),
            "duplicate target {}",
            target.name
        );
        let test = format!("fn {}() {{\n    bounded(\"{}\");", target.name, target.name);
        assert!(
            source.replace("\r\n", "\n").contains(&test),
            "no bounded test for {}",
            target.name
        );
        let binary = root
            .join("fuzz/fuzz_targets")
            .join(format!("{}.rs", target.name));
        let text = std::fs::read_to_string(&binary)
            .unwrap_or_else(|error| panic!("{}: {error}", binary.display()));
        assert!(text.contains(&format!("fuzz_one(\"{}\", data)", target.name)));
        assert!(manifest.contains(&format!("name = \"{}\"", target.name)));
    }
    // The nightly matrix: the first JSON list in the fuzz job's target line.
    let workflow = std::fs::read_to_string(root.join(".github/workflows/ci.yml")).unwrap();
    let matrix = workflow
        .lines()
        .find_map(|line| line.trim().strip_prefix("target: ${{ fromJSON("))
        .and_then(|rest| rest.split('\'').find(|piece| piece.starts_with("[\"")))
        .expect("the fuzz job's nightly matrix");
    let mut nightly: Vec<String> = serde_json::from_str(matrix).unwrap();
    nightly.sort();
    let mut expected: Vec<&str> = names.iter().copied().collect();
    expected.sort();
    assert_eq!(
        nightly, expected,
        "the nightly fuzz matrix lists each target once"
    );
    if let Ok(entries) = std::fs::read_dir(root.join("fuzz/regressions")) {
        for entry in entries.flatten().filter(|entry| entry.path().is_dir()) {
            let name = entry.file_name().into_string().unwrap();
            assert!(
                names.contains(name.as_str()),
                "regressions for unknown target {name}"
            );
        }
    }
}

/// Every kept failing input, on its own, still passes its target.
#[test]
fn kept_regressions_replay_cleanly() {
    let directory = tempfile::tempdir().unwrap();
    let mut node = None;
    let mut replayed = 0;
    for target in TARGETS {
        let kept = regressions(target.name);
        if kept.is_empty() {
            continue;
        }
        if matches!(target.run, Run::Node(_)) && node.is_none() {
            node = Some(targets::fixture_node(directory.path()));
        }
        for (path, input) in kept {
            if let Err(message) = execute(target, node.as_ref(), &input) {
                panic!("{}: {message}", path.display());
            }
            replayed += 1;
        }
    }
    eprintln!("{replayed} kept regressions replayed");
}

/// Found by `rpc_params` (see `fuzz/regressions/rpc_params/`): the quote
/// methods named the default sender by indexing `params`, which panics when
/// a client sends a JSON array or scalar there.
#[test]
fn quote_methods_refuse_parameters_that_are_not_objects() {
    let directory = tempfile::tempdir().unwrap();
    let node = Node::open(
        &directory.path().join("node.sqlite"),
        Config::devnet(),
        crypto::public_key(&[1; 32]).unwrap(),
    )
    .unwrap();
    for method in ["fee_quote", "transfer_quote"] {
        for params in [
            json!([]),
            json!(["sender"]),
            json!("x"),
            json!(1),
            json!(true),
        ] {
            let error = node.rpc(method, params.clone()).unwrap_err();
            assert_eq!(
                error.to_string(),
                "expected quote fields",
                "{method} {params}"
            );
        }
        // Omitted parameters are no fields: the quote then asks for what is
        // missing, starting with the sender it never defaults.
        let error = node.rpc(method, Value::Null).unwrap_err().to_string();
        assert!(error.contains("missing"), "{method}: {error}");
    }
}

/// Found by `stratum_session` (see `fuzz/regressions/stratum_session/`): a
/// `mining.configure` naming serde_json's private RawValue token as an
/// extension was answered with that name as a key, and serde_json, whose
/// `raw_value` feature axum enables, refuses such an object (or, led by a
/// string, reads that string as a document). Miners never need to
/// authorize to send it. Replies now name only keys the node's own JSON
/// accepts, and requests with a reserved key anywhere are refused unread.
#[test]
fn stratum_replies_never_name_keys_serde_json_reserves() {
    const RAW: &str = "$serde_json::private::RawValue";
    let directory = tempfile::tempdir().unwrap();
    let node = targets::fixture_node(directory.path());
    let target = targets::target("stratum_session");
    let session = |input: &[u8]| {
        // The fuzz target's own checks, then the raw session for its replies.
        if let Err(message) = execute(target, Some(&node), input) {
            panic!("{}: {message}", String::from_utf8_lossy(input));
        }
        node::fuzz::stratum_session(&node, input, Some(targets::STRATUM_PASSWORD))
    };
    let replies = |replies: &[u8]| -> Vec<Value> {
        replies
            .split(|&byte| byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| {
                let reply: Value = serde_json::from_slice(line)
                    .unwrap_or_else(|error| panic!("{}: {error}", String::from_utf8_lossy(line)));
                if let Err(error) = hashstash::network_guard::parse_json(line) {
                    panic!("the node refuses its own reply: {error}");
                }
                reply
            })
            .collect()
    };
    let (_, minimized) = regressions("stratum_session")
        .into_iter()
        .find(|(path, _)| path.ends_with("serde-json-reserved-extension-key.hex"))
        .expect("kept regression");
    let line = |request: Value| format!("{request}\n").into_bytes();
    for input in [
        minimized,
        line(json!({"id":4,"method":"mining.configure","params":[[RAW]]})),
        line(json!({"id":4,"method":"mining.configure","params":[["version-rolling",RAW]]})),
        line(json!({"id":4,"method":"mining.configure","params":[["x".repeat(129)]]})),
    ] {
        let answered = replies(&session(&input).replies);
        assert_eq!(answered.len(), 1, "{answered:?}");
        assert_eq!(answered[0]["id"], 4);
        assert_eq!(answered[0]["error"][1], "invalid extension name");
    }
    // Other extension names are still answered under their own names.
    let answered = replies(
        &session(&line(json!({"id":5,"method":"mining.configure","params":[
            ["version-rolling","$other-extension"],{"version-rolling.mask":"1fffe000"}
        ]})))
        .replies,
    );
    assert_eq!(answered[0]["result"]["version-rolling"], true);
    assert_eq!(answered[0]["result"]["$other-extension"], false);
    // A reserved key in a request, wherever it is, closes the session unread:
    // as a later key it would otherwise be echoed back first in the sorted id.
    for request in [
        format!(r#"{{"id":{{"a":1,"{RAW}":2}},"method":"mining.subscribe","params":[]}}"#),
        format!(r#"{{"{RAW}":"{{\"id\":6,\"method\":\"mining.subscribe\"}}"}}"#),
    ] {
        let closed = session(format!("{request}\n").as_bytes());
        assert!(closed.replies.is_empty(), "{request}");
        let ended = closed.ended.unwrap_err().to_string();
        assert!(ended.contains("reserved"), "{request}: {ended}");
    }
}

/// Fuzz every selected target concurrently, each for the chosen time.
#[test]
#[ignore = "long-running; select with --ignored, see the module documentation"]
fn fuzz_for_a_bounded_time() {
    let seconds: u64 = std::env::var("HASHSTASH_FUZZ_SECONDS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(60);
    let seed: u64 = std::env::var("HASHSTASH_FUZZ_SEED")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64
        });
    let selected: Vec<&Target> = match std::env::var("HASHSTASH_FUZZ_TARGETS") {
        Ok(names) => names
            .split(',')
            .map(|name| targets::target(name.trim()))
            .collect(),
        Err(_) => TARGETS.iter().collect(),
    };
    let corpus = libfuzzer_corpus();
    eprintln!(
        "fuzzing {} targets for {seconds} s each, seed {seed}, adding any corpus under {}",
        selected.len(),
        corpus.display()
    );
    let until = Instant::now() + Duration::from_secs(seconds);
    let local = corpus.as_path();
    std::thread::scope(|scope| {
        let runs: Vec<_> = selected
            .iter()
            .map(|&target| {
                scope.spawn(move || {
                    let directory = tempfile::tempdir().unwrap();
                    let node = matches!(target.run, Run::Node(_))
                        .then(|| targets::fixture_node(directory.path()));
                    (
                        target.name,
                        fuzz(
                            target,
                            node.as_ref(),
                            seed,
                            u64::MAX,
                            Some(until),
                            Some(local),
                        ),
                    )
                })
            })
            .collect();
        for run in runs {
            match run.join() {
                Ok((name, summary)) => eprintln!(
                    "{name}: {} inputs, {} outcomes, corpus {}, slowest {:?}",
                    summary.inputs, summary.labels, summary.corpus, summary.slowest
                ),
                Err(payload) => std::panic::resume_unwind(payload),
            }
        }
    });
}

/// Write each target's seeds as raw files for a libFuzzer corpus directory.
#[test]
#[ignore = "writes HASHSTASH_FUZZ_CORPUS/<target>/; see docs/VALIDATION.md"]
fn write_seed_corpus() {
    let output = PathBuf::from(
        std::env::var_os("HASHSTASH_FUZZ_CORPUS").expect("set HASHSTASH_FUZZ_CORPUS"),
    );
    let directory = tempfile::tempdir().unwrap();
    let node = targets::fixture_node(directory.path());
    for target in TARGETS {
        let path = output.join(target.name);
        std::fs::create_dir_all(&path).unwrap();
        let mut seeds = (target.seeds)(Some(&node));
        seeds.extend(regressions(target.name).into_iter().map(|(_, input)| input));
        for input in seeds {
            std::fs::write(path.join(hex_digest(&input)), &input).unwrap();
        }
    }
}

// ---------------------------------------------------------------------------
// Mail envelopes, as the node indexes them and the browser opens them.

/// Edits of the public mail fixture with the node's verdict on each, which
/// `fuzz/js/mail_envelope.cjs` requires the browser's parser to share.
const MAIL_VECTORS: &str = "fuzz/mail-envelope-vectors.json";

fn mail_fixture() -> Vec<u8> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(root.join("tests/fixtures/mail-v2.json")).unwrap();
    let fixture: Value = serde_json::from_str(&text).unwrap();
    hex::decode(fixture["data_hex"].as_str().unwrap()).unwrap()
}

/// Apply `[at, delete, inserted hex]` edits in order.
fn edited(base: &[u8], edits: &Value) -> Vec<u8> {
    let mut bytes = base.to_vec();
    for edit in edits.as_array().unwrap() {
        let at = edit[0].as_u64().unwrap() as usize;
        let delete = edit[1].as_u64().unwrap() as usize;
        let inserted = hex::decode(edit[2].as_str().unwrap()).unwrap();
        bytes.splice(at..at + delete, inserted);
    }
    bytes
}

#[test]
fn mail_envelope_vectors_record_the_node_verdicts() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let vectors: Value =
        serde_json::from_str(&std::fs::read_to_string(root.join(MAIL_VECTORS)).unwrap()).unwrap();
    let base = mail_fixture();
    let mut accepted = 0;
    let vectors = vectors["vectors"].as_array().unwrap();
    for vector in vectors {
        let data = edited(&base, &vector["edits"]);
        let verdict = hashstash::mail::decode(&data).is_some();
        assert_eq!(
            verdict,
            vector["accepted"].as_bool().unwrap(),
            "{}",
            vector["name"]
        );
        accepted += usize::from(verdict);
    }
    assert!(accepted > 1 && accepted < vectors.len());
}

/// Rewrites the vectors from the node's current verdicts. Review the diff:
/// a changed verdict is a change to what counts as mail.
#[test]
#[ignore = "rewrites fuzz/mail-envelope-vectors.json"]
fn write_mail_envelope_vectors() {
    let base = mail_fixture();
    let text = String::from_utf8(base.clone()).unwrap();
    let prefix = hashstash::mail::PREFIX.len();
    let value = |field: &str| text.find(&format!("\"{field}\":\"")).unwrap() + field.len() + 4;
    let replace = |at: usize, delete: usize, with: &[u8]| json!([[at, delete, hex::encode(with)]]);
    let cipher = value("ciphertext");
    let letter = cipher
        + text[cipher..]
            .find(|c: char| c.is_ascii_lowercase())
            .unwrap();
    let digit = cipher + text[cipher..].find(|c: char| c.is_ascii_digit()).unwrap();
    let iv = &text[value("iv")..value("iv") + 24];
    let end = base.len() - 1;
    let mut vectors = vec![
        ("canonical fixture".to_owned(), json!([])),
        (
            "byte-order mark before the prefix".into(),
            replace(0, 0, "\u{feff}".as_bytes()),
        ),
        (
            "byte-order mark after the prefix".into(),
            replace(prefix, 0, "\u{feff}".as_bytes()),
        ),
        ("version 3 prefix".into(), replace(prefix - 2, 1, b"3")),
        (
            "CRLF after the prefix".into(),
            replace(prefix - 1, 0, b"\r"),
        ),
        ("space before the JSON".into(), replace(prefix, 0, b" ")),
        (
            "space after the first colon".into(),
            replace(text.find(':').unwrap() + 1, 0, b" "),
        ),
        ("trailing newline".into(), replace(base.len(), 0, b"\n")),
        ("trailing NUL".into(), replace(base.len(), 0, &[0])),
        ("truncated by one byte".into(), replace(end, 1, b"")),
        (
            "uppercase ciphertext digit".into(),
            replace(
                letter,
                1,
                text[letter..=letter].to_ascii_uppercase().as_bytes(),
            ),
        ),
        (
            "escaped ciphertext digit".into(),
            replace(digit, 1, format!("\\u00{:02x}", base[digit]).as_bytes()),
        ),
        (
            "invalid UTF-8 in the ciphertext".into(),
            replace(digit, 1, &[0xff]),
        ),
        (
            "overlong UTF-8 digit".into(),
            replace(digit, 1, &[0xc0, 0x80 | (base[digit] & 0x3f)]),
        ),
        (
            "ciphertext one byte longer".into(),
            replace(cipher, 0, b"00"),
        ),
        ("iv one byte shorter".into(), replace(value("iv"), 2, b"")),
        (
            "ephemeral key x = 0".into(),
            replace(value("ephemeral_key"), 64, "0".repeat(64).as_bytes()),
        ),
        (
            "ephemeral key x = field prime".into(),
            replace(
                value("ephemeral_key"),
                64,
                b"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
            ),
        ),
        ("extra field".into(), replace(end, 0, br#","extra":"00""#)),
        (
            "duplicate iv field".into(),
            replace(end, 0, format!(",\"iv\":\"{iv}\"").as_bytes()),
        ),
        ("iv and sender iv exchanged".into(), {
            let sender = value("sender_iv");
            let other = &text[sender..sender + 24];
            json!([
                [value("iv"), 24, hex::encode(other)],
                [sender, 24, hex::encode(iv)]
            ])
        }),
    ];
    // Single-byte replacements across the record, mostly in the ciphertext.
    let mut rng = Rng(SEED ^ 2);
    let bytes: &[u8] = b"0123456789abcdefABCDEF\"\\{}[],: \n\x00\x7f\x80\xff";
    for n in 0..96 {
        let at = rng.below(base.len());
        let byte = bytes[rng.below(bytes.len())];
        vectors.push((format!("random byte {n}"), replace(at, 1, &[byte])));
    }
    let vectors: Vec<Value> = vectors
        .into_iter()
        .map(|(name, edits)| {
            let accepted = hashstash::mail::decode(&edited(&base, &edits)).is_some();
            json!({"name": name, "edits": edits, "accepted": accepted})
        })
        .collect();
    let file = json!({
        "format": "hashstash-mail-envelope-vectors-v1",
        "base": "tests/fixtures/mail-v2.json data_hex",
        "edit": "[byte offset, bytes deleted, hexadecimal bytes inserted], applied in order",
        "vectors": vectors,
    });
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut text = serde_json::to_string_pretty(&file).unwrap();
    text.push('\n');
    std::fs::write(root.join(MAIL_VECTORS), text).unwrap();
}

// ---------------------------------------------------------------------------
// The live listeners, through real sockets.

/// Panics on runtime worker threads, where the listeners' session tasks run
/// and where the runtime otherwise turns a panic into a dropped connection.
/// The in-process targets above run on their test threads instead.
static PANICS: AtomicUsize = AtomicUsize::new(0);
fn count_panics() {
    static HOOK: Once = Once::new();
    HOOK.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if std::thread::current()
                .name()
                .is_some_and(|name| name.starts_with("tokio-runtime-worker"))
            {
                PANICS.fetch_add(1, Ordering::SeqCst);
            }
            previous(info);
        }));
    });
}

const DEADLINE: Duration = Duration::from_secs(5);
const RESPONSE_LIMIT: u64 = 4 * 1024 * 1024;
const PASSWORD: &str = "fuzz-fixture-password";

async fn listening() -> (tempfile::TempDir, Node, Server) {
    let directory = tempfile::tempdir().unwrap();
    let mut config = Config::devnet();
    config.initial_bits = 0x1f1fffff;
    config.limit_bits = config.initial_bits;
    let node = Node::open(
        &directory.path().join("node.sqlite"),
        config,
        crypto::public_key(&[101; 32]).unwrap(),
    )
    .unwrap();
    let zero: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let server = node::serve(
        node.clone(),
        ServerOptions {
            rpc: zero,
            p2p: zero,
            stratum: zero,
            peers: vec![],
            stratum_password: Some(PASSWORD.into()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    (directory, node, server)
}

/// One connection per input, each from its own loopback address, so one
/// input's cooldown never refuses the next.
async fn connect(address: SocketAddr, index: usize) -> TcpStream {
    let source = Ipv4Addr::new(127, 20 + (index / 250) as u8, 1 + (index % 250) as u8, 1);
    let socket = TcpSocket::new_v4().unwrap();
    socket.bind(SocketAddr::new(IpAddr::V4(source), 0)).unwrap();
    timeout(DEADLINE, socket.connect(address))
        .await
        .expect("connect timed out")
        .unwrap()
}

fn closed_by_peer(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
    )
}

/// Send everything, end the write side, and read until the node closes.
async fn exchange(address: SocketAddr, index: usize, bytes: &[u8]) -> Vec<u8> {
    let mut stream = connect(address, index).await;
    if let Err(error) = stream.write_all(bytes).await {
        assert!(closed_by_peer(&error), "{error}");
    }
    let _ = stream.shutdown().await;
    let mut reply = Vec::new();
    let read = timeout(
        DEADLINE * 3,
        (&mut stream).take(RESPONSE_LIMIT).read_to_end(&mut reply),
    )
    .await
    .expect("the node never closed a session");
    if let Err(error) = read {
        assert!(closed_by_peer(&error), "{error}");
    }
    assert!(reply.len() < RESPONSE_LIMIT as usize, "unbounded reply");
    reply
}

async fn healthy(server: &Server) -> Value {
    timeout(
        DEADLINE,
        node::call_rpc(&format!("http://{}/rpc", server.rpc), "status", json!({})),
    )
    .await
    .expect("RPC became unresponsive")
    .expect("RPC status failed")
}

fn line(value: &Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(value).unwrap();
    bytes.push(b'\n');
    bytes
}

/// Mutated Stratum requests after a genuine subscribe and authorize, each
/// session on its own connection: replies stay lines of JSON, every session
/// closes, and the node keeps serving RPC without a panicked task.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stratum_sessions_survive_mutated_requests() {
    count_panics();
    let panics = PANICS.load(Ordering::SeqCst);
    let (_directory, _node, server) = listening().await;
    // One genuine job supplies the identifiers a valid submission names.
    let stream = connect(server.stratum, 0).await;
    let (read, mut write) = stream.into_split();
    let mut read = BufReader::new(read);
    let mut handshake = line(&json!({"id":1,"method":"mining.subscribe","params":["fuzz/1"]}));
    handshake.extend(line(
        &json!({"id":2,"method":"mining.authorize","params":["fuzz.worker",PASSWORD]}),
    ));
    write.write_all(&handshake).await.unwrap();
    let mut job = Value::Null;
    while job.is_null() {
        let mut text = String::new();
        timeout(DEADLINE, read.read_line(&mut text))
            .await
            .unwrap()
            .unwrap();
        let value: Value = serde_json::from_str(&text).unwrap();
        if value["method"] == "mining.notify" {
            job = value["params"].clone();
        }
    }
    drop((read, write));
    let requests = [
        json!({"id":3,"method":"mining.configure","params":[["version-rolling"],{"version-rolling.mask":"1fffe000","version-rolling.min-bit-count":2}]}),
        json!({"id":4,"method":"mining.extranonce.subscribe","params":[]}),
        json!({"id":5,"method":"mining.suggest_difficulty","params":[0.5]}),
        json!({"id":6,"method":"mining.submit","params":["fuzz.worker",job[0],"00000001",job[7],"0000abcd"]}),
        json!({"id":7,"method":"mining.submit","params":["fuzz.worker",job[0],"00000002",job[7],"00000000","00002000"]}),
        json!({"id":8,"method":"mining.authorize","params":["other.worker","wrong"]}),
        json!({"id":9,"method":"unknown.method","params":{}}),
    ];
    let corpus: Vec<Vec<u8>> = requests.iter().map(line).collect();
    let mut rng = Rng(SEED);
    let sessions = if cfg!(debug_assertions) { 24 } else { 160 };
    for index in 1..=sessions {
        let mut session = handshake.clone();
        for _ in 0..1 + rng.below(6) {
            let mut request = corpus[rng.below(corpus.len())].clone();
            mutate(&mut rng, &mut request, &corpus, targets::JSON_TOKENS, 4096);
            session.extend(request);
            if rng.below(4) != 0 {
                session.push(b'\n');
            }
        }
        let reply = exchange(server.stratum, index, &session).await;
        for reply in reply
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            assert!(
                serde_json::from_slice::<Value>(reply).is_ok(),
                "session {index}: a reply is not JSON: {}",
                String::from_utf8_lossy(reply)
            );
        }
        if index % 16 == 0 {
            healthy(&server).await;
        }
    }
    healthy(&server).await;
    assert_eq!(PANICS.load(Ordering::SeqCst), panics, "a session panicked");
    server.stop().await;
}

/// Mutated HTTP requests to the private listener, built from the JSON-RPC
/// seeds, browser assets and wallet endpoints: half mutate the whole request,
/// half only the body with a corrected length. Every reply is HTTP, every
/// session closes and no session panics.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_sessions_survive_mutated_requests() {
    count_panics();
    let panics = PANICS.load(Ordering::SeqCst);
    let (directory, node, server) = listening().await;
    let host = server.rpc;
    let fixture = tempfile::tempdir_in(directory.path()).unwrap();
    let rpc_node = targets::fixture_node(fixture.path());
    let target = targets::target("rpc_params");
    let mut bodies: Vec<Vec<u8>> = (target.seeds)(Some(&rpc_node))
        .into_iter()
        .filter(|seed| seed[0] & 0x80 == 0)
        .map(|seed| {
            let method = targets::rpc_method(seed[0]);
            let params: Value = serde_json::from_slice(&seed[1..]).unwrap();
            serde_json::to_vec(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
                .unwrap()
        })
        .collect();
    bodies.push(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"fee_quote\",\"params\":[]}".to_vec());
    drop(rpc_node);
    let request = |path: &str, extra: &str, body: &[u8]| -> Vec<u8> {
        let mut bytes = format!(
            "POST {path} HTTP/1.1\r\nHost: {host}\r\nOrigin: http://{host}\r\nContent-Type: application/json\r\n{extra}Content-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        bytes.extend_from_slice(body);
        bytes
    };
    let mut corpus: Vec<Vec<u8>> = bodies
        .iter()
        .map(|body| request("/rpc", "", body))
        .collect();
    for path in ["/", "/app.js", "/api/session", "/style.css", "/missing"] {
        corpus.push(
            format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nSec-Fetch-Site: same-origin\r\n\r\n")
                .into_bytes(),
        );
    }
    corpus.push(request(
        "/api/wallet",
        "X-Hashstash-Token: guessed\r\n",
        b"{}",
    ));
    corpus.push(request(
        "/api/wallet/manage",
        "",
        b"{\"action\":\"status\"}",
    ));
    let mut rng = Rng(SEED ^ 1);
    let requests = if cfg!(debug_assertions) { 60 } else { 480 };
    for index in 1..=requests {
        let wire = if rng.below(2) == 0 {
            let mut wire = corpus[rng.below(corpus.len())].clone();
            mutate(
                &mut rng,
                &mut wire,
                &corpus,
                targets::HTTP_TOKENS,
                32 * 1024,
            );
            wire
        } else {
            let mut body = bodies[rng.below(bodies.len())].clone();
            mutate(&mut rng, &mut body, &bodies, targets::RPC_TOKENS, 16 * 1024);
            request("/rpc", "", &body)
        };
        let reply = exchange(server.rpc, 1000 + index, &wire).await;
        assert!(
            reply.is_empty() || reply.starts_with(b"HTTP/1.1 "),
            "request {index}: not an HTTP reply: {}",
            String::from_utf8_lossy(&reply[..reply.len().min(256)])
        );
        if index % 32 == 0 {
            healthy(&server).await;
        }
    }
    let status = healthy(&server).await;
    assert_eq!(status["chain_id"], node.status().unwrap()["chain_id"]);
    assert_eq!(PANICS.load(Ordering::SeqCst), panics, "a session panicked");
    server.stop().await;
}
