//! Regressions for audit findings F007 and R04: the depth of authenticated
//! state maps must not follow chosen keys.
//!
//! The original treap's priorities were public hashes of keys, and many keys
//! are chosen by users, so one path could be ground as deep as an attacker paid
//! for. Recursive operations on it overflowed the stack (F007); iterative ones
//! still copied and rehashed one node per level on every update of that path
//! (R04). The trie over hashed keys bounds depth by 256 and makes every extra
//! level cost about twice the hashing of the one before.
//!
//! Every root pinned here was computed by an independent Python model of the
//! documented commitment (docs/CONSENSUS.md, "State commitments"), not by this
//! implementation.
use hashstash::{codec, crypto, tree::Map};
use std::sync::OnceLock;

/// The F007 ladder length. It made the treap a single path this deep.
const DEPTH: usize = 3_000;
/// A deliberately small worker stack, well below Tokio's 2 MiB default.
const STACK: usize = 128 * 1024;

struct Keys {
    /// Lowest old priority: the treap's root.
    root: Vec<u8>,
    /// Ascending keys with ascending old priorities: the treap's right spine.
    spine: Vec<Vec<u8>>,
    /// Highest old priority, ordered after the root.
    last: Vec<u8>,
}

/// Grinds a `prefix || counter` key whose old treap priority lies in one of
/// `bands` equal, disjoint bands of the leading 64 priority bits.
fn grind(prefix: u8, counter: &mut u64, band: usize, bands: usize) -> Vec<u8> {
    let low = ((band as u128) << 64) / bands as u128;
    let high = ((band as u128 + 1) << 64) / bands as u128;
    loop {
        let mut key = vec![prefix];
        key.extend_from_slice(&counter.to_be_bytes());
        *counter += 1;
        let priority = crypto::tagged_hash("Hashstash/TreePriority", &key);
        let lead = u64::from_be_bytes(priority[..8].try_into().unwrap()) as u128;
        if (low..high).contains(&lead) {
            return key;
        }
    }
}

fn keys() -> &'static Keys {
    static KEYS: OnceLock<Keys> = OnceLock::new();
    KEYS.get_or_init(|| {
        let bands = DEPTH + 2;
        let mut counter = 0;
        Keys {
            root: grind(1, &mut counter, 0, bands),
            spine: (1..=DEPTH)
                .map(|band| grind(0, &mut counter, band, bands))
                .collect(),
            last: grind(2, &mut counter, DEPTH + 1, bands),
        }
    })
}

fn build(k: &Keys, with_root: bool) -> Map<u64> {
    let mut map = Map::new();
    map.insert(k.last.clone(), 0);
    for (i, key) in k.spine.iter().enumerate().rev() {
        map.insert(key.clone(), i as u64 + 1);
    }
    if with_root {
        map.insert(k.root.clone(), u64::MAX);
    }
    map
}

/// A key's depth: the number of trie branches above its leaf.
fn depth(map: &Map<u64>, key: &[u8]) -> usize {
    map.proof(key).unwrap().path.len()
}

fn max_depth<'a>(map: &Map<u64>, keys: impl IntoIterator<Item = &'a Vec<u8>>) -> usize {
    keys.into_iter().map(|k| depth(map, k)).max().unwrap_or(0)
}

/// floor(log2(n)) for n > 0.
fn log2(n: usize) -> usize {
    n.ilog2() as usize
}

#[test]
fn the_f007_ladder_is_shallow_and_runs_on_a_small_stack() {
    let k = keys();
    std::thread::Builder::new()
        .name("small-stack".into())
        .stack_size(STACK)
        .spawn(move || {
            let original = build(k, true);
            let deepest = k.spine.last().unwrap();
            assert_eq!(original.len(), DEPTH + 2);
            // The ladder was one path DEPTH deep in the treap; in the trie it
            // is as shallow as any 3,002 keys: about log2(3002) = 11.
            let all: Vec<_> = original.iter().map(|(key, _)| key.to_vec()).collect();
            let deepest_level = max_depth(&original, &all);
            assert!(
                deepest_level <= log2(all.len()) + 12,
                "trie depth {deepest_level}"
            );
            let canonical = original.root();

            // Update, remove and reinsert the old deepest key.
            let mut map = original.clone();
            map.insert(deepest.clone(), 7);
            assert_ne!(map.root(), canonical);
            assert_eq!(map.remove(deepest), Some(7));
            assert_eq!(map.remove(deepest), None);
            map.insert(deepest.clone(), DEPTH as u64);
            assert_eq!(map.root(), canonical);

            // Removing and reinserting the old root key.
            assert_eq!(map.remove(&k.root), Some(u64::MAX));
            let without_root = build(k, false);
            assert_eq!(map.root(), without_root.root());
            assert_eq!(map, without_root);
            map.insert(k.root.clone(), u64::MAX);
            assert_eq!(map.root(), canonical);

            // Snapshots restore, compare and format the same map.
            let bytes = codec::encode(&original);
            let restored: Map<u64> = codec::decode(&bytes, bytes.len()).unwrap();
            assert_eq!(restored.root(), canonical);
            assert_eq!(restored, original);
            assert_eq!(depth(&restored, deepest), depth(&original, deepest));
            assert!(format!("{restored:?}").len() > DEPTH);

            // Dropping uniquely owned versions frees them.
            drop((map, without_root, restored));
            let mut last = original;
            for key in &k.spine {
                last.remove(key);
            }
            assert_eq!(last.len(), 2);
        })
        .unwrap()
        .join()
        .expect("tree operations failed");
}

/// The best an attacker can do against the trie: grind keys whose paths share
/// ever longer prefixes with a victim's. Each ground key adds at most one
/// branch above the victim, and sharing `s` bits takes about 2^(s+1) tries.
#[test]
fn ground_trie_paths_cost_exponential_work_per_level() {
    const BACKGROUND: u32 = 4096;
    const LEVELS: u32 = 18;
    let path = |key: &[u8]| crypto::tagged_hash("Hashstash/TriePath", key);
    let shared_bits = |a: &[u8; 32], b: &[u8; 32]| {
        a.iter()
            .zip(b)
            .position(|(x, y)| x != y)
            .map_or(256, |i| i * 8 + (a[i] ^ b[i]).leading_zeros() as usize)
    };
    let mut map = Map::new();
    let mut keys: Vec<Vec<u8>> = (0..BACKGROUND).map(|n| n.to_be_bytes().to_vec()).collect();
    for key in &keys {
        map.insert(key.clone(), 1);
    }
    let victim = keys[0].clone();
    let natural = depth(&map, &victim);
    let target = path(&victim);
    let (mut counter, mut hashes) = (0u64, 0u64);
    let mut costs = Vec::new();
    for shared in 0..LEVELS as usize {
        let before = hashes;
        let key = loop {
            let key = [b"ground".as_slice(), &counter.to_be_bytes()].concat();
            counter += 1;
            hashes += 1;
            if shared_bits(&path(&key), &target) == shared {
                break key;
            }
        };
        costs.push(hashes - before);
        map.insert(key.clone(), 2);
        keys.push(key);
        assert!(depth(&map, &victim) <= natural + shared + 1);
    }
    let ground = depth(&map, &victim);
    // Eighteen ground keys bought at most eighteen levels...
    assert!(ground <= natural + LEVELS as usize, "{natural} -> {ground}");
    assert!(ground >= LEVELS as usize);
    // ...for about 2^19 hashes, half of them on the last level alone.
    assert!(hashes >= 1 << (LEVELS - 2), "{hashes} hashes");
    assert!(costs[LEVELS as usize - 1] >= 1 << (LEVELS - 4), "{costs:?}");
    // No key is deeper than the background depth plus the ground levels.
    let deepest = max_depth(&map, &keys);
    assert!(
        deepest <= log2(keys.len()) + 12 + LEVELS as usize,
        "trie depth {deepest}"
    );
    assert!(deepest <= 256);
}

/// Update, lookup, clone and snapshot costs of an account-sized map.
#[test]
#[ignore = "benchmark: run with --ignored --nocapture --test-threads 1"]
fn bench_map_at_100k_entries() {
    use hashstash::types::Account;
    use std::time::Instant;
    const ENTRIES: u64 = 100_000;
    let key = |n: u64| crypto::tagged_hash("bench", &n.to_be_bytes()).to_vec();
    let account = |n: u64| Account {
        ordinary: (n * 1_000_003).into(),
        shares: n.into(),
        nonce: n,
        epoch: 0,
    };
    let started = Instant::now();
    let mut map = Map::new();
    for n in 0..ENTRIES {
        map.insert(key(n), account(n));
    }
    let build = started.elapsed();
    let keys: Vec<_> = (0..ENTRIES).map(key).collect();
    let depths: Vec<usize> = keys
        .iter()
        .map(|k| map.proof(k).unwrap().path.len())
        .collect();
    let mean = depths.iter().sum::<usize>() as f64 / depths.len() as f64;
    let deepest = *depths.iter().max().unwrap();

    let started = Instant::now();
    for (i, k) in keys.iter().enumerate().take(20_000) {
        map.insert(k.clone(), account(i as u64 + 7));
    }
    let update = started.elapsed() / 20_000;
    let started = Instant::now();
    let mut found = 0;
    for k in &keys {
        found += usize::from(map.get(k).is_some());
    }
    let lookup = started.elapsed() / ENTRIES as u32;
    assert_eq!(found, ENTRIES as usize);
    // A state version per transaction: clone, update one account, root.
    let started = Instant::now();
    let mut version = map.clone();
    for (i, k) in keys.iter().enumerate().take(20_000) {
        let mut next = version.clone();
        next.insert(k.clone(), account(i as u64 + 9));
        std::hint::black_box(next.root());
        version = next;
    }
    let versioned = started.elapsed() / 20_000;
    let bytes = codec::encode(&map);
    let started = Instant::now();
    let restored: Map<Account> = codec::decode(&bytes, bytes.len()).unwrap();
    let restore = started.elapsed();
    assert_eq!(restored.root(), map.root());
    println!(
        "\n{ENTRIES} accounts: build {build:?}, depth mean {mean:.1} max {deepest}, \
         update {update:?}, lookup {lookup:?}, clone+update+root {versioned:?}, \
         restore {restore:?} ({} bytes)",
        bytes.len()
    );
}

#[test]
fn trie_roots_match_independent_vectors() {
    let mut ordered = Map::new();
    for n in 0..700u32 {
        ordered.insert(n.to_be_bytes().to_vec(), u64::from(n) * 3);
    }
    let mut removed = ordered.clone();
    for n in (0..700u32).step_by(3) {
        removed.remove(&n.to_be_bytes());
    }
    let roots = [ordered.root(), removed.root(), build(keys(), true).root()];
    assert_eq!(
        roots.map(hex::encode),
        [
            "7272fcf6893bf88d0dca747b9dab9b55cc9f0f2f0b1357a91e7868e4e327ecdc",
            "784e1d7609f31f91f8ed47ce4171381203f1b270df14cf16ab77ba84a27eec6d",
            "3dd5842dff1eb2f72ef8561d745e229c586737b7452de7ccb481a8bb65a404e2",
        ]
    );
}
