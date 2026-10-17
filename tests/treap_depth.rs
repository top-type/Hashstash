//! Regression for audit finding F007. Treap priorities are public hashes of
//! keys, and many keys are chosen by users, so one path can be ground as deep
//! as an attacker pays for. Every tree operation must walk such a path without
//! recursing per level: a stack overflow aborts the whole node process.
//!
//! The commitments of the reworked operations are pinned against the original
//! recursive implementation.
use hashstash::{codec, crypto, tree::Map};
use std::sync::OnceLock;

/// Spine depth. The recursive implementation needs far more than `STACK`.
const DEPTH: usize = 3_000;
/// A deliberately small worker stack, well below Tokio's 2 MiB default.
const STACK: usize = 128 * 1024;

struct Keys {
    /// Lowest priority: the root.
    root: Vec<u8>,
    /// Ascending keys with ascending priorities below the root: a right spine.
    spine: Vec<Vec<u8>>,
    /// Highest priority, ordered after the root: the root's right child.
    last: Vec<u8>,
}

/// Grinds a `prefix || counter` key whose priority lies in one of `bands`
/// equal, disjoint bands of the leading 64 priority bits.
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

/// Descending key order puts every new spine key at the root, so building
/// costs one copy per key; the root key then splits the whole spine.
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

#[test]
fn adversarial_depth_operations_run_on_a_small_stack() {
    let k = keys();
    std::thread::Builder::new()
        .name("small-stack".into())
        .stack_size(STACK)
        .spawn(move || {
            let original = build(k, true);
            let deepest = k.spine.last().unwrap();
            assert_eq!(original.len(), DEPTH + 2);
            assert_eq!(original.proof(deepest).unwrap().path.len(), DEPTH);
            let canonical = original.root();

            // Update, remove and reinsert the deepest key.
            let mut map = original.clone();
            map.insert(deepest.clone(), 7);
            assert_ne!(map.root(), canonical);
            assert_eq!(map.remove(deepest), Some(7));
            assert_eq!(map.remove(deepest), None);
            map.insert(deepest.clone(), DEPTH as u64);
            assert_eq!(map.root(), canonical);

            // Removing the root merges the whole spine with its right subtree;
            // reinserting it splits the spine again.
            assert_eq!(map.remove(&k.root), Some(u64::MAX));
            let without_root = build(k, false);
            assert_eq!(map.root(), without_root.root());
            assert_eq!(map, without_root);
            map.insert(k.root.clone(), u64::MAX);
            assert_eq!(map.root(), canonical);

            // Snapshots restore, compare and format the same shape.
            let bytes = codec::encode(&original);
            let restored: Map<u64> = codec::decode(&bytes, bytes.len()).unwrap();
            assert_eq!(restored.root(), canonical);
            assert_eq!(restored, original);
            assert_eq!(restored.proof(deepest).unwrap().path.len(), DEPTH);
            assert!(format!("{restored:?}").len() > DEPTH);

            // Dropping uniquely owned versions frees whole deep paths.
            drop((map, without_root, restored));
            let mut last = original;
            for key in &k.spine {
                last.remove(key);
            }
            assert_eq!(last.len(), 2);
        })
        .unwrap()
        .join()
        .expect("deep tree operations failed");
}

#[test]
fn reworked_operations_keep_original_commitments() {
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
            "6cb7cc0acfa7dee8cf9df7380db885edbfae3d3791c650e2c9084bae2d57b33c",
            "1c8baa62454c4c58f5a2eff559b2cc985268d1a6b386731ebe35415aa0628eb6",
            "193f19b554be549d26d5c3ce786db33ab5a435ef5870d415f08b8306c8075908",
        ]
    );
}
