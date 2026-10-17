//! Persistent authenticated ordered map.
//!
//! The binary-search shape is the unique Cartesian tree of `(SHA256-tagged(key),
//! key)` priorities. Thus insertion order and snapshot restoration cannot change
//! the root. Nodes are immutable, reference counted, and cache their commitment.
//! Values are shared between versions, so cloning is constant time and an update
//! copies only the nodes of its search path, not the values stored on it.
//!
//! Priorities are public functions of keys, and many keys (account public keys,
//! proposal identifiers) are chosen by users. Depth is therefore logarithmic only
//! in expectation: ground keys can lengthen one path by a level per key. Every
//! operation, including dropping and restoring a map, walks paths with explicit
//! heap worklists, so no depth exhausts a thread stack. Work still follows
//! depth: an update copies and rehashes one node per level of its path, so
//! updates under a ground path cost time linear in its length.

use crate::{codec, crypto, types::Hash};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de, ser::SerializeSeq};
use std::{cmp::Ordering, fmt, sync::Arc};

type Link<V> = Option<Arc<Node<V>>>;

struct Node<V> {
    key: Vec<u8>,
    value: Arc<V>,
    value_hash: Hash,
    priority: Hash,
    left: Link<V>,
    right: Link<V>,
    len: usize,
    root: Hash,
}

impl<V> Drop for Node<V> {
    /// The derived drop would recurse once per level. Detach uniquely owned
    /// descendants first and free them from a worklist; shared subtrees only
    /// lose a reference.
    fn drop(&mut self) {
        let mut pending = Vec::new();
        for link in [self.left.take(), self.right.take()] {
            pending.extend(link.and_then(Arc::into_inner));
        }
        while let Some(mut node) = pending.pop() {
            for link in [node.left.take(), node.right.take()] {
                pending.extend(link.and_then(Arc::into_inner));
            }
        }
    }
}

#[derive(Clone)]
pub struct Map<V> {
    node: Link<V>,
}

impl<V: fmt::Debug> fmt::Debug for Map<V> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_map().entries(self.iter()).finish()
    }
}

fn empty_root() -> Hash {
    crypto::tagged_hash("Hashstash/TreeEmpty", &[])
}

fn root<V>(node: &Link<V>) -> Hash {
    node.as_ref().map_or_else(empty_root, |node| node.root)
}

fn value_hash<V: Serialize>(value: &V) -> Hash {
    crypto::tagged_hash("Hashstash/TreeValue", &codec::encode(value))
}

fn node_hash(key: &[u8], value: &Hash, left: &Hash, right: &Hash) -> Hash {
    crypto::tagged_hash(
        "Hashstash/TreeNode",
        &codec::encode(&(key, value, left, right)),
    )
}

fn key_priority(key: &[u8]) -> Hash {
    crypto::tagged_hash("Hashstash/TreePriority", key)
}

impl<V> Node<V> {
    fn with_priority(
        key: Vec<u8>,
        value: Arc<V>,
        value_hash: Hash,
        priority: Hash,
        left: Link<V>,
        right: Link<V>,
    ) -> Arc<Self> {
        let len = 1 + left.as_ref().map_or(0, |n| n.len) + right.as_ref().map_or(0, |n| n.len);
        let root = node_hash(&key, &value_hash, &root(&left), &root(&right));
        Arc::new(Self {
            key,
            value,
            value_hash,
            priority,
            left,
            right,
            len,
            root,
        })
    }

    fn rebuild(&self, left: Link<V>, right: Link<V>) -> Arc<Self> {
        Self::with_priority(
            self.key.clone(),
            self.value.clone(),
            self.value_hash,
            self.priority,
            left,
            right,
        )
    }

    fn precedes(&self, other: &Self) -> bool {
        (self.priority, &self.key) < (other.priority, &other.key)
    }

    fn child(&self, direction: Direction) -> Option<&Arc<Self>> {
        match direction {
            Direction::Left => self.left.as_ref(),
            Direction::Right => self.right.as_ref(),
        }
    }
}

/// Copies a recorded search path bottom-up. Each ancestor takes the new
/// subtree on the side the search followed and keeps its other child.
fn rebuild_path<V>(path: Vec<(&Node<V>, Direction)>, mut child: Link<V>) -> Link<V> {
    for (n, direction) in path.into_iter().rev() {
        child = Some(match direction {
            Direction::Left => n.rebuild(child, n.right.clone()),
            Direction::Right => n.rebuild(n.left.clone(), child),
        });
    }
    child
}

/// Splits a subtree that does not contain `key` into the parts ordered before
/// and after it. Only the nodes on the key's search path are copied.
fn split<V>(mut next: Option<&Arc<Node<V>>>, key: &[u8]) -> (Link<V>, Link<V>) {
    let (mut before, mut after) = (Vec::new(), Vec::new());
    while let Some(n) = next {
        if n.key.as_slice() < key {
            before.push(n);
            next = n.right.as_ref();
        } else {
            after.push(n);
            next = n.left.as_ref();
        }
    }
    let mut left = None;
    for n in before.into_iter().rev() {
        left = Some(n.rebuild(n.left.clone(), left));
    }
    let mut right = None;
    for n in after.into_iter().rev() {
        right = Some(n.rebuild(right, n.right.clone()));
    }
    (left, right)
}

fn insert<V: Serialize>(node: &Link<V>, key: Vec<u8>, value: V) -> Link<V> {
    let priority = key_priority(&key);
    let digest = value_hash(&value);
    let mut path = Vec::new();
    let mut next = node.as_ref();
    while let Some(n) = next {
        let direction = match key.cmp(&n.key) {
            // An existing key keeps its priority, position and subtrees.
            Ordering::Equal => {
                let updated = Node::with_priority(
                    key,
                    Arc::new(value),
                    digest,
                    n.priority,
                    n.left.clone(),
                    n.right.clone(),
                );
                return rebuild_path(path, Some(updated));
            }
            // A new key that precedes this node roots its subtree.
            _ if (priority, key.as_slice()) < (n.priority, n.key.as_slice()) => break,
            Ordering::Less => Direction::Left,
            Ordering::Greater => Direction::Right,
        };
        path.push((n.as_ref(), direction));
        next = n.child(direction);
    }
    let (left, right) = split(next, &key);
    let node = Node::with_priority(key, Arc::new(value), digest, priority, left, right);
    rebuild_path(path, Some(node))
}

/// Joins two subtrees whose keys are all ordered before and after each other.
fn merge<V>(left: &Link<V>, right: &Link<V>) -> Link<V> {
    let mut path = Vec::new();
    let (mut l, mut r) = (left.as_ref(), right.as_ref());
    let rest = loop {
        match (l, r) {
            (Some(a), Some(b)) if a.precedes(b) => {
                path.push((a.as_ref(), Direction::Right));
                l = a.right.as_ref();
            }
            (Some(_), Some(b)) => {
                path.push((b.as_ref(), Direction::Left));
                r = b.left.as_ref();
            }
            (rest, None) | (None, rest) => break rest.cloned(),
        }
    };
    rebuild_path(path, rest)
}

fn remove<V: Clone>(node: &Link<V>, key: &[u8]) -> (Link<V>, Option<V>) {
    let mut path = Vec::new();
    let mut next = node.as_ref();
    while let Some(n) = next {
        let direction = match key.cmp(n.key.as_slice()) {
            Ordering::Equal => {
                let merged = merge(&n.left, &n.right);
                return (rebuild_path(path, merged), Some((*n.value).clone()));
            }
            Ordering::Less => Direction::Left,
            Ordering::Greater => Direction::Right,
        };
        path.push((n.as_ref(), direction));
        next = n.child(direction);
    }
    (node.clone(), None)
}

impl<V> Default for Map<V> {
    fn default() -> Self {
        Self { node: None }
    }
}

impl<V> Map<V> {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn len(&self) -> usize {
        self.node.as_ref().map_or(0, |n| n.len)
    }
    pub fn is_empty(&self) -> bool {
        self.node.is_none()
    }
    pub fn root(&self) -> Hash {
        root(&self.node)
    }

    pub fn get(&self, key: &[u8]) -> Option<&V> {
        self.get_shared(key).map(|value| &**value)
    }

    /// The stored value itself, for a holder that must outlive this version
    /// without copying it.
    pub fn get_shared(&self, key: &[u8]) -> Option<&Arc<V>> {
        let mut next = self.node.as_deref();
        while let Some(n) = next {
            match key.cmp(n.key.as_slice()) {
                std::cmp::Ordering::Equal => return Some(&n.value),
                std::cmp::Ordering::Less => next = n.left.as_deref(),
                std::cmp::Ordering::Greater => next = n.right.as_deref(),
            }
        }
        None
    }

    pub fn last(&self) -> Option<(&[u8], &V)> {
        let mut n = self.node.as_deref()?;
        while let Some(right) = n.right.as_deref() {
            n = right;
        }
        Some((&n.key, &*n.value))
    }

    pub fn iter(&self) -> Iter<'_, V> {
        let mut it = Iter { stack: Vec::new() };
        it.push_left(self.node.as_deref());
        it
    }

    /// An inclusion proof commits to a value, not to a particular serialization
    /// of an in-memory tree. The caller supplies the independently trusted root.
    pub fn proof(&self, key: &[u8]) -> Option<Proof> {
        let mut path = Vec::new();
        let mut next = self.node.as_deref();
        while let Some(n) = next {
            let direction = match key.cmp(n.key.as_slice()) {
                std::cmp::Ordering::Equal => {
                    return Some(Proof {
                        left: root(&n.left),
                        right: root(&n.right),
                        path,
                    });
                }
                std::cmp::Ordering::Less => Direction::Left,
                std::cmp::Ordering::Greater => Direction::Right,
            };
            let sibling = match direction {
                Direction::Left => root(&n.right),
                Direction::Right => root(&n.left),
            };
            path.push(ProofStep {
                key: n.key.clone(),
                value_hash: n.value_hash,
                sibling,
                direction,
            });
            next = match direction {
                Direction::Left => n.left.as_deref(),
                Direction::Right => n.right.as_deref(),
            };
        }
        None
    }
}

impl<V: Clone + Serialize> Map<V> {
    pub fn insert(&mut self, key: Vec<u8>, value: V) {
        self.node = insert(&self.node, key, value);
    }

    pub fn remove(&mut self, key: &[u8]) -> Option<V> {
        let (node, old) = remove(&self.node, key);
        self.node = node;
        old
    }
}

pub struct Iter<'a, V> {
    stack: Vec<&'a Node<V>>,
}

impl<'a, V> Iter<'a, V> {
    fn push_left(&mut self, mut next: Option<&'a Node<V>>) {
        while let Some(n) = next {
            self.stack.push(n);
            next = n.left.as_deref();
        }
    }
}

impl<'a, V> Iterator for Iter<'a, V> {
    type Item = (&'a [u8], &'a V);
    fn next(&mut self) -> Option<Self::Item> {
        let n = self.stack.pop()?;
        self.push_left(n.right.as_deref());
        Some((&n.key, &*n.value))
    }
}

impl<V: PartialEq> PartialEq for Map<V> {
    fn eq(&self, other: &Self) -> bool {
        self.len() == other.len() && self.iter().eq(other.iter())
    }
}
impl<V: Eq> Eq for Map<V> {}

impl<V: Serialize> Serialize for Map<V> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(self.len()))?;
        for (key, value) in self.iter() {
            seq.serialize_element(&(key, value))?;
        }
        seq.end()
    }
}

impl<'de, V: Clone + Serialize + Deserialize<'de>> Deserialize<'de> for Map<V> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor<V>(std::marker::PhantomData<V>);
        impl<'de, V: Clone + Serialize + Deserialize<'de>> de::Visitor<'de> for Visitor<V> {
            type Value = Map<V>;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("strictly key-ordered map entries")
            }
            /// Sorted entries determine the unique Cartesian tree in one pass:
            /// `spine` holds the right spine, whose right subtrees are still
            /// open, and each node is hashed once, when its subtree closes.
            fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Map<V>, A::Error> {
                let mut spine: Vec<Open<V>> = Vec::new();
                while let Some((key, value)) = seq.next_element::<(Vec<u8>, V)>()? {
                    if spine.last().is_some_and(|last| last.key >= key) {
                        return Err(de::Error::custom("map keys must be strictly increasing"));
                    }
                    let entry = Open {
                        priority: key_priority(&key),
                        value_hash: value_hash(&value),
                        value: Arc::new(value),
                        key,
                        left: None,
                    };
                    let mut left = None;
                    while let Some(top) = spine.pop_if(|top| entry.precedes(top)) {
                        left = Some(top.close(left));
                    }
                    spine.push(Open { left, ..entry });
                }
                let mut node = None;
                while let Some(top) = spine.pop() {
                    node = Some(top.close(node));
                }
                Ok(Map { node })
            }
        }
        deserializer.deserialize_seq(Visitor(std::marker::PhantomData))
    }
}

/// A restored node whose right subtree is not yet known.
struct Open<V> {
    key: Vec<u8>,
    value: Arc<V>,
    value_hash: Hash,
    priority: Hash,
    left: Link<V>,
}

impl<V> Open<V> {
    fn precedes(&self, other: &Self) -> bool {
        (self.priority, &self.key) < (other.priority, &other.key)
    }

    fn close(self, right: Link<V>) -> Arc<Node<V>> {
        Node::with_priority(
            self.key,
            self.value,
            self.value_hash,
            self.priority,
            self.left,
            right,
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    Left,
    Right,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofStep {
    pub key: Vec<u8>,
    pub value_hash: Hash,
    pub sibling: Hash,
    pub direction: Direction,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proof {
    pub left: Hash,
    pub right: Hash,
    /// Root-to-leaf ancestors; the matching node itself is represented above.
    pub path: Vec<ProofStep>,
}

impl Proof {
    pub fn verify<V: Serialize>(&self, key: &[u8], value: &V, expected_root: &Hash) -> bool {
        let mut digest = node_hash(key, &value_hash(value), &self.left, &self.right);
        for step in self.path.iter().rev() {
            let (left, right) = match step.direction {
                Direction::Left if key < step.key.as_slice() => (digest, step.sibling),
                Direction::Right if key > step.key.as_slice() => (step.sibling, digest),
                _ => return false,
            };
            digest = node_hash(&step.key, &step.value_hash, &left, &right);
        }
        digest == *expected_root
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn key(n: u32) -> Vec<u8> {
        n.to_be_bytes().to_vec()
    }

    fn populated(order: impl IntoIterator<Item = u32>) -> Map<u64> {
        let mut map = Map::new();
        for n in order {
            map.insert(key(n), n as u64 * 3);
        }
        map
    }

    fn check_node(n: &Link<u64>, low: Option<&[u8]>, high: Option<&[u8]>) -> usize {
        let Some(n) = n else {
            return 0;
        };
        assert!(low.is_none_or(|k| k < n.key.as_slice()));
        assert!(high.is_none_or(|k| k > n.key.as_slice()));
        assert_eq!(
            n.priority,
            crypto::tagged_hash("Hashstash/TreePriority", &n.key)
        );
        for child in [&n.left, &n.right].into_iter().flatten() {
            assert!(n.precedes(child));
        }
        let count =
            1 + check_node(&n.left, low, Some(&n.key)) + check_node(&n.right, Some(&n.key), high);
        assert_eq!(count, n.len);
        assert_eq!(
            n.root,
            node_hash(
                &n.key,
                &value_hash(&*n.value),
                &root(&n.left),
                &root(&n.right)
            )
        );
        count
    }

    #[test]
    fn ordered_iteration_and_updates_match_btree() {
        let mut map = Map::new();
        let mut reference = BTreeMap::new();
        let mut random = 17u64;
        for i in 0..4000 {
            random = random.wrapping_mul(6364136223846793005).wrapping_add(1);
            let k = key((random >> 32) as u32 % 511);
            if random & 3 == 0 {
                assert_eq!(map.remove(&k), reference.remove(&k));
            } else {
                map.insert(k.clone(), i);
                reference.insert(k, i);
            }
        }
        assert_eq!(map.len(), reference.len());
        assert_eq!(
            map.iter()
                .map(|(k, v)| (k.to_vec(), *v))
                .collect::<Vec<_>>(),
            reference.into_iter().collect::<Vec<_>>()
        );
        check_node(&map.node, None, None);
        assert_eq!(map.last(), map.iter().last());
    }

    #[test]
    fn insertion_order_and_snapshot_preserve_root() {
        let a = populated(0..700);
        let b = populated((0..700).rev());
        let c = populated((0..700).map(|i| (i * 131) % 700));
        assert_eq!(a.root(), b.root());
        assert_eq!(a.root(), c.root());
        let restored: Map<u64> = codec::decode(&codec::encode(&a), 1_000_000).unwrap();
        assert_eq!(a.root(), restored.root());
        assert_eq!(a, restored);
        check_node(&restored.node, None, None);
        let json_restored: Map<u64> =
            serde_json::from_str(&serde_json::to_string(&a).unwrap()).unwrap();
        assert_eq!(a.root(), json_restored.root());
        for n in [0, 1, 2, 3, 17] {
            let small = populated(0..n);
            let restored: Map<u64> = codec::decode(&codec::encode(&small), 1000).unwrap();
            assert_eq!(small.root(), restored.root());
            check_node(&restored.node, None, None);
        }
    }

    #[test]
    fn path_copies_share_stored_values() {
        let original = populated(0..200);
        let root_key = original.node.as_ref().unwrap().key.clone();
        let mut next = original.clone();
        // Key 87 is not the root, so this update copies the root node.
        assert_ne!(root_key, key(87));
        next.insert(key(87), 999);
        let (old_root, new_root) = (original.node.as_ref(), next.node.as_ref());
        assert!(!Arc::ptr_eq(old_root.unwrap(), new_root.unwrap()));
        assert!(Arc::ptr_eq(&old_root.unwrap().value, &new_root.unwrap().value));
        assert!(Arc::ptr_eq(
            original.get_shared(&root_key).unwrap(),
            next.get_shared(&root_key).unwrap()
        ));
        assert_eq!(next.remove(&key(87)), Some(999));
        assert!(std::ptr::eq(
            original.get(&root_key).unwrap(),
            next.get(&root_key).unwrap()
        ));
        assert_eq!(
            format!("{:?}", populated(1..3)),
            "{[0, 0, 0, 1]: 3, [0, 0, 0, 2]: 6}"
        );
    }

    #[test]
    fn changes_are_persistent_and_removal_restores_canonical_root() {
        let original = populated(0..200);
        let mut next = original.clone();
        assert!(Arc::ptr_eq(
            original.node.as_ref().unwrap(),
            next.node.as_ref().unwrap()
        ));
        let old_root = original.root();
        next.insert(key(87), 999);
        assert_eq!(original.get(&key(87)), Some(&261));
        assert_eq!(next.get(&key(87)), Some(&999));
        assert_eq!(next.remove(&key(87)), Some(999));
        let rebuilt = populated((0..200).filter(|n| *n != 87));
        assert_eq!(next.root(), rebuilt.root());
        next.insert(key(87), 261);
        assert_eq!(next.root(), old_root);
        assert_eq!(original.root(), old_root);
        for n in 0..200 {
            next.remove(&key(n));
        }
        assert!(next.is_empty());
        assert_eq!(next.root(), Map::<u64>::new().root());
        assert_eq!(next.remove(&key(7)), None);
        assert_eq!(next.last(), None);
    }

    #[test]
    fn membership_proofs_detect_modified_values_paths_and_roots() {
        let map = populated(0..200);
        for n in 0..200 {
            let proof = map.proof(&key(n)).unwrap();
            assert!(proof.verify(&key(n), &(n as u64 * 3), &map.root()));
            assert!(!proof.verify(&key(n), &(n as u64 * 3 + 1), &map.root()));
            assert!(!proof.verify(&key(n + 1), &(n as u64 * 3), &map.root()));
            assert!(!proof.verify(&key(n), &(n as u64 * 3), &[0; 32]));
            let mut modified = proof.clone();
            modified.left[0] ^= 1;
            assert!(!modified.verify(&key(n), &(n as u64 * 3), &map.root()));
            if !proof.path.is_empty() {
                let mut modified = proof;
                modified.path[0].sibling[0] ^= 1;
                assert!(!modified.verify(&key(n), &(n as u64 * 3), &map.root()));
            }
        }
        assert!(map.proof(&key(500)).is_none());
    }

    #[test]
    fn snapshots_reject_duplicate_or_unsorted_keys() {
        for entries in [
            vec![(key(2), 4u64), (key(2), 9)],
            vec![(key(2), 4), (key(1), 9)],
        ] {
            let bytes = codec::encode(&entries);
            assert!(codec::decode::<Map<u64>>(&bytes, 1000).is_err());
            assert!(
                serde_json::from_str::<Map<u64>>(&serde_json::to_string(&entries).unwrap())
                    .is_err()
            );
        }
    }
}
