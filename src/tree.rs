//! Persistent authenticated ordered map.
//!
//! The binary-search shape is the unique Cartesian tree of `(SHA256-tagged(key),
//! key)` priorities. Thus insertion order and snapshot restoration cannot change
//! the root. Nodes are immutable, reference counted, and cache their commitment.
//! Cloning is constant time; updates copy an expected logarithmic search path.

use crate::{codec, crypto, types::Hash};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de, ser::SerializeSeq};
use std::{fmt, sync::Arc};

type Link<V> = Option<Arc<Node<V>>>;

#[derive(Clone, Debug)]
struct Node<V> {
    key: Vec<u8>,
    value: V,
    value_hash: Hash,
    priority: Hash,
    left: Link<V>,
    right: Link<V>,
    len: usize,
    root: Hash,
}

#[derive(Clone, Debug)]
pub struct Map<V> {
    node: Link<V>,
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

impl<V: Clone> Node<V> {
    fn make(key: Vec<u8>, value: V, value_hash: Hash, left: Link<V>, right: Link<V>) -> Arc<Self> {
        let priority = crypto::tagged_hash("Hashstash/TreePriority", &key);
        Self::with_priority(key, value, value_hash, priority, left, right)
    }

    fn with_priority(
        key: Vec<u8>,
        value: V,
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
}

fn insert<V: Clone + Serialize>(node: &Link<V>, key: Vec<u8>, value: V) -> Arc<Node<V>> {
    let Some(n) = node else {
        let digest = value_hash(&value);
        return Node::make(key, value, digest, None, None);
    };
    match key.cmp(&n.key) {
        std::cmp::Ordering::Equal => {
            let digest = value_hash(&value);
            Node::with_priority(
                key,
                value,
                digest,
                n.priority,
                n.left.clone(),
                n.right.clone(),
            )
        }
        std::cmp::Ordering::Less => {
            let left = insert(&n.left, key, value);
            if left.precedes(n) {
                let right = n.rebuild(left.right.clone(), n.right.clone());
                left.rebuild(left.left.clone(), Some(right))
            } else {
                n.rebuild(Some(left), n.right.clone())
            }
        }
        std::cmp::Ordering::Greater => {
            let right = insert(&n.right, key, value);
            if right.precedes(n) {
                let left = n.rebuild(n.left.clone(), right.left.clone());
                right.rebuild(Some(left), right.right.clone())
            } else {
                n.rebuild(n.left.clone(), Some(right))
            }
        }
    }
}

fn merge<V: Clone>(left: &Link<V>, right: &Link<V>) -> Link<V> {
    match (left, right) {
        (None, _) => right.clone(),
        (_, None) => left.clone(),
        (Some(l), Some(r)) => {
            if l.precedes(r) {
                Some(l.rebuild(l.left.clone(), merge(&l.right, right)))
            } else {
                Some(r.rebuild(merge(left, &r.left), r.right.clone()))
            }
        }
    }
}

fn remove<V: Clone>(node: &Link<V>, key: &[u8]) -> (Link<V>, Option<V>) {
    let Some(n) = node else {
        return (None, None);
    };
    match key.cmp(n.key.as_slice()) {
        std::cmp::Ordering::Equal => (merge(&n.left, &n.right), Some(n.value.clone())),
        std::cmp::Ordering::Less => {
            let (left, old) = remove(&n.left, key);
            if old.is_some() {
                (Some(n.rebuild(left, n.right.clone())), old)
            } else {
                (node.clone(), None)
            }
        }
        std::cmp::Ordering::Greater => {
            let (right, old) = remove(&n.right, key);
            if old.is_some() {
                (Some(n.rebuild(n.left.clone(), right)), old)
            } else {
                (node.clone(), None)
            }
        }
    }
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
        Some((&n.key, &n.value))
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
        self.node = Some(insert(&self.node, key, value));
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
        Some((&n.key, &n.value))
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
            fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Map<V>, A::Error> {
                let mut map = Map::new();
                let mut previous: Option<Vec<u8>> = None;
                while let Some((key, value)) = seq.next_element::<(Vec<u8>, V)>()? {
                    if previous.as_ref().is_some_and(|last| last >= &key) {
                        return Err(de::Error::custom("map keys must be strictly increasing"));
                    }
                    previous = Some(key.clone());
                    map.insert(key, value);
                }
                Ok(map)
            }
        }
        deserializer.deserialize_seq(Visitor(std::marker::PhantomData))
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
                &value_hash(&n.value),
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
        let json_restored: Map<u64> =
            serde_json::from_str(&serde_json::to_string(&a).unwrap()).unwrap();
        assert_eq!(a.root(), json_restored.root());
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
