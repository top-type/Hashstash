//! Persistent authenticated ordered map.
//!
//! The commitment is a binary Patricia trie over hashed keys: each key's path
//! is `tagged_hash("Hashstash/TriePath", key)`, a lone entry is a leaf, and a
//! branch records the first path bit in which its two subtrees differ. The
//! trie of a key set is unique, so insertion order, removals and snapshot
//! restoration cannot change the root. A branch tests a later bit than its
//! parent, so no entry lies under more than 256 branches. Paths are hashes, so
//! chosen keys cannot cheaply deepen one: sharing L more leading path bits
//! with an existing key costs about 2^L hash evaluations.
//!
//! Hashed paths have no useful order, so lookups and key-ordered access use a
//! separate, uncommitted index of the same entries: a weight-balanced search
//! tree over key bytes, whose height is logarithmic in the number of entries
//! for any keys and insertion order. Its shape depends on history, but no
//! result does.
//!
//! Entries and nodes are immutable and reference counted, and each entry is
//! shared by both structures. Cloning is constant time and an update copies
//! one path in each, never the values stored on it. Walks use explicit
//! worklists; the only recursion is bounded by those heights.

use crate::{codec, crypto, types::Hash};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de, ser::SerializeSeq};
use std::{cmp::Ordering, fmt, sync::Arc};

/// One stored entry, shared by the trie and index of every version holding it.
struct Entry<V> {
    key: Vec<u8>,
    value: Arc<V>,
    /// The entry's position in the trie.
    path: Hash,
    /// The leaf commitment.
    hash: Hash,
}

impl<V: Serialize> Entry<V> {
    fn new(key: Vec<u8>, value: Arc<V>) -> Arc<Self> {
        Arc::new(Self {
            path: key_path(&key),
            hash: leaf_hash(&key, &*value),
            key,
            value,
        })
    }
}

fn empty_root() -> Hash {
    crypto::tagged_hash("Hashstash/TrieEmpty", &[])
}

fn key_path(key: &[u8]) -> Hash {
    crypto::tagged_hash("Hashstash/TriePath", key)
}

fn leaf_hash<V: Serialize>(key: &[u8], value: &V) -> Hash {
    crypto::tagged_hash("Hashstash/TrieLeaf", &codec::encode(&(key, value)))
}

fn branch_hash(bit: u8, left: &Hash, right: &Hash) -> Hash {
    let mut bytes = [0; 65];
    bytes[0] = bit;
    bytes[1..33].copy_from_slice(left);
    bytes[33..].copy_from_slice(right);
    crypto::tagged_hash("Hashstash/TrieBranch", &bytes)
}

/// Bit `index` of a path, most significant bit of the first byte first: the
/// child (0 or 1) that holds the path below a branch at that bit.
fn side(path: &Hash, index: u8) -> usize {
    usize::from(path[usize::from(index / 8)] >> (7 - index % 8) & 1)
}

/// The first bit in which two paths differ; `None` when they are equal.
fn first_difference(a: &Hash, b: &Hash) -> Option<u8> {
    a.iter().zip(b).enumerate().find_map(|(i, (x, y))| {
        let differ = x ^ y;
        if differ == 0 {
            return None;
        }
        // i < 32 and a nonzero byte has at most seven leading zeros, so the
        // bit fits a byte.
        Some((i * 8) as u8 + differ.leading_zeros() as u8)
    })
}

/// A committed subtree.
enum Trie<V> {
    Leaf(Arc<Entry<V>>),
    Branch(Arc<Branch<V>>),
}

impl<V> Clone for Trie<V> {
    fn clone(&self) -> Self {
        match self {
            Self::Leaf(entry) => Self::Leaf(entry.clone()),
            Self::Branch(branch) => Self::Branch(branch.clone()),
        }
    }
}

struct Branch<V> {
    /// The first path bit in which the two subtrees differ. Every path below
    /// `children[0]` has a zero there, every path below `children[1]` a one,
    /// and all of them share the bits before it.
    bit: u8,
    children: [Trie<V>; 2],
    hash: Hash,
}

impl<V> Trie<V> {
    fn hash(&self) -> Hash {
        match self {
            Self::Leaf(entry) => entry.hash,
            Self::Branch(branch) => branch.hash,
        }
    }

    fn branch(bit: u8, children: [Self; 2]) -> Self {
        let hash = branch_hash(bit, &children[0].hash(), &children[1].hash());
        Self::Branch(Arc::new(Branch {
            bit,
            children,
            hash,
        }))
    }
}

/// Copies a recorded trie path bottom-up. Each branch takes the new subtree
/// on the side the path followed and keeps its other child.
fn rebuild_trie<V>(path: Vec<(&Branch<V>, usize)>, mut child: Trie<V>) -> Trie<V> {
    for (branch, side) in path.into_iter().rev() {
        let other = branch.children[1 - side].clone();
        let children = if side == 0 {
            [child, other]
        } else {
            [other, child]
        };
        child = Trie::branch(branch.bit, children);
    }
    child
}

fn trie_insert<V>(root: Option<&Trie<V>>, entry: Arc<Entry<V>>) -> Trie<V> {
    let Some(root) = root else {
        return Trie::Leaf(entry);
    };
    // Following the new path ends at the entry whose path shares the longest
    // prefix with it, so their first difference is where the new leaf joins.
    let mut next = root;
    let nearest = loop {
        match next {
            Trie::Leaf(leaf) => break leaf,
            Trie::Branch(b) => next = &b.children[side(&entry.path, b.bit)],
        }
    };
    let split = first_difference(&entry.path, &nearest.path);
    // Every branch above the split bit is shared with that entry. No branch on
    // this route tests the split bit itself: `nearest` would differ there.
    let mut path = Vec::new();
    let mut next = root;
    while let Trie::Branch(b) = next
        && split.is_none_or(|bit| b.bit < bit)
    {
        let side = side(&entry.path, b.bit);
        path.push((b.as_ref(), side));
        next = &b.children[side];
    }
    let child = match split {
        // The same path, so (short of a SHA-256 collision) the same key:
        // replace its leaf.
        None => Trie::Leaf(entry),
        Some(bit) => {
            let side = side(&entry.path, bit);
            let mut children = [next.clone(), Trie::Leaf(entry)];
            if side == 0 {
                children.swap(0, 1);
            }
            Trie::branch(bit, children)
        }
    };
    rebuild_trie(path, child)
}

/// The trie without `entry`, which it holds; `None` once it is empty. The
/// leaf's parent branch is replaced by the leaf's sibling.
fn trie_remove<V>(root: &Trie<V>, entry: &Entry<V>) -> Option<Trie<V>> {
    let mut path = Vec::new();
    let mut next = root;
    let leaf = loop {
        match next {
            Trie::Leaf(leaf) => break leaf,
            Trie::Branch(b) => {
                let side = side(&entry.path, b.bit);
                path.push((b.as_ref(), side));
                next = &b.children[side];
            }
        }
    };
    if leaf.key != entry.key {
        // Unreachable without a SHA-256 collision between the two keys' paths.
        return Some(root.clone());
    }
    let (parent, side) = path.pop()?;
    Some(rebuild_trie(path, parent.children[1 - side].clone()))
}

/// Builds the trie of entries in one pass, hashing each branch once. `None`
/// when two paths are equal, which needs a SHA-256 collision.
fn build_trie<V>(mut entries: Vec<Arc<Entry<V>>>) -> Option<Option<Trie<V>>> {
    entries.sort_unstable_by(|a, b| a.path.cmp(&b.path));
    let mut entries = entries.into_iter();
    let Some(first) = entries.next() else {
        return Some(None);
    };
    // `open` holds the branches on the right edge, whose right subtrees are
    // still growing, with ascending bits; `current` is the newest subtree.
    let mut open: Vec<(u8, Trie<V>)> = Vec::new();
    let mut previous = first.path;
    let mut current = Trie::Leaf(first);
    for entry in entries {
        // Sorted paths: the previous one has a zero at `bit`, this one a one.
        let bit = first_difference(&previous, &entry.path)?;
        while let Some((open_bit, left)) = open.pop_if(|(open_bit, _)| *open_bit > bit) {
            current = Trie::branch(open_bit, [left, current]);
        }
        open.push((bit, current));
        previous = entry.path;
        current = Trie::Leaf(entry);
    }
    while let Some((bit, left)) = open.pop() {
        current = Trie::branch(bit, [left, current]);
    }
    Some(Some(current))
}

type Link<V> = Option<Arc<Node<V>>>;

/// An index node. The index is weight balanced: unless a node has at most one
/// descendant, neither child holds more than `DELTA` times the other's entries.
struct Node<V> {
    entry: Arc<Entry<V>>,
    left: Link<V>,
    right: Link<V>,
    size: usize,
}

/// Balance parameters of Adams' weight-balanced trees as used by Haskell's
/// `Data.Map`; (3, 2) is the integer pair proven to keep every tree balanced
/// under single insertions and deletions (Hirai and Yamamoto, 2011). Each
/// child then holds at most three quarters of its parent's entries, so the
/// height is below 2.41 * log2(n + 1) + 2.
const DELTA: usize = 3;
const RATIO: usize = 2;

fn size<V>(link: &Link<V>) -> usize {
    link.as_ref().map_or(0, |n| n.size)
}

fn node<V>(entry: Arc<Entry<V>>, left: Link<V>, right: Link<V>) -> Arc<Node<V>> {
    let size = 1 + size(&left) + size(&right);
    Arc::new(Node {
        entry,
        left,
        right,
        size,
    })
}

/// A node over subtrees that were balanced before one insertion or deletion
/// below it, rotated once or twice if that left it out of balance.
fn balance<V>(entry: Arc<Entry<V>>, left: Link<V>, right: Link<V>) -> Arc<Node<V>> {
    let (l, r) = (size(&left), size(&right));
    if l + r <= 1 {
        node(entry, left, right)
    } else if r > DELTA * l {
        rotate_left(entry, left, right)
    } else if l > DELTA * r {
        rotate_right(entry, left, right)
    } else {
        node(entry, left, right)
    }
}

fn rotate_left<V>(entry: Arc<Entry<V>>, left: Link<V>, right: Link<V>) -> Arc<Node<V>> {
    let Some(r) = right.as_deref() else {
        return node(entry, left, right);
    };
    match r.left.as_deref() {
        Some(rl) if size(&r.left) >= RATIO * size(&r.right) => node(
            rl.entry.clone(),
            Some(node(entry, left, rl.left.clone())),
            Some(node(r.entry.clone(), rl.right.clone(), r.right.clone())),
        ),
        _ => node(
            r.entry.clone(),
            Some(node(entry, left, r.left.clone())),
            r.right.clone(),
        ),
    }
}

fn rotate_right<V>(entry: Arc<Entry<V>>, left: Link<V>, right: Link<V>) -> Arc<Node<V>> {
    let Some(l) = left.as_deref() else {
        return node(entry, left, right);
    };
    match l.right.as_deref() {
        Some(lr) if size(&l.right) >= RATIO * size(&l.left) => node(
            lr.entry.clone(),
            Some(node(l.entry.clone(), l.left.clone(), lr.left.clone())),
            Some(node(entry, lr.right.clone(), right)),
        ),
        _ => node(
            l.entry.clone(),
            l.left.clone(),
            Some(node(entry, l.right.clone(), right)),
        ),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Direction {
    Left,
    Right,
}

/// Copies a recorded index path bottom-up, rebalancing each copied node.
fn rebalance<V>(path: Vec<(&Node<V>, Direction)>, mut child: Link<V>) -> Link<V> {
    for (n, direction) in path.into_iter().rev() {
        child = Some(match direction {
            Direction::Left => balance(n.entry.clone(), child, n.right.clone()),
            Direction::Right => balance(n.entry.clone(), n.left.clone(), child),
        });
    }
    child
}

fn index_insert<V>(root: &Link<V>, entry: Arc<Entry<V>>) -> Link<V> {
    let mut path = Vec::new();
    let mut next = root.as_deref();
    while let Some(n) = next {
        let direction = match entry.key.cmp(&n.entry.key) {
            // Sizes are unchanged, so rebalancing the path rotates nothing.
            Ordering::Equal => {
                let replaced = node(entry, n.left.clone(), n.right.clone());
                return rebalance(path, Some(replaced));
            }
            Ordering::Less => Direction::Left,
            Ordering::Greater => Direction::Right,
        };
        path.push((n, direction));
        next = match direction {
            Direction::Left => n.left.as_deref(),
            Direction::Right => n.right.as_deref(),
        };
    }
    rebalance(path, Some(node(entry, None, None)))
}

/// The index without `key` and the entry removed, if it was present.
fn index_remove<V>(root: &Link<V>, key: &[u8]) -> Option<(Link<V>, Arc<Entry<V>>)> {
    let mut path = Vec::new();
    let mut next = root.as_deref();
    while let Some(n) = next {
        let direction = match key.cmp(n.entry.key.as_slice()) {
            Ordering::Equal => {
                let joined = join(&n.left, &n.right);
                return Some((rebalance(path, joined), n.entry.clone()));
            }
            Ordering::Less => Direction::Left,
            Ordering::Greater => Direction::Right,
        };
        path.push((n, direction));
        next = match direction {
            Direction::Left => n.left.as_deref(),
            Direction::Right => n.right.as_deref(),
        };
    }
    None
}

/// Joins the two subtrees of a removed node, all of whose keys are ordered
/// before and after each other, around an extreme entry of the larger one.
fn join<V>(left: &Link<V>, right: &Link<V>) -> Link<V> {
    match (left.as_deref(), right.as_deref()) {
        (None, _) => right.clone(),
        (_, None) => left.clone(),
        (Some(l), Some(r)) => Some(if l.size > r.size {
            let (last, rest) = remove_extreme(l, Direction::Right);
            balance(last, rest, right.clone())
        } else {
            let (first, rest) = remove_extreme(r, Direction::Left);
            balance(first, left.clone(), rest)
        }),
    }
}

/// Removes the first (`Left`) or last (`Right`) entry of a subtree.
fn remove_extreme<V>(top: &Node<V>, direction: Direction) -> (Arc<Entry<V>>, Link<V>) {
    let mut path = Vec::new();
    let mut n = top;
    loop {
        let (inner, outer) = match direction {
            Direction::Left => (&n.left, &n.right),
            Direction::Right => (&n.right, &n.left),
        };
        match inner.as_deref() {
            Some(child) => {
                path.push((n, direction));
                n = child;
            }
            None => return (n.entry.clone(), rebalance(path, outer.clone())),
        }
    }
}

/// A perfectly balanced index of key-ordered entries. Recursion depth is
/// log2 of their number.
fn build_index<V>(entries: &[Arc<Entry<V>>]) -> Link<V> {
    if entries.is_empty() {
        return None;
    }
    let middle = entries.len() / 2;
    Some(node(
        entries[middle].clone(),
        build_index(&entries[..middle]),
        build_index(&entries[middle + 1..]),
    ))
}

pub struct Map<V> {
    /// The committed trie; `None` when the map is empty.
    trie: Option<Trie<V>>,
    /// The uncommitted index of the same entries in key order.
    index: Link<V>,
}

impl<V> Clone for Map<V> {
    fn clone(&self) -> Self {
        Self {
            trie: self.trie.clone(),
            index: self.index.clone(),
        }
    }
}

impl<V: fmt::Debug> fmt::Debug for Map<V> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_map().entries(self.iter()).finish()
    }
}

impl<V> Default for Map<V> {
    fn default() -> Self {
        Self {
            trie: None,
            index: None,
        }
    }
}

impl<V> Map<V> {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn len(&self) -> usize {
        size(&self.index)
    }
    pub fn is_empty(&self) -> bool {
        self.index.is_none()
    }
    pub fn root(&self) -> Hash {
        self.trie.as_ref().map_or_else(empty_root, Trie::hash)
    }

    fn entry(&self, key: &[u8]) -> Option<&Arc<Entry<V>>> {
        let mut next = self.index.as_deref();
        while let Some(n) = next {
            match key.cmp(n.entry.key.as_slice()) {
                Ordering::Equal => return Some(&n.entry),
                Ordering::Less => next = n.left.as_deref(),
                Ordering::Greater => next = n.right.as_deref(),
            }
        }
        None
    }

    pub fn get(&self, key: &[u8]) -> Option<&V> {
        self.get_shared(key).map(|value| &**value)
    }

    /// The stored value itself, for a holder that must outlive this version
    /// without copying it.
    pub fn get_shared(&self, key: &[u8]) -> Option<&Arc<V>> {
        self.entry(key).map(|entry| &entry.value)
    }

    /// The entry with the greatest key.
    pub fn last(&self) -> Option<(&[u8], &V)> {
        let mut n = self.index.as_deref()?;
        while let Some(right) = n.right.as_deref() {
            n = right;
        }
        Some((&n.entry.key, &*n.entry.value))
    }

    /// Entries in key order.
    pub fn iter(&self) -> Iter<'_, V> {
        let mut it = Iter { stack: Vec::new() };
        it.push_left(self.index.as_deref());
        it
    }

    /// An inclusion proof commits to a value, not to a particular serialization
    /// of an in-memory tree. The caller supplies the independently trusted root.
    /// Its length is the key's depth in the trie.
    pub fn proof(&self, key: &[u8]) -> Option<Proof> {
        let entry = self.entry(key)?;
        let mut path = Vec::new();
        let mut next = self.trie.as_ref()?;
        while let Trie::Branch(b) = next {
            let side = side(&entry.path, b.bit);
            path.push(ProofStep {
                bit: b.bit,
                sibling: b.children[1 - side].hash(),
            });
            next = &b.children[side];
        }
        Some(Proof { path })
    }
}

impl<V: Clone + Serialize> Map<V> {
    pub fn insert(&mut self, key: Vec<u8>, value: V) {
        let entry = Entry::new(key, Arc::new(value));
        self.trie = Some(trie_insert(self.trie.as_ref(), entry.clone()));
        self.index = index_insert(&self.index, entry);
    }

    pub fn remove(&mut self, key: &[u8]) -> Option<V> {
        let (index, entry) = index_remove(&self.index, key)?;
        self.trie = self.trie.as_ref().and_then(|trie| trie_remove(trie, &entry));
        self.index = index;
        Some((*entry.value).clone())
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
        Some((&n.entry.key, &*n.entry.value))
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
            /// Sorted entries determine a balanced index directly, and sorting
            /// them by path builds the trie in one pass.
            fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Map<V>, A::Error> {
                let mut entries: Vec<Arc<Entry<V>>> = Vec::new();
                while let Some((key, value)) = seq.next_element::<(Vec<u8>, V)>()? {
                    if entries.last().is_some_and(|last| last.key >= key) {
                        return Err(de::Error::custom("map keys must be strictly increasing"));
                    }
                    entries.push(Entry::new(key, Arc::new(value)));
                }
                let index = build_index(&entries);
                let trie = build_trie(entries)
                    .ok_or_else(|| de::Error::custom("map key paths must be distinct"))?;
                Ok(Map { trie, index })
            }
        }
        deserializer.deserialize_seq(Visitor(std::marker::PhantomData))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofStep {
    /// The branch's bit; the proven key's path selects its side.
    pub bit: u8,
    /// The root of the branch's other child.
    pub sibling: Hash,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proof {
    /// Root-to-leaf branches above the proven entry's leaf.
    pub path: Vec<ProofStep>,
}

impl Proof {
    pub fn verify<V: Serialize>(&self, key: &[u8], value: &V, expected_root: &Hash) -> bool {
        if !self.path.is_sorted_by(|a, b| a.bit < b.bit) {
            return false;
        }
        let path = key_path(key);
        let mut digest = leaf_hash(key, value);
        for step in self.path.iter().rev() {
            digest = match side(&path, step.bit) {
                0 => branch_hash(step.bit, &digest, &step.sibling),
                _ => branch_hash(step.bit, &step.sibling, &digest),
            };
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

    /// Checks a trie subtree whose paths all share bits before `above`, and
    /// returns its entries' keys and depths.
    fn check_trie(t: &Trie<u64>, above: Option<u8>, depth: usize, out: &mut Vec<(Vec<u8>, usize)>) {
        match t {
            Trie::Leaf(e) => {
                assert_eq!(e.path, key_path(&e.key));
                assert_eq!(e.hash, leaf_hash(&e.key, &*e.value));
                out.push((e.key.clone(), depth));
            }
            Trie::Branch(b) => {
                assert!(above.is_none_or(|bit| bit < b.bit));
                assert_eq!(
                    b.hash,
                    branch_hash(b.bit, &b.children[0].hash(), &b.children[1].hash())
                );
                for (side_index, child) in b.children.iter().enumerate() {
                    let start = out.len();
                    check_trie(child, Some(b.bit), depth + 1, out);
                    for (k, _) in &out[start..] {
                        assert_eq!(side(&key_path(k), b.bit), side_index);
                    }
                }
            }
        }
    }

    /// Checks key order, sizes and weight balance; returns the height.
    fn check_index(n: &Link<u64>, low: Option<&[u8]>, high: Option<&[u8]>) -> usize {
        let Some(n) = n else {
            return 0;
        };
        let key = n.entry.key.as_slice();
        assert!(low.is_none_or(|k| k < key));
        assert!(high.is_none_or(|k| k > key));
        let (l, r) = (size(&n.left), size(&n.right));
        assert_eq!(n.size, 1 + l + r);
        assert!(l + r <= 1 || (l <= DELTA * r && r <= DELTA * l), "{l} {r}");
        1 + check_index(&n.left, low, Some(key)).max(check_index(&n.right, Some(key), high))
    }

    /// Checks both structures and that the trie is the one its entries
    /// determine; returns the trie's maximum depth and the index height.
    fn check(map: &Map<u64>) -> (usize, usize) {
        let height = check_index(&map.index, None, None);
        let mut leaves = Vec::new();
        if let Some(t) = &map.trie {
            check_trie(t, None, 0, &mut leaves);
        }
        leaves.sort();
        let keys: Vec<_> = map.iter().map(|(k, _)| k.to_vec()).collect();
        assert_eq!(leaves.iter().map(|(k, _)| k.clone()).collect::<Vec<_>>(), keys);
        assert_eq!(map.len(), keys.len());
        let rebuilt: Map<u64> = codec::decode(&codec::encode(map), usize::MAX).unwrap();
        assert_eq!(rebuilt.root(), map.root());
        (leaves.iter().map(|(_, d)| *d).max().unwrap_or(0), height)
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
            if i % 97 == 0 {
                check(&map);
            }
        }
        assert_eq!(map.len(), reference.len());
        assert_eq!(
            map.iter()
                .map(|(k, v)| (k.to_vec(), *v))
                .collect::<Vec<_>>(),
            reference.clone().into_iter().collect::<Vec<_>>()
        );
        for (k, v) in &reference {
            assert_eq!(map.get(k), Some(v));
        }
        assert_eq!(map.get(&key(600)), None);
        check(&map);
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
        check(&restored);
        let json_restored: Map<u64> =
            serde_json::from_str(&serde_json::to_string(&a).unwrap()).unwrap();
        assert_eq!(a.root(), json_restored.root());
        for n in [0, 1, 2, 3, 17] {
            let small = populated(0..n);
            let restored: Map<u64> = codec::decode(&codec::encode(&small), 1000).unwrap();
            assert_eq!(small.root(), restored.root());
            check(&restored);
        }
        // A lone entry is its own leaf.
        let one = populated(0..1);
        assert_eq!(one.root(), leaf_hash(&key(0), &0u64));
        assert_eq!(Map::<u64>::new().root(), empty_root());
    }

    #[test]
    fn sorted_insertions_keep_the_index_balanced_and_the_trie_shallow() {
        // Ascending and descending keys degenerate an unbalanced search tree.
        for order in [
            (0..4096).collect::<Vec<u32>>(),
            (0..4096).rev().collect::<Vec<u32>>(),
        ] {
            let mut map = populated(order);
            let (depth, height) = check(&map);
            // 2.41 * log2(4097) + 2 < 31; a perfect tree has height 13.
            assert!(height <= 30, "index height {height}");
            // Random paths: about log2(4096) = 12, far below the 256 bound.
            assert!(depth <= 40, "trie depth {depth}");
            for n in (0..4096).step_by(2) {
                map.remove(&key(n));
            }
            assert!(check(&map).1 <= 28);
        }
    }

    #[test]
    fn updates_copy_one_path_and_share_stored_values() {
        let original = populated(0..200);
        let mut next = original.clone();
        let depth = original.proof(&key(87)).unwrap().path.len();
        next.insert(key(87), 999);
        // Only the branches above the updated leaf are new.
        let fresh = |t: &Trie<u64>, old: &Trie<u64>| {
            let (mut count, mut pending) = (0, vec![(t.clone(), old.clone())]);
            while let Some((a, b)) = pending.pop() {
                match (a, b) {
                    (Trie::Branch(x), Trie::Branch(y)) if Arc::ptr_eq(&x, &y) => {}
                    (Trie::Leaf(x), Trie::Leaf(y)) if Arc::ptr_eq(&x, &y) => {}
                    (Trie::Branch(x), Trie::Branch(y)) => {
                        count += 1;
                        pending.extend(x.children.iter().cloned().zip(y.children.iter().cloned()));
                    }
                    _ => count += 1,
                }
            }
            count
        };
        let (new_trie, old_trie) = (next.trie.as_ref().unwrap(), original.trie.as_ref().unwrap());
        assert_eq!(fresh(new_trie, old_trie), depth + 1);
        // Untouched entries are the same records in both versions.
        assert!(Arc::ptr_eq(
            original.get_shared(&key(3)).unwrap(),
            next.get_shared(&key(3)).unwrap()
        ));
        assert_eq!(next.remove(&key(87)), Some(999));
        assert!(std::ptr::eq(
            original.get(&key(150)).unwrap(),
            next.get(&key(150)).unwrap()
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
            original.index.as_ref().unwrap(),
            next.index.as_ref().unwrap()
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
            if n % 23 == 0 {
                check(&next);
            }
        }
        assert!(next.is_empty());
        assert_eq!(next.root(), Map::<u64>::new().root());
        assert_eq!(next.remove(&key(7)), None);
        assert_eq!(next.last(), None);
        assert!(next.trie.is_none());
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
            modified.path[0].sibling[0] ^= 1;
            assert!(!modified.verify(&key(n), &(n as u64 * 3), &map.root()));
            let mut modified = proof.clone();
            modified.path[0].bit ^= 1;
            assert!(!modified.verify(&key(n), &(n as u64 * 3), &map.root()));
            // Steps must descend to ever later bits.
            let mut modified = proof;
            modified.path.swap(0, 1);
            assert!(!modified.verify(&key(n), &(n as u64 * 3), &map.root()));
        }
        assert!(map.proof(&key(500)).is_none());
        // A lone entry's proof is empty.
        let one = populated(5..6);
        let proof = one.proof(&key(5)).unwrap();
        assert!(proof.path.is_empty());
        assert!(proof.verify(&key(5), &15u64, &one.root()));
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

    #[test]
    fn path_bits_read_most_significant_first() {
        let mut path = [0u8; 32];
        path[0] = 0b1000_0000;
        path[31] = 1;
        assert_eq!((side(&path, 0), side(&path, 1), side(&path, 255)), (1, 0, 1));
        let mut other = path;
        assert_eq!(first_difference(&path, &other), None);
        other[31] = 0;
        assert_eq!(first_difference(&path, &other), Some(255));
        other[0] = 0;
        assert_eq!(first_difference(&path, &other), Some(0));
        other = path;
        other[2] ^= 0b0001_0000;
        assert_eq!(first_difference(&path, &other), Some(19));
    }
}
