//! Sahyadri Sparse Merkle Tree (SMT).
//!
//! 256-level binary tree keyed by a 32-byte hash. Subtrees holding a single
//! leaf are compressed into that leaf, so the tree shape (and therefore the
//! root) is canonical: it depends only on the set of (key, value) pairs,
//! never on insertion order. Nodes are content-addressed, so a new root can
//! be derived from a parent root without mutating any existing state.

use sha3::{Digest, Sha3_256};
use std::collections::HashMap;

pub type H256 = [u8; 32];

/// Root of an empty tree / hash of an empty subtree.
pub const EMPTY: H256 = [0u8; 32];

const TREE_DEPTH: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Node {
    Leaf { key: H256, value: H256 },
    Branch { left: H256, right: H256 },
}

impl Node {
    pub fn hash(&self) -> H256 {
        match self {
            Node::Leaf { key, value } => hash_leaf(key, value),
            Node::Branch { left, right } => hash_branch(left, right),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SmtError {
    MissingNode(H256),
    DepthExceeded,
}

pub fn hash_leaf(key: &H256, value: &H256) -> H256 {
    let mut h = Sha3_256::new();
    h.update(b"SAHYADRI_SMT_LEAF_V1");
    h.update(key);
    h.update(value);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

pub fn hash_branch(left: &H256, right: &H256) -> H256 {
    let mut h = Sha3_256::new();
    h.update(b"SAHYADRI_SMT_BRANCH_V1");
    h.update(left);
    h.update(right);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

/// Hash arbitrary bytes into a tree key (use for account keys).
pub fn hash_key(data: &[u8]) -> H256 {
    let mut h = Sha3_256::new();
    h.update(b"SAHYADRI_SMT_KEY_V1");
    h.update(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

#[inline]
fn bit(key: &H256, i: usize) -> u8 {
    (key[i / 8] >> (7 - (i % 8))) & 1
}

/// Node storage. A DB-backed implementation (and an overlay on top of it)
/// will implement this later; `MemStore` is used for tests.
pub trait NodeStore {
    fn get(&self, hash: &H256) -> Option<Node>;
    /// Store the node and return its hash.
    fn put(&mut self, node: Node) -> H256;
}

#[derive(Default, Clone)]
pub struct MemStore {
    nodes: HashMap<H256, Node>,
}

impl NodeStore for MemStore {
    fn get(&self, hash: &H256) -> Option<Node> {
        self.nodes.get(hash).cloned()
    }
    fn put(&mut self, node: Node) -> H256 {
        let h = node.hash();
        self.nodes.insert(h, node);
        h
    }
}

fn is_leaf<S: NodeStore>(store: &S, h: &H256) -> Result<bool, SmtError> {
    Ok(matches!(store.get(h).ok_or(SmtError::MissingNode(*h))?, Node::Leaf { .. }))
}

/// Set (`Some`) or delete (`None`) a key. Returns the new root.
pub fn update<S: NodeStore>(store: &mut S, root: H256, key: &H256, value: Option<H256>) -> Result<H256, SmtError> {
    update_at(store, root, 0, key, value)
}

/// Apply many changes. Order does not affect the resulting root.
pub fn update_many<S: NodeStore, I: IntoIterator<Item = (H256, Option<H256>)>>(
    store: &mut S,
    mut root: H256,
    changes: I,
) -> Result<H256, SmtError> {
    for (key, value) in changes {
        root = update(store, root, &key, value)?;
    }
    Ok(root)
}

fn update_at<S: NodeStore>(
    store: &mut S,
    node_hash: H256,
    depth: usize,
    key: &H256,
    value: Option<H256>,
) -> Result<H256, SmtError> {
    if node_hash == EMPTY {
        return Ok(match value {
            Some(v) => store.put(Node::Leaf { key: *key, value: v }),
            None => EMPTY,
        });
    }
    let node = store.get(&node_hash).ok_or(SmtError::MissingNode(node_hash))?;
    match node {
        Node::Leaf { key: k, value: v } => {
            if &k == key {
                return Ok(match value {
                    Some(nv) => store.put(Node::Leaf { key: k, value: nv }),
                    None => EMPTY,
                });
            }
            let Some(nv) = value else { return Ok(node_hash) };
            split(store, depth, k, v, *key, nv)
        }
        Node::Branch { left, right } => {
            if depth >= TREE_DEPTH {
                return Err(SmtError::DepthExceeded);
            }
            let (l, r) = if bit(key, depth) == 0 {
                (update_at(store, left, depth + 1, key, value)?, right)
            } else {
                (left, update_at(store, right, depth + 1, key, value)?)
            };
            normalize(store, l, r)
        }
    }
}

/// Place two distinct leaves under a new subtree rooted at `depth`.
fn split<S: NodeStore>(store: &mut S, depth: usize, ka: H256, va: H256, kb: H256, vb: H256) -> Result<H256, SmtError> {
    if depth >= TREE_DEPTH {
        return Err(SmtError::DepthExceeded);
    }
    let (ba, bb) = (bit(&ka, depth), bit(&kb, depth));
    if ba != bb {
        let ha = store.put(Node::Leaf { key: ka, value: va });
        let hb = store.put(Node::Leaf { key: kb, value: vb });
        let (l, r) = if ba == 0 { (ha, hb) } else { (hb, ha) };
        Ok(store.put(Node::Branch { left: l, right: r }))
    } else {
        let child = split(store, depth + 1, ka, va, kb, vb)?;
        let (l, r) = if ba == 0 { (child, EMPTY) } else { (EMPTY, child) };
        Ok(store.put(Node::Branch { left: l, right: r }))
    }
}

/// Keep the tree canonical after a child changed (collapse on delete).
fn normalize<S: NodeStore>(store: &mut S, l: H256, r: H256) -> Result<H256, SmtError> {
    match (l == EMPTY, r == EMPTY) {
        (true, true) => Ok(EMPTY),
        (false, true) if is_leaf(&*store, &l)? => Ok(l),
        (true, false) if is_leaf(&*store, &r)? => Ok(r),
        _ => Ok(store.put(Node::Branch { left: l, right: r })),
    }
}

pub fn get<S: NodeStore>(store: &S, root: H256, key: &H256) -> Result<Option<H256>, SmtError> {
    let mut cur = root;
    let mut depth = 0usize;
    loop {
        if cur == EMPTY {
            return Ok(None);
        }
        match store.get(&cur).ok_or(SmtError::MissingNode(cur))? {
            Node::Leaf { key: k, value } => return Ok(if &k == key { Some(value) } else { None }),
            Node::Branch { left, right } => {
                if depth >= TREE_DEPTH {
                    return Err(SmtError::DepthExceeded);
                }
                cur = if bit(key, depth) == 0 { left } else { right };
                depth += 1;
            }
        }
    }
}

// ───────────────────────── Proofs ─────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Terminal {
    Empty,
    Leaf { key: H256, value: H256 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    /// Sibling hashes from the root downwards.
    pub siblings: Vec<H256>,
    pub terminal: Terminal,
}

pub fn prove<S: NodeStore>(store: &S, root: H256, key: &H256) -> Result<Proof, SmtError> {
    let mut siblings = Vec::new();
    let mut cur = root;
    let mut depth = 0usize;
    loop {
        if cur == EMPTY {
            return Ok(Proof { siblings, terminal: Terminal::Empty });
        }
        match store.get(&cur).ok_or(SmtError::MissingNode(cur))? {
            Node::Leaf { key: k, value } => {
                return Ok(Proof { siblings, terminal: Terminal::Leaf { key: k, value } });
            }
            Node::Branch { left, right } => {
                if depth >= TREE_DEPTH {
                    return Err(SmtError::DepthExceeded);
                }
                if bit(key, depth) == 0 {
                    siblings.push(right);
                    cur = left;
                } else {
                    siblings.push(left);
                    cur = right;
                }
                depth += 1;
            }
        }
    }
}

fn compute_root(key: &H256, proof: &Proof) -> H256 {
    let mut h = match &proof.terminal {
        Terminal::Empty => EMPTY,
        Terminal::Leaf { key, value } => hash_leaf(key, value),
    };
    for (i, sib) in proof.siblings.iter().enumerate().rev() {
        h = if bit(key, i) == 0 { hash_branch(&h, sib) } else { hash_branch(sib, &h) };
    }
    h
}

fn shares_prefix(a: &H256, b: &H256, n: usize) -> bool {
    (0..n).all(|i| bit(a, i) == bit(b, i))
}

/// `key -> value` is present under `root`.
pub fn verify_inclusion(root: &H256, key: &H256, value: &H256, proof: &Proof) -> bool {
    match &proof.terminal {
        Terminal::Leaf { key: k, value: v } if k == key && v == value => compute_root(key, proof) == *root,
        _ => false,
    }
}

/// `key` is absent under `root`.
pub fn verify_exclusion(root: &H256, key: &H256, proof: &Proof) -> bool {
    match &proof.terminal {
        Terminal::Empty => compute_root(key, proof) == *root,
        Terminal::Leaf { key: k, .. } => {
            k != key && shares_prefix(k, key, proof.siblings.len()) && compute_root(key, proof) == *root
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(i: u32) -> H256 {
        hash_key(&i.to_le_bytes())
    }
    fn v(i: u32) -> H256 {
        hash_key(&i.wrapping_add(1_000_000).to_le_bytes())
    }
    fn build(store: &mut MemStore, ids: &[u32]) -> H256 {
        let mut root = EMPTY;
        for &i in ids {
            root = update(store, root, &k(i), Some(v(i))).unwrap();
        }
        root
    }

    #[test]
    fn empty_tree() {
        let s = MemStore::default();
        assert_eq!(get(&s, EMPTY, &k(1)).unwrap(), None);
    }

    #[test]
    fn insert_order_does_not_matter() {
        let ids: Vec<u32> = (0..64).collect();
        let mut rev = ids.clone();
        rev.reverse();
        let (mut s1, mut s2) = (MemStore::default(), MemStore::default());
        assert_eq!(build(&mut s1, &ids), build(&mut s2, &rev));
    }

    #[test]
    fn get_returns_values() {
        let mut s = MemStore::default();
        let root = build(&mut s, &[1, 2, 3, 4, 5]);
        for i in 1..=5 {
            assert_eq!(get(&s, root, &k(i)).unwrap(), Some(v(i)));
        }
        assert_eq!(get(&s, root, &k(99)).unwrap(), None);
    }

    #[test]
    fn delete_restores_previous_root() {
        let mut s = MemStore::default();
        let r_ab = build(&mut s, &[1, 2]);
        let r_abc = update(&mut s, r_ab, &k(3), Some(v(3))).unwrap();
        assert_ne!(r_ab, r_abc);
        let back = update(&mut s, r_abc, &k(3), None).unwrap();
        assert_eq!(back, r_ab);
        let r1 = update(&mut s, back, &k(1), None).unwrap();
        let r0 = update(&mut s, r1, &k(2), None).unwrap();
        assert_eq!(r0, EMPTY);
    }

    #[test]
    fn delete_missing_key_is_noop() {
        let mut s = MemStore::default();
        let root = build(&mut s, &[1, 2, 3]);
        assert_eq!(update(&mut s, root, &k(50), None).unwrap(), root);
    }

    #[test]
    fn overwrite_value() {
        let mut s = MemStore::default();
        let r1 = build(&mut s, &[1, 2]);
        let r2 = update(&mut s, r1, &k(1), Some(v(77))).unwrap();
        assert_ne!(r1, r2);
        assert_eq!(get(&s, r2, &k(1)).unwrap(), Some(v(77)));
        let r3 = update(&mut s, r2, &k(1), Some(v(1))).unwrap();
        assert_eq!(r3, r1);
    }

    #[test]
    fn deep_shared_prefix() {
        let a = [0u8; 32];
        let mut b = [0u8; 32];
        b[31] = 1; // differs only in the very last bit
        let (mut s1, mut s2) = (MemStore::default(), MemStore::default());
        let r1 = update(&mut s1, EMPTY, &a, Some(v(1))).unwrap();
        let r1 = update(&mut s1, r1, &b, Some(v(2))).unwrap();
        let r2 = update(&mut s2, EMPTY, &b, Some(v(2))).unwrap();
        let r2 = update(&mut s2, r2, &a, Some(v(1))).unwrap();
        assert_eq!(r1, r2);
        assert_eq!(get(&s1, r1, &a).unwrap(), Some(v(1)));
        assert_eq!(get(&s1, r1, &b).unwrap(), Some(v(2)));
        let only_a = update(&mut s1, r1, &b, None).unwrap();
        let mut s3 = MemStore::default();
        assert_eq!(only_a, update(&mut s3, EMPTY, &a, Some(v(1))).unwrap());
    }

    #[test]
    fn update_many_matches_sequential() {
        let (mut s1, mut s2) = (MemStore::default(), MemStore::default());
        let seq = build(&mut s1, &[1, 2, 3, 4]);
        let many = update_many(&mut s2, EMPTY, (1..=4).rev().map(|i| (k(i), Some(v(i))))).unwrap();
        assert_eq!(seq, many);
    }

    #[test]
    fn proofs_work() {
        let mut s = MemStore::default();
        let ids: Vec<u32> = (0..40).collect();
        let root = build(&mut s, &ids);
        for i in 0..40 {
            let p = prove(&s, root, &k(i)).unwrap();
            assert!(verify_inclusion(&root, &k(i), &v(i), &p));
            assert!(!verify_inclusion(&root, &k(i), &v(i + 1), &p));
            assert!(!verify_exclusion(&root, &k(i), &p));
        }
        for i in 100..140 {
            let p = prove(&s, root, &k(i)).unwrap();
            assert!(verify_exclusion(&root, &k(i), &p));
            assert!(!verify_inclusion(&root, &k(i), &v(i), &p));
        }
        let mut p = prove(&s, root, &k(3)).unwrap();
        p.siblings[0][0] ^= 1;
        assert!(!verify_inclusion(&root, &k(3), &v(3), &p));
    }
}
