//! DID state inside the account SMT.
//! PHASE A: pure logic only. NOT called from consensus yet.
//!
//! Leaf key   = hash_key("DID1" || did)
//! Leaf value = content hash of the DidDocument (stored content-addressed)
//! No wall-clock: created_at / updated_at carry the block DAA score.

use crate::model::stores::did_store::DidDocument;
use sahyadri_addresses::Prefix;
use sahyadri_database::prelude::StoreError;
use sahyadri_hashes::Hash;
use sahyadri_smt::{NodeStore, SmtError, H256};
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;

pub const MAX_DID_DOC_BYTES: usize = 16 * 1024;
const DID_PREFIX: &str = "did:sahyadri:";
const PUBKEY_BYTES: usize = 1952;

#[derive(Debug)]
pub enum DidError {
    Smt(SmtError),
    Store(StoreError),
    MissingState(String),
}
impl From<SmtError> for DidError {
    fn from(e: SmtError) -> Self {
        DidError::Smt(e)
    }
}
impl From<StoreError> for DidError {
    fn from(e: StoreError) -> Self {
        DidError::Store(e)
    }
}

/// Content-addressed DID state reader (hash -> document). Ok(None) = not stored.
pub trait DidStatesReader {
    fn get_did_state(&self, hash: Hash) -> Result<Option<DidDocument>, StoreError>;
}

pub fn did_key_hash(did: &str) -> H256 {
    let mut bytes = b"DID1".to_vec();
    bytes.extend_from_slice(did.as_bytes());
    sahyadri_smt::hash_key(&bytes)
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u32).to_le_bytes());
    out.extend_from_slice(s.as_bytes());
}

pub fn did_content_hash(d: &DidDocument) -> Hash {
    let mut out = Vec::with_capacity(256 + d.document.len());
    put_str(&mut out, &d.did);
    put_str(&mut out, &d.csm_address);
    put_str(&mut out, &d.public_key);
    put_str(&mut out, &d.document);
    out.push(d.active as u8);
    out.extend_from_slice(&d.version.to_le_bytes());
    out.extend_from_slice(&d.created_at.to_le_bytes());
    out.extend_from_slice(&d.updated_at.to_le_bytes());
    let mut purposes = d.purposes.clone();
    purposes.sort();
    out.extend_from_slice(&(purposes.len() as u32).to_le_bytes());
    for p in &purposes {
        put_str(&mut out, p);
    }
    let mut services = d.services.clone();
    services.sort();
    out.extend_from_slice(&(services.len() as u32).to_le_bytes());
    for s in &services {
        put_str(&mut out, s);
    }
    let mut h = Sha3_256::new();
    h.update(b"SAHYADRI_DID_STATE_V1");
    h.update(&out);
    Hash::from_slice(&h.finalize())
}

/// Binding hash — used ONLY for DCRT/DUPD signature binding.
/// Excludes created_at/updated_at (which carry DAA score and are not
/// known to the wallet at signing time). Binding covers:
///   did + csm_address + public_key + document + version
pub fn did_binding_hash(
    did: &str,
    csm_address: &str,
    public_key_hex: &str,
    document: &str,
    version: u64,
) -> Hash {
    let mut out = Vec::with_capacity(256 + document.len());
    put_str(&mut out, did);
    put_str(&mut out, csm_address);
    put_str(&mut out, public_key_hex);
    put_str(&mut out, document);
    out.extend_from_slice(&version.to_le_bytes());

    let mut h = Sha3_256::new();
    h.update(b"SAHYADRI_DID_BIND_V1");
    h.update(&out);
    Hash::from_slice(&h.finalize())
}

/// Derive CSM address from Dilithium pubkey with network-aware prefix.
/// MUST match SDK's `pubkeyToAddress` in `sahyadri-sdk/src/address.ts`.
fn derive_csm_address(pubkey: &[u8], prefix: Prefix) -> String {
    use sha3::{Digest, Sha3_256};
    use sahyadri_addresses::{Address, Version};

    let hash = Sha3_256::digest(pubkey);
    let hash20 = &hash[..20];
    Address::new(prefix, Version::PubKeyDilithium, hash20).to_string()
}

// ── Payload parsing (same wire format as the current commit handlers) ──

#[derive(Debug, Clone)]
pub enum DidOp {
    Create { pubkey: Vec<u8>, did: String, csm_address: String, document: String, timestamp: u64, sig: Vec<u8> },
    Update { did: String, document: String, timestamp: u64, sig: Vec<u8> },
    Deactivate { did: String, timestamp: u64, sig: Vec<u8> },
}

fn rd_bytes<'a>(p: &'a [u8], o: &mut usize, n: usize) -> Option<&'a [u8]> {
    let end = o.checked_add(n)?;
    let b = p.get(*o..end)?;
    *o = end;
    Some(b)
}
fn rd_u32(p: &[u8], o: &mut usize) -> Option<usize> {
    Some(u32::from_le_bytes(rd_bytes(p, o, 4)?.try_into().ok()?) as usize)
}
fn rd_str(p: &[u8], o: &mut usize) -> Option<String> {
    let n = rd_u32(p, o)?;
    String::from_utf8(rd_bytes(p, o, n)?.to_vec()).ok()
}
fn last_u64(body: &[u8], min_start: usize) -> Option<u64> {
    let start = body.len().checked_sub(8)?;
    if start < min_start {
        return None;
    }
    Some(u64::from_le_bytes(body[start..].try_into().ok()?))
}

/// `sig_size` = SIG_SIZE of the Dilithium mode used by the node.
pub fn parse_did_op(payload: &[u8], sig_size: usize) -> Option<DidOp> {
    if payload.len() < 4 + sig_size {
        return None;
    }
    let (body, sig) = payload.split_at(payload.len() - sig_size);
    let sig = sig.to_vec();
    let mut o = 4usize;
    match &body[..4] {
        b"DCRT" => {
            let did = rd_str(body, &mut o)?;
            let pubkey = rd_bytes(body, &mut o, PUBKEY_BYTES)?.to_vec();
            let csm_address = rd_str(body, &mut o)?;
            let document = rd_str(body, &mut o)?;
            let timestamp = u64::from_le_bytes(rd_bytes(body, &mut o, 8)?.try_into().ok()?);
            Some(DidOp::Create { pubkey, did, csm_address, document, timestamp, sig })
        }
        b"DUPD" => {
            let did = rd_str(body, &mut o)?;
            let document = rd_str(body, &mut o)?;
            let timestamp = last_u64(body, o)?;
            Some(DidOp::Update { did, document, timestamp, sig })
        }
        b"DDEC" => {
            let did = rd_str(body, &mut o)?;
            let timestamp = last_u64(body, o)?;
            Some(DidOp::Deactivate { did, timestamp, sig })
        }
        _ => None,
    }
}

// ── State transition ──

fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = vec![0u8; s.len() / 2];
    faster_hex::hex_decode(s.as_bytes(), &mut out).ok()?;
    Some(out)
}

fn lookup(
    smt: &impl NodeStore,
    states: &dyn DidStatesReader,
    root: H256,
    touched: &HashMap<String, DidDocument>,
    did: &str,
) -> Result<Option<DidDocument>, DidError> {
    if let Some(d) = touched.get(did) {
        return Ok(Some(d.clone()));
    }
    match sahyadri_smt::get(smt, root, &did_key_hash(did))? {
        None => Ok(None),
        Some(h) => match states.get_did_state(Hash::from_bytes(h))? {
            Some(d) => Ok(Some(d)),
            None => Err(DidError::MissingState(did.to_string())),
        },
    }
}

/// Apply a block's DID ops on top of `root`. Invalid ops are skipped (never fail the block).
/// `verify(pubkey, sig, msg)` is injected so this file needs no Dilithium imports.
pub fn compute_block_did_changes(
    root: H256,
    smt: &mut impl NodeStore,
    states: &dyn DidStatesReader,
    ops: &[DidOp],
    daa_score: u64,
    prefix: Prefix,
    verify: &dyn Fn(&[u8], &[u8], &[u8]) -> bool,
) -> Result<(H256, Vec<DidDocument>), DidError> {
    let mut touched: HashMap<String, DidDocument> = HashMap::new();

    for op in ops {
        match op {
            DidOp::Create { pubkey, did, csm_address, document, timestamp: _timestamp, sig } => {
                if document.len() > MAX_DID_DOC_BYTES || *did != format!("{}{}", DID_PREFIX, csm_address) {
                    continue;
                }

                // Squatting check — csm_address must derive from pubkey
                let derived = derive_csm_address(pubkey, prefix);
                if derived != *csm_address {
                    log::warn!(
                        "SAHYADRI DID: csm_address mismatch — expected {}, got {}",
                        derived, csm_address
                    );
                    continue;
                }

                if lookup(&*smt, states, root, &touched, did)?.is_some() {
                    continue;
                }
                let pubkey_hex = faster_hex::hex_string(pubkey);
                let binding = did_binding_hash(did, csm_address, &pubkey_hex, document, 1);
                let binding_hex = faster_hex::hex_string(&binding.as_bytes());
                let msg = format!("did:create:{}:1:{}", csm_address, binding_hex);
                log::warn!("DID DEBUG: csm_address=[{}]", csm_address);
                log::warn!("DID DEBUG: pubkey_hex=[{}]", pubkey_hex);
                log::warn!("DID DEBUG: document=[{}]", document);
                log::warn!("DID DEBUG: binding_hex=[{}]", binding_hex);
                log::warn!("DID DEBUG: msg=[{}]", msg);
                if !verify(pubkey, sig, msg.as_bytes()) {
                    log::warn!("DID_DBG verify FAILED for did={}", did);
                    continue;
                }
                log::warn!("DID_DBG verify PASSED for did={}", did);
                touched.insert(
                    did.clone(),
                    DidDocument {
                        did: did.clone(),
                        csm_address: csm_address.clone(),
                        public_key: faster_hex::hex_string(pubkey),
                        document: document.clone(),
                        purposes: vec!["authentication".to_string()],
                        services: vec![],
                        active: true,
                        created_at: daa_score,
                        updated_at: daa_score,
                        version: 1,
                    },
                );
            }
            DidOp::Update { did, document, timestamp: _timestamp, sig } => {
                if document.len() > MAX_DID_DOC_BYTES {
                    continue;
                }
                let Some(mut cur) = lookup(&*smt, states, root, &touched, did)? else { continue };
                if !cur.active {
                    continue;
                }
                let Some(pk) = hex_to_bytes(&cur.public_key) else { continue };
                let new_version = cur.version + 1;
                let binding = did_binding_hash(
                    &cur.did,
                    &cur.csm_address,
                    &cur.public_key,
                    document,
                    new_version,
                );
                let binding_hex = faster_hex::hex_string(&binding.as_bytes());
                let msg = format!("did:update:{}:{}:{}", cur.csm_address, new_version, binding_hex);
                if !verify(&pk, sig, msg.as_bytes()) {
                    continue;
                }
                cur.document = document.clone();
                cur.updated_at = daa_score;
                cur.version += 1;
                touched.insert(did.clone(), cur);
            }
            DidOp::Deactivate { did, timestamp: _timestamp, sig } => {
                let Some(mut cur) = lookup(&*smt, states, root, &touched, did)? else { continue };
                if !cur.active {
                    continue;
                }
                let Some(pk) = hex_to_bytes(&cur.public_key) else { continue };
                let new_version = cur.version + 1;
                let msg = format!("did:deactivate:{}:{}", cur.csm_address, new_version);
                if !verify(&pk, sig, msg.as_bytes()) {
                    continue;
                }
                cur.active = false;
                cur.updated_at = daa_score;
                cur.version += 1;
                touched.insert(did.clone(), cur);
            }
        }
    }

    let mut new_root = root;
    let mut changed = Vec::with_capacity(touched.len());
    for (did, doc) in touched {
        let leaf = did_content_hash(&doc).as_bytes();
        new_root = sahyadri_smt::update(smt, new_root, &did_key_hash(&did), Some(leaf))?;
        changed.push(doc);
    }
    Ok((new_root, changed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sahyadri_smt::{MemStore, EMPTY};

    #[derive(Default)]
    struct MockStates(HashMap<Hash, DidDocument>);
    impl DidStatesReader for MockStates {
        fn get_did_state(&self, h: Hash) -> Result<Option<DidDocument>, StoreError> {
            Ok(self.0.get(&h).cloned())
        }
    }

    fn create_op(addr: &str) -> DidOp {
        DidOp::Create {
            pubkey: vec![7; PUBKEY_BYTES],
            did: format!("did:sahyadri:{}", addr),
            csm_address: addr.to_string(),
            document: "{}".to_string(),
            timestamp: 1,
            sig: vec![],
        }
    }

    #[test]
    fn duplicate_create_is_skipped() {
        let mut smt = MemStore::default();
        let ok = |_: &[u8], _: &[u8], _: &[u8]| true;
        let ops = vec![create_op("csm1a"), create_op("csm1a")];
        let (root, changed) =
            compute_block_did_changes(EMPTY, &mut smt, &MockStates::default(), &ops, 10, &ok).unwrap();
        assert_eq!(changed.len(), 1);
        assert_ne!(root, EMPTY);
    }

    #[test]
    fn bad_signature_changes_nothing() {
        let mut smt = MemStore::default();
        let bad = |_: &[u8], _: &[u8], _: &[u8]| false;
        let (root, changed) =
            compute_block_did_changes(EMPTY, &mut smt, &MockStates::default(), &[create_op("csm1a")], 10, &bad)
                .unwrap();
        assert!(changed.is_empty());
        assert_eq!(root, EMPTY);
    }

    #[test]
    fn root_is_order_independent() {
        let ok = |_: &[u8], _: &[u8], _: &[u8]| true;
        let mut s1 = MemStore::default();
        let mut s2 = MemStore::default();
        let (r1, _) = compute_block_did_changes(
            EMPTY, &mut s1, &MockStates::default(), &[create_op("csm1a"), create_op("csm1b")], 5, &ok,
        )
        .unwrap();
        let (r2, _) = compute_block_did_changes(
            EMPTY, &mut s2, &MockStates::default(), &[create_op("csm1b"), create_op("csm1a")], 5, &ok,
        )
        .unwrap();
        assert_eq!(r1, r2);
    }
}
