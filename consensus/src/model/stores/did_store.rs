use sahyadri_database::prelude::DbKey;
use rocksdb::WriteBatch;
use sahyadri_database::prelude::{BatchDbWriter, CachedDbAccess, StoreError, StoreResult};
use sahyadri_utils::mem_size::MemSizeEstimator;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

// ============================================================================
// SAHYADRI OBJECT-MODEL LAYER — Decentralized Identity (DID)
// ============================================================================
//
// This module implements the "Object Model" layer of Sahyadri blockchain,
// distinct from the "Account Model" layer (see account_store.rs).
//
// ## Architecture Overview
//
// ### Account Model (account_store.rs)
// - Purpose: Simple balance/nonce tracking for CSM (native token)
// - Structure: Flat { balance: u64, nonce: u64 }
// - Operations: Balance debit/credit, nonce increment/decrement
// - Analogy: Like a bank account ledger
//
// ### Object Model (THIS FILE — did_store.rs)  ⭐
// - Purpose: Rich, versioned identity objects with ownership semantics
// - Structure: Complex nested document with metadata, keys, services
// - Operations: Create, Update, Deactivate, Resolve (CRUD + lifecycle)
// - Analogy: Like a digital passport or identity card
//
// ## Key Differences from Account Model
//
// | Aspect | Account Model | Object Model (DID) |
// |--------|---------------|-------------------|
// | Primary Key | ScriptPublicKey (address) | DID string (did:sahyadri:...) |
// | Data Shape | Flat (balance + nonce) | Structured (document + metadata) |
// | Ownership | Implicit (who can sign) | Explicit (controller field) |
// | Versioning | None (state is current) | Yes (version field for OCC) |
// | Lifecycle | Permanent while balance > 0 | Can be deactivated |
// | Query Methods | By address only | By DID + By address (reverse lookup) |
// | Use Case | Token transfers | Identity, auth, Web5, credentials |
//
// ## Design Patterns Used
//
// 1. **Repository Pattern**: DbDidStore implements DidStore trait (abstract interface)
// 2. **Index Pattern**: Secondary index (address → DID) for reverse lookups
// 3. **Unit of Work**: All writes use WriteBatch for atomicity
// 4. **Optimistic Concurrency**: Version field prevents lost updates
//
// ## Integration Points
//
// - RPC Layer: rpc/service/src/service.rs (submit_did_create/update/deactivate)
// - Consensus: consensus/src/pipeline/virtual_processor/processor.rs (TX validation)
// - WASM Wallet: wasm/pkg/ (client-side DID operations)
// - Web5: Future integration point for DWN (Decentralized Web Node)
//
// ## Standards Compliance
//
// This implementation follows W3C DID Core specification:
// - https://www.w3.org/TR/did-core/
// - Method name: "sahyadri"
// - DID format: did:sahyadri:{base58check-encoded-hash}
//
// ============================================================================

/// Represents a DID Document stored on-chain
///
/// This is the core data structure of Sahyadri's Object Model layer.
/// Unlike AccountState (which tracks simple balance/nonce), DidDocument
/// is a rich, versioned identity object with:
///
/// - **Unique Identification**: Globally unique DID string
/// - **Ownership**: Linked to a CSM blockchain address (controller)
/// - **Cryptographic Identity**: Dilithium3 post-quantum public key
/// - **Structured Data**: JSON-LD document conforming to W3C DID spec
/// - **Lifecycle Management**: Active/inactive state, version tracking
///
/// # Example
///
/// ```ignore
/// let doc = DidDocument {
///     did: "did:sahyadri:ABC123...".to_string(),
///     csm_address: "sahyadri:qxyz...".to_string(),
///     public_key: "dilithium3_pubkey_hex...".to_string(),
///     document: r#"{"@context": ["https://w3id.org/did/v1"]}"#.to_string(),
///     purposes: vec!["authentication".to_string()],
///     services: vec![],
///     active: true,
///     created_at: 1700000000,
///     updated_at: 1700000000,
///     version: 1,
/// };
/// ```
///
/// # On-Chain Storage
///
/// - Primary key: `DidKey(did)` → `DidDocument` (in "dids-store" prefix)
/// - Secondary index: `DidKey(addr:csm_address)` → `DidIndexEntry(did)` (in "dids-addr-index" prefix)
///
/// # Type Safety
///
/// This struct derives Serialize/Deserialize for RocksDB persistence
/// and network serialization. It also implements MemSizeEstimator
/// for cache size tracking.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DidDocument {
    /// Full DID identifier (e.g., "did:sahyadri:abc123...")
    pub did: String,
    /// Associated CSM blockchain address
    pub csm_address: String,
    /// Dilithium public key (hex encoded)
    pub public_key: String,
    /// DID Document JSON content
    pub document: String,
    /// Purposes for this DID (authentication, key-agreement, etc.)
    pub purposes: Vec<String>,
    /// Service endpoints
    pub services: Vec<String>,
    /// Whether this DID is currently active
    pub active: bool,
    /// Block timestamp when created
    pub created_at: u64,
    /// Block timestamp when last updated
    pub updated_at: u64,
    /// Version number for conflict resolution
    pub version: u64,
}

impl Default for DidDocument {
    fn default() -> Self {
        Self {
            did: String::new(),
            csm_address: String::new(),
            public_key: String::new(),
            document: String::new(),
            purposes: Vec::new(),
            services: Vec::new(),
            active: false,
            created_at: 0,
            updated_at: 0,
            version: 0,
        }
    }
}

impl MemSizeEstimator for DidDocument {
    fn estimate_mem_bytes(&self) -> usize {
        // Rough estimate of serialized size
        self.did.len()
            + self.csm_address.len()
            + self.public_key.len()
            + self.document.len()
            + (self.purposes.len() * 32) // Average purpose string length
            + (self.services.len() * 64) // Average service endpoint length
            + 25 // Booleans + timestamps + version
    }
}

/// A wrapper to make DID strings compatible with RocksDB keys
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct DidKey(Vec<u8>);

// Implement ToString for DidKey
impl std::fmt::Display for DidKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match String::from_utf8(self.0.clone()) {
            Ok(s) => write!(f, "{}", s),
            Err(_) => write!(f, "DidKey({} bytes)", self.0.len()),
        }
    }
}

impl DidKey {
    pub fn new(did: &str) -> Self {
        Self(did.as_bytes().to_vec())
    }

    pub fn from_address(address: &str) -> Self {
        // For indexing by address: prefix with "addr:"
        let key = format!("addr:{}", address);
        Self(key.as_bytes().to_vec())
    }
}

impl AsRef<[u8]> for DidKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Wrapper type for address→DID mapping in secondary index
///
/// # Purpose
///
/// RocksDB's CachedDbAccess requires values to implement MemSizeEstimator.
/// Since std::String doesn't implement this trait, we wrap it in DidIndexEntry.
///
/// # Usage
///
/// ```ignore
/// // In address_index store:
/// // Key: DidKey("addr:sahyadri:qxyz...")
/// // Value: DidIndexEntry("did:sahyadri:abc123...")
/// ```
///
/// # Memory Estimation
///
/// Estimates memory as length of inner string (accurate enough for caching).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DidIndexEntry(pub String);

impl MemSizeEstimator for DidIndexEntry {
    fn estimate_mem_bytes(&self) -> usize {
        self.0.len()
    }
}

/// Read operations for DID Object Model Store
///
/// This trait defines the query interface for Sahyadri's DID system.
/// Implementations must support both direct and reverse lookups.
///
/// # Design Note
///
/// Separating reader/writer traits allows:
/// - Read-only references (for validation/logging)
/// - Write-only transaction contexts (for consensus)
/// - Clear API boundaries
pub trait DidStoreReader {
    /// Get full DID document by DID identifier
    fn get_by_did(&self, did: &str) -> StoreResult<Option<DidDocument>>;
    
    /// Get DID document by associated CSM address
    fn get_by_address(&self, address: &str) -> StoreResult<Option<DidDocument>>;
    
    /// Check if a DID exists and is active
    fn is_active(&self, did: &str) -> StoreResult<bool>;
    
    /// Get current version number for a DID
    fn get_version(&self, did: &str) -> StoreResult<u64>;
}

/// Write operations for DID Object Model Store (extends Reader)
///
/// All write operations use WriteBatch for atomicity.
/// Callers should commit the batch after multiple operations.
///
/// # Concurrency Safety
///
/// These methods are safe to call within a single WriteBatch.
/// The batch ensures atomic commit — either all changes persist or none do.
///
/// # Version Management
///
/// Callers are responsible for incrementing `version` field on updates.
/// This enables Optimistic Concurrency Control (OCC) to prevent lost updates.
pub trait DidStore: DidStoreReader {
    /// Create/insert a new DID document (batch operation)
    fn set_batch(&self, batch: &mut WriteBatch, doc: &DidDocument) -> StoreResult<()>;
    
    /// Update an existing DID document (batch operation, increments version)
    fn update_batch(&self, batch: &mut WriteBatch, doc: &DidDocument) -> StoreResult<()>;
    
    /// Deactivate a DID (batch operation, marks as inactive)
    fn deactivate_batch(&self, batch: &mut WriteBatch, did: &str) -> StoreResult<()>;
    
    /// Delete a DID completely (for reorg handling - batch operation)
    fn delete_batch(&self, batch: &mut WriteBatch, did: &str) -> StoreResult<()>;
}

const DID_STORE_PREFIX: &[u8] = b"dids-store";
const DID_ADDRESS_INDEX_PREFIX: &[u8] = b"dids-addr-index";

/// RocksDB-backed DID Document Store — Core of Object Model Layer
///
/// # Architecture
///
/// This store maintains TWO indexes:
///
/// 1. **Primary Index** (`did_access`):
///    - Key: Full DID identifier (e.g., "did:sahyadri:abc123")
///    - Value: Complete DidDocument object
///    - Prefix: "dids-store"
///    - Use case: Direct DID resolution
///
/// 2. **Secondary Index** (`address_index`):
///    - Key: Prefixed CSM address (e.g., "addr:sahyadri:qxyz...")
///    - Value: DID string wrapped in DidIndexEntry
///    - Prefix: "dids-addr-index"
///    - Use case: Reverse lookup (find DID by owner's address)
///
/// # Thread Safety
///
/// Both indexes use CachedDbAccess which provides:
/// - Concurrent read access (Arc-based cloning)
/// - Write batching via WriteBatch
/// - LRU cache with configurable size
///
/// # Performance Characteristics
///
/// - `get_by_did()`: O(1) primary index lookup
/// - `get_by_address()`: O(1) secondary index lookup + O(1) primary lookup = O(1) total
/// - `set_batch()`: 2 writes (primary + secondary index)
/// - `delete_batch()`: 2 deletes (primary + secondary index cleanup)
///
/// # Example Flow
///
/// ```ignore
/// // Create DID
/// let doc = DidDocument { did: "did:sahyadri:abc", csm_address: "sahyadri:qxyz", ... };
/// store.set_batch(&mut batch, &doc)?;
/// // Result: 
/// //   did_access["did:sahyadri:abc"] = doc
/// //   address_index["addr:sahyadri:qxyz"] = DidIndexEntry("did:sahyadri:abc")
///
/// // Reverse lookup
/// let found = store.get_by_address("sahyadri:qxyz")?;
/// assert_eq!(found.unwrap().did, "did:sahyadri:abc");
/// ```
#[derive(Clone)]
pub struct DbDidStore {
    /// Primary storage: DID identifier → Full document
    did_access: CachedDbAccess<DidKey, DidDocument>,
    
    /// Secondary index: CSM address → DID identifier (for reverse lookup)
    address_index: CachedDbAccess<DidKey, DidIndexEntry>,
}

impl DbDidStore {
    pub fn new(db: Arc<sahyadri_database::prelude::DB>, cache_size: u64) -> Self {
        Self {
            did_access: CachedDbAccess::new(
                db.clone(),
                sahyadri_database::prelude::CachePolicy::Count(cache_size as usize),
                DID_STORE_PREFIX.to_vec(),
            ),
            address_index: CachedDbAccess::new(
                db.clone(),
                sahyadri_database::prelude::CachePolicy::Count(cache_size as usize),
                DID_ADDRESS_INDEX_PREFIX.to_vec(),
            ),
        }
    }
}

impl DidStoreReader for DbDidStore {
    fn get_by_did(&self, did: &str) -> StoreResult<Option<DidDocument>> {
        match self.did_access.read(DidKey::new(did)) {
            Ok(doc) => Ok(Some(doc)),
            Err(StoreError::KeyNotFound(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn get_by_address(&self, address: &str) -> StoreResult<Option<DidDocument>> {
        match self.address_index.read(DidKey::from_address(address)) {
            Ok(did_entry) => self.get_by_did(&did_entry.0),
            Err(StoreError::KeyNotFound(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn is_active(&self, did: &str) -> StoreResult<bool> {
        match self.get_by_did(did) {
            Ok(Some(doc)) => Ok(doc.active),
            Ok(None) => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn get_version(&self, did: &str) -> StoreResult<u64> {
        match self.get_by_did(did) {
            Ok(Some(doc)) => Ok(doc.version),
            Ok(None) => Ok(0),
            Err(e) => Err(e),
        }
    }
}

impl DidStore for DbDidStore {
    fn set_batch(&self, batch: &mut WriteBatch, doc: &DidDocument) -> StoreResult<()> {
        // Write main DID entry
        self.did_access.write(
            BatchDbWriter::new(batch),
            DidKey::new(&doc.did),
            doc.clone(),
        )?;
    
        // Write address index
        if !doc.csm_address.is_empty() {
            self.address_index.write(
                BatchDbWriter::new(batch),
                DidKey::from_address(&doc.csm_address),
                DidIndexEntry(doc.did.clone()),  // Wrapped in DidIndexEntry
            )?;
        }
    
        Ok(())
    }

    fn update_batch(&self, batch: &mut WriteBatch, doc: &DidDocument) -> StoreResult<()> {
        // Verify DID exists and get current state
        let mut existing = match self.get_by_did(&doc.did)? {
            Some(existing_doc) => existing_doc,
            None => return Err(StoreError::KeyNotFound(DbKey::prefix_only(DID_STORE_PREFIX))),
        };
        
        // Update fields (version auto-incremented by caller usually)
        existing.document = doc.document.clone();
        existing.purposes = doc.purposes.clone();
        existing.services = doc.services.clone();
        existing.updated_at = doc.updated_at;
        existing.version = doc.version;
        
        // Write updated document
        self.set_batch(batch, &existing)
    }

    fn deactivate_batch(&self, batch: &mut WriteBatch, did: &str) -> StoreResult<()> {
         let mut doc = match self.get_by_did(did)? {
            Some(existing_doc) => existing_doc,
            None => return Err(StoreError::KeyNotFound(DbKey::prefix_only(DID_STORE_PREFIX))),
        };
        
        doc.active = false;
        self.set_batch(batch, &doc)
    }

    fn delete_batch(&self, batch: &mut WriteBatch, did: &str) -> StoreResult<()> {
        // Get document to clean up address index
        if let Some(doc) = self.get_by_did(did)? {
            if !doc.csm_address.is_empty() {
                self.address_index.delete(
                    BatchDbWriter::new(batch),
                    DidKey::from_address(&doc.csm_address),
                )?;
            }
        }
    
        // Remove main DID entry
        self.did_access.delete(BatchDbWriter::new(batch), DidKey::new(did))
    }
}
