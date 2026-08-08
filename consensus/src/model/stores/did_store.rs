use sahyadri_database::prelude::DbKey;
use rocksdb::WriteBatch;
use sahyadri_database::prelude::{BatchDbWriter, CachedDbAccess, StoreError, StoreResult};
use sahyadri_utils::mem_size::MemSizeEstimator;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Represents a DID Document stored on-chain
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

impl std::fmt::Display for DidKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match String::from_utf8(self.0.clone()) {
            Ok(s) => write!(f, "DidKey({})", s),
            Err(_) => write!(f, "DidKey({} bytes)", self.0.len()),
        }
    }
}

/// Trait defining read operations for DID Store
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

/// Trait defining write operations for DID Store
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

#[derive(Clone)]
pub struct DbDidStore {
    /// Main storage: DID → DidDocument
    did_access: CachedDbAccess<DidKey, DidDocument>,
    // Note: We'll use a simple approach without address index for now,
    // or implement it differently. For now, comment out or remove:
    // address_index: CachedDbAccess<DidKey, String>,
}

impl DbDidStore {
    pub fn new(db: Arc<sahyadri_database::prelude::DB>, cache_size: u64) -> Self {
        Self {
            did_access: CachedDbAccess::new(
                db.clone(),
                sahyadri_database::prelude::CachePolicy::Count(cache_size as usize),
                DID_STORE_PREFIX.to_vec(),
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

    fn get_by_address(&self, _address: &str) -> StoreResult<Option<DidDocument>> {
        // TODO: Implement address-based lookup when address_index is added
        Ok(None)
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
        
        // TODO: Update address index when address_index field is re-added
        // self.address_index.write(
        //     BatchDbWriter::new(batch),
        //     DidKey::from_address(&doc.csm_address),
        //     doc.did.clone(),
        // )?;
        
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
       // if let Some(doc) = self.get_by_did(did)? {
            // Remove from address index
            // TODO: Remove from address index when field is re-added
         //   self.address_index.delete(BatchDbWriter::new(batch), DidKey::from_address(&doc.csm_address))?;
        // }
        
        // Remove main DID entry
        self.did_access.delete(BatchDbWriter::new(batch), DidKey::new(did))
    }
}
