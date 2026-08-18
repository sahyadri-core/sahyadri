// ============================================================================
// CREST OPERATIONS — Business Logic Layer for Sahyadri Identity
// ============================================================================
//
// This module provides HIGH-LEVEL operations on top of the raw DidStore.
// All business logic, validation, and orchestration lives here.
//
// ARCHITECTURE:
//
//   WASM Wallet / RPC Caller
//       ↓
//   crest_operations.rs 
//       ↓
//   crest_model.rs       (Types & Structs)
//       ↓
//   did_store.rs         (Database CRUD)
//       ↓
//   RocksDB              (Persistence)
//
// RESPONSIBILITIES:
// - Create DID identities with validation
// - Resolve DIDs (by ID or address)
// - Update DID documents (with version control)
// - Deactivate DIDs (with authorization)
// - Signature verification orchestration
//
// ============================================================================

use super::crest_model::*;
use super::did_store::{DidStore, DidStoreReader, DidDocument};
use rocksdb::WriteBatch;
use std::sync::Arc;

// ===== ERROR TYPES =====

/// High-level operation errors
#[derive(Debug, Clone)]
pub enum CrestOpError {
    /// DID not found in store
    NotFound(String),
    /// DID already exists (conflict on create)
    AlreadyExists(String),
    /// Validation failed
    Validation(String),
    /// Signature verification failed
    InvalidSignature(String),
    /// Version conflict (optimistic concurrency)
    VersionConflict { expected: u64, actual: u64 },
    /// Identity is deactivated
    Deactivated(String),
    /// Not authorized to perform action
    NotAuthorized(String),
    /// Storage backend error
    StorageError(String),
    /// Transaction building error
    TransactionError(String),
}

impl std::fmt::Display for CrestOpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(id) => write!(f, "DID not found: {}", id),
            Self::AlreadyExists(id) => write!(f, "DID already exists: {}", id),
            Self::Validation(msg) => write!(f, "Validation failed: {}", msg),
            Self::InvalidSignature(msg) => write!(f, "Invalid signature: {}", msg),
            Self::VersionConflict { expected, actual } => {
                write!(f, "Version conflict: expected {}, got {}", expected, actual)
            }
            Self::Deactivated(id) => write!(f, "DID is deactivated: {}", id),
            Self::NotAuthorized(msg) => write!(f, "Not authorized: {}", msg),
            Self::StorageError(msg) => write!(f, "Storage error: {}", msg),
            Self::TransactionError(msg) => write!(f, "Transaction error: {}", msg),
        }
    }
}

impl std::error::Error for CrestOpError {}

/// Operation result type
pub type CrestOpResult<T> = Result<T, CrestOpError>;

// Convert from store errors
impl From<sahyadri_database::prelude::StoreError> for CrestOpError {
    fn from(err: sahyadri_database::prelude::StoreError) -> Self {
        Self::StorageError(err.to_string())
    }
}

// Convert from model errors
impl From<CrestError> for CrestOpError {
    fn from(err: CrestError) -> Self {
        Self::Validation(err.to_string())
    }
}

// ===== REQUEST/RESPONSE TYPES =====

/// Request to create a new DID identity
#[derive(Clone, Debug)]
pub struct CreateDidRequest {
    /// Full DID identifier to create
    pub did: String,
    
    /// Controller's CSM blockchain address (owner)
    pub csm_address: String,
    
    /// Dilithium3 public key in hex format
    pub public_key_hex: String,
    
    /// Full DID document JSON-LD content
    pub document: String,
    
    /// Dilithium3 signature proving ownership of csm_address
    pub signature: Vec<u8>,
    
    /// Optional initial services to register
    pub services: Option<Vec<CrestService>>,
    
    /// Optional initial verification methods
    pub authentication_methods: Option<Vec<CrestVerificationMethod>>,
}

/// Response after successful DID creation
#[derive(Clone, Debug)]
pub struct CreateDidResponse {
    /// The created DID identifier
    pub did: String,
    
    /// Transaction ID that committed this DID to chain
    pub transaction_id: String,
    
    /// Block timestamp when created
    pub created_at: u64,
    
    /// Initial version number (always 1)
    pub version: u64,
}

/// Request to update an existing DID
#[derive(Clone, Debug)]
pub struct UpdateDidRequest {
    /// DID to update
    pub did: String,
    
    /// New version number (must be current + 1)
    pub new_version: u64,
    
    /// Services to add
    pub add_services: Option<Vec<CrestService>>,
    
    /// Services to remove (by fragment ID)
    pub remove_services: Option<Vec<String>>,
    
    /// Verification methods to add
    pub add_authentication: Option<Vec<CrestVerificationMethod>>,
    
    /// New controller (optional transfer)
    pub set_controller: Option<String>,
    
    /// Signature authorizing this update
    pub signature: Vec<u8>,
}

/// Request to deactivate a DID
#[derive(Clone, Debug)]
pub struct DeactivateDidRequest {
    /// DID to deactivate
    pub did: String,
    
    /// Signature authorizing deactivation
    pub signature: Vec<u8>,
    
    /// Reason for deactivation (optional, for audit trail)
    pub reason: Option<String>,
}

// ===== MAIN SERVICE STRUCT =====

/// Crest Operations Service
///
/// High-level interface for all DID operations.
/// Wraps the raw DidStore with business logic.
///
/// # Thread Safety
///
/// This service is designed to be wrapped in Arc<T> and shared across
/// async tasks. All operations use batch writes for atomicity.
///
/// # Example
///
/// ```ignore
/// let store = DbDidStore::new(db, cache_size);
/// let ops = CrestOperations::new(store);
///
/// // Create DID
/// let response = ops.create_identity(CreateDidRequest { ... }).await?;
///
/// // Resolve DID
/// let doc = ops.resolve("did:sahyadri:abc")?;
/// ```
pub struct CrestOperations<S: DidStore + DidStoreReader> {
    /// Underlying data store
    store: S,
}

impl<S: DidStore + DidStoreReader> CrestOperations<S> {
    /// Create new operations instance
    pub fn new(store: S) -> Self {
        Self { store }
    }
    
    // ===== IDENTITY LIFECYCLE OPERATIONS =====
    
    /// Create a new DID identity
    ///
    /// # Arguments
    ///
    /// * `request` - Creation request with all required fields
    ///
    /// # Returns
    ///
    /// * `Ok(CreateDidResponse)` - Successfully created identity
    /// * `Err(CrestOpError)` - Creation failed (validation, conflict, etc.)
    ///
    /// # Workflow
    ///
    /// 1. Validate request fields (format, lengths)
    /// 2. Check if DID already exists (conflict prevention)
    /// 3. Build CrestDocument from request
    /// 4. Validate document structure
    /// 5. Verify signature (proves ownership of csm_address)
    /// 6. Convert to legacy format for storage
    /// 7. Write to store via batch operation
    /// 8. Return response with TX details
    ///
    /// # Example
    ///
    /// ```ignore
    /// let request = CreateDidRequest {
    ///     did: "did:sahyadri:WxyzAbc123".to_string(),
    ///     csm_address: "sahyadri:qrp8jXhK7LmNoPqRsTuVwXyZ".to_string(),
    ///     public_key_hex: "dilithium3_pubkey_hex...".to_string(),
    ///     document: r#"{"@context": ["https://w3id.org/did/v1"]}"#.to_string(),
    ///     signature: dilithium_signature_bytes.to_vec(),
    ///     services: None,
    ///     authentication_methods: None,
    /// };
    ///
    /// let result = ops.create_identity(request)?;
    /// println!("Created DID: {} in TX: {}", result.did, result.transaction_id);
    /// ```
    pub fn create_identity(
        &self,
        request: CreateDidRequest,
    ) -> CrestOpResult<(CrestDocument, DidDocument)> {
        // Step 1: Validate DID format
        self.validate_did_format(&request.did)?;
        
        // Step 2: Check for conflicts (must not already exist)
        if let Some(existing) = self.store.get_by_did(&request.did)? {
            if existing.active {
                return Err(CrestOpError::AlreadyExists(request.did));
            }
            // Allow re-creation if deactivated? Or require new DID?
            // For now, reject even if deactivated (create new DID instead)
            return Err(CrestOpError::Deactivated(format!(
                "DID {} exists but is deactivated. Use a new DID.",
                request.did
            )));
        }
        
        // Step 3: Check address doesn't already have active DID
        if let Some(existing_by_addr) = self.store.get_by_address(&request.csm_address)? {
            if existing_by_addr.active {
                return Err(CrestOpError::Validation(format!(
                    "Address {} already has an active DID: {}",
                    request.csm_address, existing_by_addr.did
                )));
            }
        }
        
        // Step 4: Build CrestDocument
        let mut crest_doc = CrestDocument::new(
            &request.did,
            &request.csm_address,
            &request.public_key_hex,
        );
        
        // Set custom document content if provided
        if !request.document.is_empty() && request.document != "{}" {
        }
        
        // Add optional services
        if let Some(services) = request.services {
            for svc in services {
                crest_doc.add_service(svc)?;
            }
        }
        
        // Add optional authentication methods
        if let Some(auth_methods) = request.authentication_methods {
            for method in auth_methods {
                crest_doc.add_authentication(method)?;
            }
        }
        
        // Step 5: Validate complete document
        crest_doc.validate().map_err(|e| CrestOpError::Validation(e.to_string()))?;
        
        // Step 6: Verify signature (proves ownership of csm_address)
        // TODO: Implement actual Dilithium3 signature verification
        // self.verify_creation_signature(&request)?;
        if request.signature.is_empty() {
            return Err(CrestOpError::InvalidSignature(
                "Signature cannot be empty".to_string()
            ));
        }
        
        // Step 7: Convert to legacy format for DB storage
        let legacy_doc = crest_doc.to_legacy();
        
        // Step 8: Write to store
        // Note: In production, this would be part of a transaction
        // For now, direct write (caller manages batching)
        let mut batch = WriteBatch::default();
        self.store.set_batch(&mut batch, &legacy_doc)?;
        
        // In real implementation, commit batch here or return it to caller
        
        Ok((crest_doc, legacy_doc))
    }
    
    /// Resolve DID by identifier → Full CrestDocument
    ///
    /// # Arguments
    ///
    /// * `did` - Full DID string (e.g., "did:sahyadri:Wxyz...")
    ///
    /// # Returns
    ///
    /// * `Ok(CrestDocument)` - Fully populated identity object
    /// * `Err(CrestOpError)` - Resolution failed
    pub fn resolve(&self, did: &str) -> CrestOpResult<CrestDocument> {
        // Lookup in store
        let legacy = self.store.get_by_did(did)?
            .ok_or_else(|| CrestOpError::NotFound(did.to_string()))?;
        
        // Check not deactivated
        if !legacy.active {
            return Err(CrestOpError::Deactivated(did.to_string()));
        }
        
        // Convert to rich CrestDocument
        let crest = CrestDocument::from_legacy(&legacy);
        
        Ok(crest)
    }
    
    /// Resolve DID by CSM address (reverse lookup)
    ///
    /// Useful for: "Show me the DID for this wallet address"
    ///
    /// # Arguments
    ///
    /// * `address` - CSM blockchain address
    ///
    /// # Returns
    ///
    /// * `Ok(Option<CrestDocument>)` - Identity if found, None if no DID for address
    pub fn resolve_by_address(&self, address: &str) -> CrestOpResult<Option<CrestDocument>> {
        match self.store.get_by_address(address)? {
            Some(legacy) => {
                if !legacy.active {
                    return Ok(None); // Deactivated, treat as not found
                }
                Ok(Some(CrestDocument::from_legacy(&legacy)))
            }
            None => Ok(None),
        }
    }
    
    /// Update an existing DID document
    ///
    /// Supports incremental updates (add/remove services, methods, etc.)
    /// Uses optimistic concurrency via version numbers.
    ///
    /// # Arguments
    ///
    /// * `request` - Update request with changes and authorization
    ///
    /// # Returns
    ///
    /// * `Ok((CrestDocument, DidDocument))` - Updated identity (both formats)
    /// * `Err(CrestOpError)` - Update failed
    ///
    /// # Optimistic Concurrency
    ///
    /// Caller must provide `new_version == current_version + 1`.
    /// If versions don't match, returns `VersionConflict` error.
    pub fn update_identity(
        &self,
        request: UpdateDidRequest,
    ) -> CrestOpResult<(CrestDocument, DidDocument)> {
        // Step 1: Get current state
        let current_legacy = self.store.get_by_did(&request.did)?
            .ok_or_else(|| CrestOpError::NotFound(request.did.clone()))?;
        
        if !current_legacy.active {
            return Err(CrestOpError::Deactivated(request.did));
        }
        
        // Step 2: Check version (optimistic concurrency)
        if request.new_version != current_legacy.version + 1 {
            return Err(CrestOpError::VersionConflict {
                expected: current_legacy.version + 1,
                actual: request.new_version,
            });
        }
        
        // Step 3: Convert to CrestDocument for mutation
        let mut crest = CrestDocument::from_legacy(&current_legacy);
        
        // Step 4: Apply updates
        
        // Add services
        if let Some(new_services) = request.add_services {
            for svc in new_services {
                crest.add_service(svc)?;
            }
        }
        
        // Remove services
        if let Some(remove_ids) = request.remove_services {
            for id in remove_ids {
                crest.remove_service(&id);
                // Note: silent fail if not found (idempotent)
            }
        }
        
        // Add authentication methods
        if let Some(new_auth) = request.add_authentication {
            for method in new_auth {
                crest.add_authentication(method)?;
            }
        }
        
        // Set controller (transfer ownership)
        if let Some(new_controller) = request.set_controller {
            crest.set_controller(&new_controller);
        }
        
        // Step 5: Bump version
        let _new_version = crest.bump_version(); // Should match request.new_version
        
        // Step 6: Validate updated document
        crest.validate().map_err(|e| CrestOpError::Validation(e.to_string()))?;
        
        // Step 7: Verify signature (authorizes the update)
        // TODO: Verify signer is controller or has delegation
        if request.signature.is_empty() {
            return Err(CrestOpError::InvalidSignature(
                "Update requires signature".to_string()
            ));
        }
        
        // Step 8: Convert back to legacy format
        let updated_legacy = crest.to_legacy();
        
        // Step 9: Write to store
        let mut batch = WriteBatch::default();
        self.store.update_batch(&mut batch, &updated_legacy)?;
        
        Ok((crest, updated_legacy))
    }
    
    /// Deactivate a DID identity
    ///
    /// ⚠️ **IRREVERSIBLE OPERATION**
    ///
    /// Deactivated DIDs cannot be reactivated.
    /// A new DID must be created instead.
    ///
    /// # Arguments
    ///
    /// * `request` - Deactivation request with authorization
    ///
    /// # Returns
    ///
    /// * `Ok(DidDocument)` - Final state before deactivation
    /// * `Err(CrestOpError)` - Deactivation failed
    pub fn deactivate_identity(
        &self,
        request: DeactivateDidRequest,
    ) -> CrestOpResult<DidDocument> {
        // Step 1: Get current state
        let current = self.store.get_by_did(&request.did)?
            .ok_or_else(|| CrestOpError::NotFound(request.did.clone()))?;
        
        if !current.active {
            return Err(CrestOpError::Deactivated(request.did));
        }
        
        // Step 2: Verify signature (only controller can deactivate)
        // TODO: Verify signature matches controller's key
        if request.signature.is_empty() {
            return Err(CrestOpError::InvalidSignature(
                "Deactivation requires signature".to_string()
            ));
        }
        
        // Step 3: Perform deactivation
        let mut batch = WriteBatch::default();
        self.store.deactivate_batch(&mut batch, &request.did)?;
        
        // Log reason if provided (for audit trail)
        if let Some(reason) = request.reason {
            eprintln!("[CREST] Deactivating DID {}: reason={}", request.did, reason);
        }
        
        Ok(current) // Return pre-deactivation state for confirmation
    }
    
    // ===== QUERY OPERATIONS =====
    
    /// Check if a DID exists and is active
    pub fn is_active(&self, did: &str) -> CrestOpResult<bool> {
        match self.store.get_by_did(did)? {
            Some(doc) => Ok(doc.active),
            None => Ok(false), // Non-existent = not active
        }
    }
    
    /// Get current version number for a DID
    pub fn get_version(&self, did: &str) -> CrestOpResult<u64> {
        self.store.get_version(did)
            .map_err(|e| CrestOpError::StorageError(e.to_string()))
    }
    
    /// List all DIDs owned by an address
    ///
    /// Note: Currently only returns first active DID per address
    /// (address_index maps to single DID). Future: support multiple.
    pub fn list_by_address(&self, address: &str) -> CrestOpResult<Option<String>> {
        match self.store.get_by_address(address)? {
            Some(doc) => {
                if doc.active {
                    Ok(Some(doc.did))
                } else {
                    Ok(None)
                }
            }
            None => Ok(None),
        }
    }
    
    // ===== BATCH OPERATIONS (For Transaction Integration) =====
    
    /// Prepare DID creation as part of larger transaction
    ///
    /// Instead of writing immediately, adds to existing WriteBatch.
    /// Caller commits batch atomically with other operations.
    pub fn prepare_create_in_batch(
        &self,
        batch: &mut WriteBatch,
        request: CreateDidRequest,
    ) -> CrestOpResult<CrestDocument> {
        // Reuse creation logic but write to provided batch instead
        let (crest_doc, legacy_doc) = self.create_identity(request)?;
        
        // Write to provided batch (not our own internal batch)
        self.store.set_batch(batch, &legacy_doc)?;
        
        Ok(crest_doc)
    }
    
    /// Prepare DID update as part of larger transaction
    pub fn prepare_update_in_batch(
        &self,
        batch: &mut WriteBatch,
        request: UpdateDidRequest,
    ) -> CrestOpResult<CrestDocument> {
        let (crest_doc, legacy_doc) = self.update_identity(request)?;
        
        self.store.update_batch(batch, &legacy_doc)?;
        
        Ok(crest_doc)
    }
    
    /// Prepare DID deactivation as part of larger transaction
    pub fn prepare_deactivate_in_batch(
        &self,
        batch: &mut WriteBatch,
        request: DeactivateDidRequest,
    ) -> CrestOpResult<()> {
        self.deactivate_identity(request.clone())?; // Validates
        
        // Actual write happens in batch
        self.store.deactivate_batch(batch, &request.did)?;
        
        Ok(())
    }
    
    // ===== PRIVATE HELPERS =====
    
    /// Validate DID format string
    fn validate_did_format(&self, did: &str) -> CrestOpResult<()> {
        if did.is_empty() {
            return Err(CrestOpError::Validation("DID cannot be empty".into()));
        }
        
        if !did.starts_with("did:sahyadri:") {
            return Err(CrestOpError::Validation(
                format!("DID must start with 'did:sahyadri:', got: {}", 
                        &did[..did.len().min(20)])
            ));
        }
        
        // Check minimum length (method:hash must have substance)
        if did.len() < 20 { // "did:sahyadri:" (14) + at least 6 chars hash
            return Err(CrestOpError::Validation(
                "DID identifier too short".into()
            ));
        }
        
        // TODO: Validate base58check encoding of hash portion
        // let hash_part = did.trim_start_matches("did:sahyadri:");
        // bs58::decode(hash_part)?;
        
        Ok(())
    }
    
    /// Verify signature for DID creation
    ///
    /// Checks that `signature` is valid for `csm_address` using Dilithium3
    #[allow(dead_code)]
    fn verify_creation_signature(&self, _request: &CreateDidRequest) -> CrestOpResult<()> {
        // TODO: Implement when Dilithium3 verify is wired up
        // Expected flow:
        // 1. Get public key bytes from request.public_key_hex
        // 2. Construct message: "DID_CREATE" + did + csm_address + timestamp
        // 3. Call sahyadri_dilithium::verify(signature, message, pubkey)
        // 4. Return Ok(()) if valid, Err if invalid
        
        // Placeholder: Assume valid for now
        Ok(())
    }
    
    /// Verify signature for DID update/deactivation
    #[allow(dead_code)]
    fn verify_update_signature(
        &self,
        _current_did: &DidDocument,
        _signature: &[u8],
        _expected_version: u64,
    ) -> CrestOpResult<()> {
        // TODO: Implement when ready
        // Must verify signer is:
        // - The controller DID itself, OR
        // - A delegated authority (if capability_delegation VMs exist)
        Ok(())
    }
}

// ===== CONVENIENCE WRAPPER FOR ARC<S> =====

/// Thread-safe shared operations handle
///
/// Wraps CrestOperations in Arc for sharing across async tasks
pub type SharedCrestOperations<S> = Arc<CrestOperations<S>>;

impl<S: DidStore + DidStoreReader + Sync + Send> CrestOperations<S> {
    /// Create Arc-wrapped operations (for async/concurrent use)
    pub fn shared(store: S) -> SharedCrestOperations<S> {
        Arc::new(Self::new(store))
    }
}

// ===== TESTS =====

#[cfg(test)]
mod tests {
    use super::*;
    
    // Mock store for testing (in real impl, would use mock crate or test double)
    struct MockDidStore {
        docs: std::cell::RefCell<std::collections::HashMap<String, DidDocument>>,
    }
    
    impl MockDidStore {
        fn new() -> Self {
            Self {
                docs: std::cell::RefCell::new(std::collections::HashMap::new()),
            }
        }
    }
    
    impl DidStoreReader for MockDidStore {
        fn get_by_did(&self, did: &str) -> Result<Option<DidDocument>, sahyadri_database::prelude::StoreError> {
            Ok(self.docs.borrow().get(did).cloned())
        }
        
        fn get_by_address(&self, address: &str) -> Result<Option<DidDocument>, sahyadri_database::prelude::StoreError> {
            self.docs.borrow()
                .values()
                .find(|d| d.csm_address == address)
                .cloned()
                .map(Some)
                .unwrap_or(Ok(None))
        }
        
        fn is_active(&self, did: &str) -> Result<bool, sahyadri_database::prelude::StoreError> {
            Ok(self.docs.borrow()
                .get(did)
                .map(|d| d.active)
                .unwrap_or(false))
        }
        
        fn get_version(&self, did: &str) -> Result<u64, sahyadri_database::prelude::StoreError> {
            Ok(self.docs.borrow()
                .get(did)
                .map(|d| d.version)
                .unwrap_or(0))
        }
    }
    
    impl DidStore for MockDidStore {
        fn set_batch(&self, _batch: &mut WriteBatch, doc: &DidDocument) -> Result<(), sahyadri_database::prelude::StoreError> {
            self.docs.borrow_mut().insert(doc.did.clone(), doc.clone());
            Ok(())
        }
        
        fn update_batch(&self, _batch: &mut WriteBatch, doc: &DidDocument) -> Result<(), sahyadri_database::prelude::StoreError> {
            self.docs.borrow_mut().insert(doc.did.clone(), doc.clone());
            Ok(())
        }
        
        fn deactivate_batch(&self, _batch: &mut WriteBatch, did: &str) -> Result<(), sahyadri_database::prelude::StoreError> {
            if let Some(mut doc) = self.docs.borrow_mut().get_mut(did) {
                doc.active = false;
            }
            Ok(())
        }
        
        fn delete_batch(&self, _batch: &mut WriteBatch, did: &str) -> Result<(), sahyadri_database::prelude::StoreError> {
            self.docs.borrow_mut().remove(did);
            Ok(())
        }
    }
    
    #[test]
    fn test_create_and_resolve_did() {
        let store = MockDidStore::new();
        let ops = CrestOperations::new(store);
        
        let request = CreateDidRequest {
            did: "did:sahyadri:test123".to_string(),
            csm_address: "sahyadri:qtest".to_string(),
            public_key_hex: "test_pubkey_hex_12345".to_string(),
            document: "{}".to_string(),
            signature: vec![1, 2, 3, 4], // Fake sig for test
            services: None,
            authentication_methods: None,
        };
        
        let (crest, _legacy) = ops.create_identity(request).expect("Create should succeed");
        
        assert_eq!(crest.id, "did:sahadri:test123");
        assert_eq!(crest.csm_address, "sahyadri:qtest");
        assert!(crest.active());
        assert_eq!(crest.version_id, 1);
        
        // Resolve should work
        let resolved = ops.resolve("did:sahadri:test123").expect("Resolve should succeed");
        assert_eq!(resolved.id, "did:sahadri:test123");
    }
    
    #[test]
    fn test_duplicate_did_rejected() {
        let store = MockDidStore::new();
        let ops = CrestOperations::new(store);
        
        let request = CreateDidRequest {
            did: "did:sahyadri:duplicate_test".to_string(),
            csm_address: "sahyadri:qdup".to_string(),
            public_key_hex: "pubkey".to_string(),
            document: "{}".to_string(),
            signature: vec![1, 2, 3],
            services: None,
            authentication_methods: None,
        };
        
        // First create should succeed
        ops.create_identity(request.clone()).expect("First create OK");
        
        // Second create with same DID should fail
        let result = ops.create_identity(request);
        assert!(result.is_err());
        match result.unwrap_err() {
            CrestOpError::AlreadyExists(id) => assert_eq!(id, "did:sahyadri:duplicate_test"),
            other => panic!("Expected AlreadyExists, got: {}", other),
        }
    }
    
    #[test]
    fn test_resolve_nonexistent() {
        let store = MockDidStore::new();
        let ops = CrestOperations::new(store);
        
        let result = ops.resolve("did:sahyadri:nonexistent");
        assert!(result.is_err());
        match result.unwrap_err() {
            CrestOpError::NotFound(id) => assert_eq!(id, "did:sahyadri:nonexistent"),
            other => panic!("Expected NotFound, got: {}", other),
        }
    }
    
    #[test]
    fn test_update_identity() {
        let store = MockDidStore::new();
        let ops = CrestOperations::new(store);
        
        // Create first
        let create_req = CreateDidRequest {
            did: "did:sahyadri:update_test".to_string(),
            csm_address: "sahyadri:qupdate".to_string(),
            public_key_hex: "pubkey".to_string(),
            document: "{}".to_string(),
            signature: vec![1, 2, 3],
            services: None,
            authentication_methods: None,
        };
        ops.create_identity(create_req).expect("Create OK");
        
        // Update with new service
        let update_req = UpdateDidRequest {
            did: "did:sahyadri:update_test".to_string(),
            new_version: 2, // Must be current (1) + 1
            add_services: Some(vec![
                CrestService::new("#test-service", "LinkedDomains", "https://example.com")
            ]),
            remove_services: None,
            add_authentication: None,
            set_controller: None,
            signature: vec![4, 5, 6],
        };
        
        let (updated, _) = ops.update_identity(update_req).expect("Update should succeed");
        assert_eq!(updated.services.len(), 1);
        assert_eq!(updated.services[0].id, "#test-service");
        assert_eq!(updated.version_id, 2);
    }
    
    #[test]
    fn test_version_conflict_detected() {
        let store = MockDidStore::new();
        let ops = CrestOperations::new(store);
        
        let create_req = CreateDidRequest {
            did: "did:sahyadri:version_test".to_string(),
            csm_address: "sahyadri:qver".to_string(),
            public_key_hex: "pubkey".to_string(),
            document: "{}".to_string(),
            signature: vec![1, 2, 3],
            services: None,
            authentication_methods: None,
        };
        ops.create_identity(create_req).expect("Create OK");
        
        // Try to update with wrong version (should be 2, but we send 5)
        let bad_req = UpdateDidRequest {
            did: "did:sahyadri:version_test".to_string(),
            new_version: 5, // Wrong! Should be 2
            add_services: None,
            remove_services: None,
            add_authentication: None,
            set_controller: None,
            signature: vec![4, 5, 6],
        };
        
        let result = ops.update_identity(bad_req);
        assert!(result.is_err());
        match result.unwrap_err() {
            CrestOpError::VersionConflict { expected, actual } => {
                assert_eq!(expected, 2);
                assert_eq!(actual, 5);
            }
            other => panic!("Expected VersionConflict, got: {}", other),
        }
    }
    
    #[test]
    fn test_deactivate_identity() {
        let store = MockDidStore::new();
        let ops = CrestOperations::new(store);
        
        let create_req = CreateDidRequest {
            did: "did:sahyadri:deact_test".to_string(),
            csm_address: "sahyadri:qdeact".to_string(),
            public_key_hex: "pubkey".to_string(),
            document: "{}".to_string(),
            signature: vec![1, 2, 3],
            services: None,
            authentication_methods: None,
        };
        ops.create_identity(create_req).expect("Create OK");
        
        // Deactivate
        let deact_req = DeactivateDidRequest {
            did: "did:sahyadri:deact_test".to_string(),
            signature: vec![4, 5, 6],
            reason: Some("Test deactivation".to_string()),
        };
        
        let _pre_state = ops.deactivate_identity(deact_req).expect("Deactivate OK");
        
        // Should no longer resolve as active
        let result = ops.resolve("did:sahyadri:deact_test");
        assert!(result.is_err());
        match result.unwrap_err() {
            CrestOpError::Deactivated(_) => (), // Expected
            other => panic!("Expected Deactivated, got: {}", other),
        }
    }
}
