// ============================================================================
// CREST MODEL — Sahyadri Identity
// ============================================================================
//
// This module defines the RICH TYPE SYSTEM for DIDs on Sahyadri.
//
// WHY THIS EXISTS:
// - did_store.rs stores flat strings (for DB efficiency)
// - crest_model.rs provides typed structures (for developer sanity)
// - Conversion happens via .to_legacy() / .from_legacy()
//
// DESIGN PRINCIPLES:
// 1. Type safety over stringly-typed data
// 2. Validation at construction time
// 3. Zero-cost abstractions (no runtime overhead)
// 4. Migration path from legacy DidDocument
//
// ============================================================================

use serde::{Deserialize, Serialize};
use serde_json;

// ===== ERROR TYPES =====

/// Crest Model Errors
#[derive(Debug, Clone)]
pub enum CrestError {
    /// Invalid purpose string
    InvalidPurpose(String),
    /// Invalid key encoding
    InvalidKey(String),
    /// Missing required field
    MissingField(String),
    /// Validation failed
    Validation(String),
    /// Serialization/deserialization error
    Serialization(String),
}

impl std::fmt::Display for CrestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPurpose(s) => write!(f, "Invalid purpose: {}", s),
            Self::InvalidKey(s) => write!(f, "Invalid key: {}", s),
            Self::MissingField(s) => write!(f, "Missing field: {}", s),
            Self::Validation(s) => write!(f, "Validation error: {}", s),
            Self::Serialization(s) => write!(f, "Serialization error: {}", s),
        }
    }
}

impl std::error::Error for CrestError {}

/// Validation warning (non-fatal)
#[derive(Debug, Clone)]
pub enum CrestWarning {
    DeprecatedField(String),
    NonStandardServiceType(String),
}

// ===== CORE ENUMS =====

/// Typed DID Verification Purpose
///
/// Replaces raw strings like "authentication" with type-safe enums.
/// Maps to W3C DID specification purposes.
///
/// # Example
///
/// ```ignore
/// let purpose = CrestPurpose::Authentication;
/// assert_eq!(purpose.to_did_string(), "authentication");
/// ```
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Copy)]
pub enum CrestPurpose {
    /// Authentication — prove ownership of DID
    Authentication,
    
    /// Key Agreement — establish encrypted communication
    KeyAgreement,
    
    /// Capability Invocation — authorize actions
    CapabilityInvocation,
    
    /// Capability Delegation — delegate authority to others
    CapabilityDelegation,
    
    /// Assertion — make claims about subjects
    Assertion,
}

impl CrestPurpose {
    /// Convert to W3C DID standard string representation
    pub fn to_did_string(&self) -> &'static str {
        match self {
            Self::Authentication => "authentication",
            Self::KeyAgreement => "keyAgreement",
            Self::CapabilityInvocation => "capabilityInvocation",
            Self::CapabilityDelegation => "capabilityDelegation",
            Self::Assertion => "assertion",
        }
    }
    
    /// Parse from W3C DID standard string
    ///
    /// # Returns
    ///
    /// - `Ok(CrestPurpose)` if valid W3C purpose string
    /// - `Err(CrestError)` if unknown purpose
    pub fn from_did_string(s: &str) -> Result<Self, CrestError> {
        match s {
            "authentication" => Ok(Self::Authentication),
            "keyAgreement" => Ok(Self::KeyAgreement),
            "capabilityInvocation" => Ok(Self::CapabilityInvocation),
            "capabilityDelegation" => Ok(Self::CapabilityDelegation),
            "assertion" => Ok(Self::Assertion),
            other => Err(CrestError::InvalidPurpose(other.to_string())),
        }
    }
    
    /// Get all valid purposes (for iteration/validation)
    pub fn all() -> &'static [Self] {
        &[
            Self::Authentication,
            Self::KeyAgreement,
            Self::CapabilityInvocation,
            Self::CapabilityDelegation,
            Self::Assertion,
        ]
    }
}

impl std::fmt::Display for CrestPurpose {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_did_string())
    }
}

// ===== SERVICE TYPES =====

/// Structured Service Endpoint
///
/// Replaces raw URL strings with validated, typed service definitions.
///
/// # Example
///
/// ```ignore
/// let dwn_service = CrestService {
///     id: "#dwn".to_string(),
///     type_: "DIDCommMessaging".to_string(),
///     service_endpoint: "https://dwn.example.com".to_string(),
///     ..Default::default()
/// };
/// dwn_service.validate()?; // Ensures well-formed
/// ```
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CrestService {
    /// Fragment identifier within DID document (e.g., "#dwn", "#hub")
    pub id: String,
    
    /// Service type identifier
    /// Common values: "DIDCommMessaging", "Web5DWN", "LinkedDomains", "CredentialService"
    pub type_: String,
    
    /// Primary endpoint URL or DID
    pub service_endpoint: String,
    
    /// Optional routing keys for encrypted messaging protocols
    pub routing_keys: Option<Vec<String>>,
    
    /// Accepted content types (MIME types)
    pub accept: Option<Vec<String>>,
    
    /// Extensible metadata map
    #[serde(default)]
    pub metadata: std::collections::HashMap<String, serde_json::Value>,
}

impl Default for CrestService {
    fn default() -> Self {
        Self {
            id: String::new(),
            type_: String::new(),
            service_endpoint: String::new(),
            routing_keys: None,
            accept: None,
            metadata: std::collections::HashMap::new(),
        }
    }
}

impl CrestService {
    /// Create new service endpoint
    pub fn new(id: &str, type_: &str, endpoint: &str) -> Self {
        Self {
            id: id.to_string(),
            type_: type_.to_string(),
            service_endpoint: endpoint.to_string(),
            ..Default::default()
        }
    }
    
    /// Validate service structure
    ///
    /// # Errors
    ///
    /// - Empty ID or type
    /// - Invalid endpoint format (must be URL or DID)
    pub fn validate(&self) -> Result<(), CrestError> {
        if self.id.is_empty() {
            return Err(CrestError::Validation("Service ID cannot be empty".into()));
        }
        
        if self.type_.is_empty() {
            return Err(CrestError::Validation("Service type cannot be empty".into()));
        }
        
        // Endpoint must be URL (http/https) or DID
        let ep = self.service_endpoint.trim();
        if !ep.starts_with("http://") 
            && !ep.starts_with("https://") 
            && !ep.starts_with("did:") 
            && !ep.is_empty() 
        {
            return Err(CrestError::Validation(
                format!("Invalid service endpoint: {} (must be URL or DID)", ep)
            ));
        }
        
        Ok(())
    }
    
    /// Check if this is a Web5 DWN service
    pub fn is_web5_dwn(&self) -> bool {
        self.type_.contains("Web5") || self.type_.contains("DWN") || self.type_.contains("DecentralizedWebNode")
    }
    
    /// Check if this is a DIDComm messaging service
    pub fn is_didcomm(&self) -> bool {
        self.type_.contains("DIDComm")
    }
}

// ===== VERIFICATION METHOD TYPES =====

/// Cryptographic Verification Method
///
/// Represents a public key bound to this DID identity.
/// Supports Dilithium3 post-quantum cryptography natively.
///
/// # Example
///
/// ```ignore
/// let auth_key = CrestVerificationMethod {
///     id: "#auth-key-1".to_string(),
///     type_: "Dilithium3VerificationKey2024".to_string(),
///     controller: "did:sahyadri:abc123".to_string(),
///     public_key_multibase: Some("z...multibase...".to_string()),
///     purpose: CrestPurpose::Authentication,
/// };
/// ```
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CrestVerificationMethod {
    /// Fragment identifier (e.g., "#key-1", "#auth-key")
    pub id: String,
    
    /// Verification method type
    /// Standard: "Dilithium3VerificationKey2024"
    /// Legacy: "Ed25519VerificationKey2018", "EcdsaSecp256k1VerificationKey2019"
    pub type_: String,
    
    /// Controller DID (who owns/controls this key)
    pub controller: String,
    
    /// Multicodec-encoded public key (preferred modern format)
    pub public_key_multibase: Option<String>,
    
    /// Base58-encoded public key (legacy compatibility)
    pub public_key_base58: Option<String>,
    
    /// What operations this key can perform
    pub purpose: CrestPurpose,
}

impl Default for CrestVerificationMethod {
    fn default() -> Self {
        Self {
            id: String::new(),
            type_: String::new(),
            controller: String::new(),
            public_key_multibase: None,
            public_key_base58: None,
            purpose: CrestPurpose::Authentication,
        }
    }
}

impl CrestVerificationMethod {
    /// Create Dilithium3 verification method (recommended for Sahyadri)
    pub fn dilithium3(
        id: &str,
        controller: &str,
        multibase_pubkey: &str,
        purpose: CrestPurpose,
    ) -> Self {
        Self {
            id: id.to_string(),
            type_: "Dilithium3VerificationKey2024".to_string(),
            controller: controller.to_string(),
            public_key_multibase: Some(multibase_pubkey.to_string()),
            public_key_base58: None,
            purpose,
        }
    }
    
    /// Create legacy Ed25519 key (for cross-chain compatibility)
    pub fn ed25519(
        id: &str,
        controller: &str,
        base58_pubkey: &str,
        purpose: CrestPurpose,
    ) -> Self {
        Self {
            id: id.to_string(),
            type_: "Ed25519VerificationKey2018".to_string(),
            controller: controller.to_string(),
            public_key_multibase: None,
            public_key_base58: Some(base58_pubkey.to_string()),
            purpose,
        }
    }
    
    /// Check if this is a post-quantum key (Dilithium)
    pub fn is_post_quantum(&self) -> bool {
        self.type_.contains("Dilithium")
    }
    
    /// Extract raw public key bytes (tries multibase first, then base58)
    pub fn get_public_key_bytes(&self) -> Result<Vec<u8>, CrestError> {
        if let Some(mb) = &self.public_key_multibase {
            // TODO: Implement proper multibase decoding when hex/bs58 crates added
            // For now, return error — this is a placeholder implementation
            Err(CrestError::InvalidKey(format!(
                "Multibase decoding not yet implemented (key starts with: {})",
                &mb[..mb.len().min(10)]
            )))
        } else if let Some(_b58) = &self.public_key_base58 {
            // TODO: Implement bs58 decode when crate added
            Err(CrestError::InvalidKey("Base58 decoding not yet implemented".to_string()))
        } else {
            Err(CrestError::MissingField("public_key".to_string()))
        }
    }
}

// ===== MAIN IDENTITY DOCUMENT =====

/// Crest Identity Document
///
/// The core object in Sahyadri's Object Model layer.
/// This is a RICH, TYPED alternative to the flat DidDocument.
///
/// # Design Principles
///
/// 1. **Typed Fields**: Uses enums instead of strings where possible
/// 2. **Validation**: Can validate itself before storage
/// 3. **Migration**: Converts to/from legacy DidDocument format
/// 4. **Extensible**: Easy to add new fields without breaking changes
///
/// # Lifecycle
///
/// ```text
/// Created → Active → (Updated N times) → Deactivated
///                         ↑
///                    Version increments each update
/// ```
///
/// # Example
///
/// ```ignore
/// let mut identity = CrestDocument::new(
///     "did:sahyadri:Wxyz...",
///     "sahyadri:qABC...",
///     "dilithium_pubkey_hex..."
/// );
///
/// identity.add_authentication(CrestVerificationMethod::dilithium3(
///     "#auth-1",
///     &identity.id,
///     "z...multibase...",
///     CrestPurpose::Authentication,
/// ))?;
///
/// identity.add_service(CrestService::new(
///     "#web5-dwn",
///     "Web5DWN",
///     "https://dwn.sahyadri.io/user/xyz",
/// ))?;
///
/// identity.validate()?; // Ensure everything is correct
/// ```
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CrestDocument {
    // === Identity Identifiers ===
    
    /// Full DID identifier: `did:sahyadri:{base58check-hash}`
    pub id: String,
    
    /// JSON-LD context(s) for document processing
    #[serde(default = "default_context")]
    pub context: Vec<String>,
    
    /// Controller DID (if different from id — for delegation scenarios)
    pub controller: Option<String>,
    
    // === Verification Methods (by category!) ===
    
    /// Keys that can authenticate (prove ownership of this DID)
    pub authentication: Vec<CrestVerificationMethod>,
    
    /// Keys for encryption/key agreement
    pub key_agreement: Vec<CrestVerificationMethod>,
    
    /// Keys that can invoke capabilities on behalf of this DID
    pub capability_invocation: Vec<CrestVerificationMethod>,
    
    /// Keys that can delegate capabilities to other DIDs
    pub capability_delegation: Vec<CrestVerificationMethod>,
    
    // === Service Endpoints ===
    
    /// Available services (DWN hubs, credential endpoints, etc.)
    pub services: Vec<CrestService>,
    
    // === Metadata ===
    
    /// Alternative DID identifiers (aliases)
    pub also_known_as: Option<Vec<String>>,
    
    /// Block timestamp when created
    pub created: u64,
    
    /// Block timestamp when last updated (None if never updated)
    pub updated: Option<u64>,
    
    /// Monotonically increasing version number (for optimistic concurrency)
    pub version_id: u64,
    
    /// Whether this identity has been deactivated
    pub deactivated: bool,
    
    // === On-Chain Linking ===
    
    /// Associated CSM blockchain address (for token transfers, staking, etc.)
    pub csm_address: String,
    
    /// Raw Dilithium3 public key in hex format (for on-chain signature verification)
    pub public_key_hex: String,
}

fn default_context() -> Vec<String> {
    vec!["https://www.w3.org/ns/did/v1".to_string()]
}

impl Default for CrestDocument {
    fn default() -> Self {
        Self {
            id: String::new(),
            context: default_context(),
            controller: None,
            authentication: Vec::new(),
            key_agreement: Vec::new(),
            capability_invocation: Vec::new(),
            capability_delegation: Vec::new(),
            services: Vec::new(),
            also_known_as: None,
            created: 0,
            updated: None,
            version_id: 0,
            deactivated: false,
            csm_address: String::new(),
            public_key_hex: String::new(),
        }
    }
}

impl CrestDocument {
    // === Constructors ===
    
    /// Create new Crest Identity
    ///
    /// # Arguments
    ///
    /// * `did` - Full DID identifier (e.g., "did:sahyadri:Wxyz...")
    /// * `csm_address` - Associated CSM blockchain address
    /// * `public_key_hex` - Dilithium3 public key in hex format
    ///
    /// # Example
    ///
    /// ```ignore
    /// let doc = CrestDocument::new(
    ///     "did:sahyadri:WxyzAbc123",
    ///     "sahyadri:qrp8jXhK7LmNoPqRsTuVwXyZ",
    ///     "dilithium3_hex_public_key_here..."
    /// );
    /// assert!(doc.active()); // New identities are active by default
    /// ```
    pub fn new(did: &str, csm_address: &str, public_key_hex: &str) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
            
        Self {
            id: did.to_string(),
            csm_address: csm_address.to_string(),
            public_key_hex: public_key_hex.to_string(),
            created: now,
            version_id: 1,
            deactivated: false,
            ..Default::default()
        }
    }
    
    // === State Queries ===
    
    /// Check if this identity is currently active
    pub fn active(&self) -> bool {
        !self.deactivated
    }
    
    /// Get total number of verification methods across all categories
    pub fn verification_method_count(&self) -> usize {
        self.authentication.len()
            + self.key_agreement.len()
            + self.capability_invocation.len()
            + self.capability_delegation.len()
    }
    
    /// Find verification method by fragment ID
    pub fn find_verification_method(&self, fragment_id: &str) -> Option<&CrestVerificationMethod> {
        self.authentication.iter()
            .chain(self.key_agreement.iter())
            .chain(self.capability_invocation.iter())
            .chain(self.capability_delegation.iter())
            .find(|vm| vm.id == fragment_id)
    }
    
    /// Find service by fragment ID
    pub fn find_service(&self, fragment_id: &str) -> Option<&CrestService> {
        self.services.iter().find(|s| s.id == fragment_id)
    }
    
    // === Mutations (with validation) ===
    
    /// Add authentication verification method
    ///
    /// # Arguments
    ///
    /// * `method` - The verification method to add
    ///
    /// # Errors
    ///
    /// - Duplicate ID
    /// - Controller mismatch
    pub fn add_authentication(&mut self, method: CrestVerificationMethod) -> Result<(), CrestError> {
        self.validate_new_vm(&method)?;
        self.authentication.push(method);
        self.touch();
        Ok(())
    }
    
    /// Add key agreement verification method
    pub fn add_key_agreement(&mut self, method: CrestVerificationMethod) -> Result<(), CrestError> {
        self.validate_new_vm(&method)?;
        self.key_agreement.push(method);
        self.touch();
        Ok(())
    }
    
    /// Add service endpoint
    ///
    /// Automatically validates the service before adding.
    ///
    /// # Errors
    ///
    /// - Invalid service structure (from `CrestService::validate()`)
    /// - Duplicate service ID
    pub fn add_service(&mut self, service: CrestService) -> Result<(), CrestError> {
        service.validate()?;
        
        if self.find_service(&service.id).is_some() {
            return Err(CrestError::Validation(format!("Duplicate service ID: {}", service.id)));
        }
        
        self.services.push(service);
        self.touch();
        Ok(())
    }
    
    /// Remove service by ID
    ///
    /// # Returns
    ///
    /// - `true` if service was found and removed
    /// - `false` if service ID not found
    pub fn remove_service(&mut self, id: &str) -> bool {
        if let Some(pos) = self.services.iter().position(|s| s.id == id) {
            self.services.remove(pos);
            self.touch();
            true
        } else {
            false
        }
    }
    
    /// Set controller (transfer ownership)
    ///
    /// # Note
    ///
    /// This requires re-signing with the new controller's key.
    pub fn set_controller(&mut self, controller_did: &str) {
        self.controller = Some(controller_did.to_string());
        self.touch();
    }
    
    /// Add alias (also-known-as)
    pub fn add_alias(&mut self, alias: &str) {
        self.also_known_as.get_or_insert_with(Vec::new).push(alias.to_string());
        self.touch();
    }
    
    /// Deactivate this identity
    ///
    /// # Warning
    ///
    /// This is irreversible! Deactivated DIDs cannot be reactivated
    /// (must create new DID instead).
    pub fn deactivate(&mut self) {
        self.deactivated = true;
        self.updated = Some(std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs());
    }
    
    /// Increment version number (call before persisting updates)
    ///
    /// # Returns
    ///
    /// The new version number after incrementing
    pub fn bump_version(&mut self) -> u64 {
        self.version_id += 1;
        self.touch();
        self.version_id
    }
    
    // === Validation ===
    
    /// Validate entire document structure
    ///
    /// # Returns
    ///
    /// - `Ok(())` if document is valid
    /// - `Err(CrestError::Validation(...))` with details if invalid
    pub fn validate(&self) -> Result<(), CrestError> {
        let mut errors = Vec::new();
        
        // Validate ID format
        if self.id.is_empty() {
            errors.push("DID cannot be empty".into());
        } else if !self.id.starts_with("did:sahyadri:") {
            errors.push(format!("DID must start with 'did:sahyadri:', got: {}", &self.id[..self.id.len().min(20)]));
        }
        
        // Validate required fields
        if self.csm_address.is_empty() {
            errors.push("CSM address cannot be empty".into());
        }
        
        if self.public_key_hex.is_empty() {
            errors.push("Public key cannot be empty".into());
        }
        
        // Validate all services
        for (i, svc) in self.services.iter().enumerate() {
            if let Err(e) = svc.validate() {
                errors.push(format!("Service[{}] '{}': {}", i, svc.id, e));
            }
        }
        
        // Validate no duplicate VM IDs
        let mut vm_ids = std::collections::HashSet::new();
        for vm in self.all_verification_methods() {
            if !vm_ids.insert(&vm.id) {
                errors.push(format!("Duplicate verification method ID: {}", vm.id));
            }
        }
        
        // Validate no duplicate service IDs
        let mut service_ids = std::collections::HashSet::new();
        for svc in &self.services {
            if !service_ids.insert(&svc.id) {
                errors.push(format!("Duplicate service ID: {}", svc.id));
            }
        }
        
        if errors.is_empty() {
            Ok(())
        } else {
            Err(CrestError::Validation(errors.join("; ")))
        }
    }
    
    // === Serialization ===
    
    /// Convert to canonical JSON-LD string
    ///
    /// Produces pretty-printed JSON suitable for signing/storage.
    pub fn to_canonical_json(&self) -> Result<String, CrestError> {
        serde_json::to_string_pretty(self)
            .map_err(|e| CrestError::Serialization(e.to_string()))
    }
    
    /// Parse from JSON-LD string
    pub fn from_canonical_json(json: &str) -> Result<Self, CrestError> {
        serde_json::from_str(json)
            .map_err(|e| CrestError::Serialization(e.to_string()))
    }
    
    // === Iterators ===
    
    /// Iterate over ALL verification methods (all categories)
    pub fn all_verification_methods(&self) -> impl Iterator<Item = &CrestVerificationMethod> {
        self.authentication.iter()
            .chain(self.key_agreement.iter())
            .chain(self.capability_invocation.iter())
            .chain(self.capability_delegation.iter())
    }
    
    /// Get all Web5/DWN services
    pub fn web5_services(&self) -> impl Iterator<Item = &CrestService> {
        self.services.iter().filter(|s| s.is_web5_dwn())
    }
    
    /// Get all DIDComm services
    pub fn didcomm_services(&self) -> impl Iterator<Item = &CrestService> {
        self.services.iter().filter(|s| s.is_didcomm())
    }
    
    // === Migration (Legacy Conversion) ===
    
    /// Convert FROM legacy DidDocument format
    ///
    /// Used when reading from database (which stores legacy format).
    ///
    /// # Note
    ///
    /// Some information may be lost in conversion because legacy format
    /// stores purposes/services as flat strings without categorization.
    pub fn from_legacy(doc: &super::did_store::DidDocument) -> Self {
        let mut crest = Self::new(&doc.did, &doc.csm_address, &doc.public_key);
        crest.created = doc.created_at;
        crest.version_id = doc.version;
        crest.deactivated = !doc.active;
        
        if doc.updated_at > 0 {
            crest.updated = Some(doc.updated_at);
        }
        
        // Try to parse legacy purposes into appropriate categories
        // Legacy stored all purposes in single Vec<String>
        // We'll put them all in authentication for safety
        for purpose_str in &doc.purposes {
            if let Ok(purpose) = CrestPurpose::from_did_string(purpose_str) {
                match purpose {
                    CrestPurpose::Authentication => { /* Will add placeholder */ }
                    CrestPurpose::KeyAgreement => { /* Will add placeholder */ }
                    _ => {}
                }
            }
        }
        
        // Legacy services were URLs — we can't reconstruct full structure
        // Store as simple LinkedDomains services
        for (i, service_url) in doc.services.iter().enumerate() {
            let svc = CrestService::new(
                &format!("#legacy-service-{}", i),
                "LinkedDomains",  // Best guess for unknown legacy services
                service_url,
            );
            // Don't validate — legacy data may not conform
            crest.services.push(svc);
        }
        
        crest
    }
    
    /// Convert TO legacy DidDocument format
    ///
    /// Used when writing to database (which expects legacy format).
    ///
    /// # Note
    ///
    /// This flattens structured data back into strings.
    pub fn to_legacy(&self) -> super::did_store::DidDocument {
        // Collect all purposes into flat Vec<String>
        let purposes: Vec<String> = self.all_verification_methods()
            .map(|vm| vm.purpose.to_did_string().to_string())
            .collect();
            
        // Collect all service endpoints into flat Vec<String>
        let services: Vec<String> = self.services.iter()
            .map(|s| s.service_endpoint.clone())
            .collect();
            
        // Serialize full document as JSON
        let document = self.to_canonical_json().unwrap_or_else(|_| "{}".to_string());
        
        super::did_store::DidDocument {
            did: self.id.clone(),
            csm_address: self.csm_address.clone(),
            public_key: self.public_key_hex.clone(),
            document,
            purposes,
            services,
            active: !self.deactivated,
            created_at: self.created,
            updated_at: self.updated.unwrap_or(0),
            version: self.version_id,
        }
    }
    
    // === Private Helpers ===
    
    /// Update timestamp on mutation
    fn touch(&mut self) {
        self.updated = Some(std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs());
    }
    
    /// Validate new verification method before adding
    fn validate_new_vm(&self, vm: &CrestVerificationMethod) -> Result<(), CrestError> {
        if vm.id.is_empty() {
            return Err(CrestError::Validation("Verification method ID cannot be empty".into()));
        }
        
        if vm.controller != self.id {
            if self.controller.as_ref().map_or(true, |c| c != &vm.controller) {
                return Err(CrestError::Validation(
                    format!("VM controller '{}' doesn't match DID '{}'", vm.controller, self.id)
                ));
            }
        }
        
        if self.find_verification_method(&vm.id).is_some() {
            return Err(CrestError::Validation(format!("Duplicate VM ID: {}", vm.id)));
        }
        
        Ok(())
    }
}

// ===== BUILDER PATTERN (Optional Convenience) =====

/// Builder for constructing CrestDocument step-by-step
///
/// # Example
///
/// ```ignore
/// let doc = CrestBuilder::new("did:sahyadri:...", "sahyadri:q...", "pubkey...")
///     .with_authentication("#auth-1", "z...multibase...")
///     .with_web5_dwn("https://dwn.example.com")
///     .build()?;
/// ```
pub struct CrestBuilder {
    inner: CrestDocument,
}

impl CrestBuilder {
    /// Start building new identity
    pub fn new(did: &str, csm_address: &str, public_key_hex: &str) -> Self {
        Self {
            inner: CrestDocument::new(did, csm_address, public_key_hex),
        }
    }
    
    /// Add Dilithium3 authentication key
    pub fn with_authentication(mut self, id: &str, multibase_pubkey: &str) -> Self {
        let vm = CrestVerificationMethod::dilithium3(
            id,
            &self.inner.id,
            multibase_pubkey,
            CrestPurpose::Authentication,
        );
        // Ignore errors during build — validate at end
        let _ = self.inner.add_authentication(vm);
        self
    }
    
    /// Add Dilithium3 key agreement key
    pub fn with_key_agreement(mut self, id: &str, multibase_pubkey: &str) -> Self {
        let vm = CrestVerificationMethod::dilithium3(
            id,
            &self.inner.id,
            multibase_pubkey,
            CrestPurpose::KeyAgreement,
        );
        let _ = self.inner.add_key_agreement(vm);
        self
    }
    
    /// Add Web5 DWN service
    pub fn with_web5_dwn(mut self, endpoint: &str) -> Self {
        let svc = CrestService::new("#web5-dwn", "DecentralizedWebNode", endpoint);
        let _ = self.inner.add_service(svc);
        self
    }
    
    /// Add DIDComm messaging service
    pub fn with_didcomm(mut self, endpoint: &str) -> Self {
        let svc = CrestService::new("#didcomm", "DIDCommMessaging", endpoint);
        let _ = self.inner.add_service(svc);
        self
    }
    
    /// Set custom controller
    pub fn with_controller(mut self, controller_did: &str) -> Self {
        self.inner.set_controller(controller_did);
        self
    }
    
    /// Build final document (validates!)
    pub fn build(self) -> Result<CrestDocument, CrestError> {
        self.inner.validate()?;
        Ok(self.inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_crest_document_creation() {
        let doc = CrestDocument::new(
            "did:sahyadri:test123",
            "sahyadri:qtest",
            "test_pubkey_hex",
        );
        
        assert_eq!(doc.id, "did:sahyadri:test123");
        assert_eq!(doc.csm_address, "sahyadri:qtest");
        assert!(doc.active());
        assert_eq!(doc.version_id, 1);
    }
    
    #[test]
    fn test_crest_purpose_roundtrip() {
        for purpose in CrestPurpose::all() {
            let s = purpose.to_did_string();
            let parsed = CrestPurpose::from_did_string(s).unwrap();
            assert_eq!(*purpose, parsed);
        }
    }
    
    #[test]
    fn test_crest_service_validation() {
        let valid = CrestService::new("#dwn", "Web5DWN", "https://example.com");
        assert!(valid.validate().is_ok());
        
        let invalid_type = CrestService::new("#x", "", "https://example.com");
        assert!(invalid_type.validate().is_err());
        
        let invalid_ep = CrestService::new("#x", "DIDComm", "not-a-url-or-did");
        assert!(invalid_ep.validate().is_err());
    }
    
    #[test]
    fn test_builder_pattern() {
        let result = CrestBuilder::new(
            "did:sahyadri:builder-test",
            "sahyadri:qbuilt",
            "builder_pubkey"
        )
        .with_authentication("#auth-1", "zdummy-multibase-pubkey")
        .with_web5_dwn("https://dwn.example.com/test")
        .build();
        
        assert!(result.is_ok());
        let doc = result.unwrap();
        assert_eq!(doc.authentication.len(), 1);
        assert_eq!(doc.services.len(), 1);
        assert!(doc.services[0].is_web5_dwn());
    }
}
