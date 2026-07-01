//!
//!  Key-related type aliases used by the wallet framework.
//!

use std::sync::Arc;

pub type ExtendedPublicKeyDilithium = sahyadri_bip32::ExtendedPublicKey<sahyadri_bip32::DilithiumPkHash>;

pub type ExtendedPublicKeys = Arc<Vec<ExtendedPublicKeyDilithium>>;
