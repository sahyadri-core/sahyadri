//!
//! Traits for derivation managers.
//!
use crate::imports::DilithiumPkHash;
use crate::result::Result;
use async_trait::async_trait;
use sahyadri_bip32::ExtendedPublicKey;
use std::{collections::HashMap, sync::Arc};

#[async_trait]
pub trait WalletDerivationManagerTrait: Send + Sync {
    fn from_master_xprv(xprv: &str, is_multisig: bool, account_index: u64, cosigner_index: Option<u32>) -> Result<Self>
    where
        Self: Sized;

    fn from_extended_public_key_str(
        xpub: &str, //xpub is drived upto m/<purpose>'/<CoinType>'/<account_index>'
        cosigner_index: Option<u32>,
    ) -> Result<Self>
    where
        Self: Sized;

    fn from_extended_public_key(
        extended_public_key: ExtendedPublicKey<DilithiumPkHash>,
        cosigner_index: Option<u32>,
    ) -> Result<Self>
    where
        Self: Sized;

    fn receive_pubkey_manager(&self) -> Arc<dyn PubkeyDerivationManagerTrait>;
    fn change_pubkey_manager(&self) -> Arc<dyn PubkeyDerivationManagerTrait>;

    fn receive_pubkey(&self) -> Result<DilithiumPkHash>;
    fn change_pubkey(&self) -> Result<DilithiumPkHash>;

    fn derive_receive_pubkey(&self, index: u32) -> Result<DilithiumPkHash>;
    fn derive_change_pubkey(&self, index: u32) -> Result<DilithiumPkHash>;

    fn new_receive_pubkey(&self) -> Result<DilithiumPkHash>;
    fn new_change_pubkey(&self) -> Result<DilithiumPkHash>;

    fn initialize(&self, _key: String, _index: Option<u32>) -> Result<()> {
        Ok(())
    }
    fn uninitialize(&self) -> Result<()> {
        Ok(())
    }
}

#[async_trait]
pub trait PubkeyDerivationManagerTrait: Send + Sync {
    fn new_pubkey(&self) -> Result<DilithiumPkHash>;
    fn current_pubkey(&self) -> Result<DilithiumPkHash>;
    fn index(&self) -> Result<u32>;
    fn set_index(&self, index: u32) -> Result<()>;
    fn get_range(&self, range: std::ops::Range<u32>) -> Result<Vec<DilithiumPkHash>>;
    fn initialize(&self, _key: String) -> Result<()> {
        Ok(())
    }
    fn get_cache(&self) -> Result<HashMap<u32, DilithiumPkHash>> {
        Ok(HashMap::new())
    }
    fn uninitialize(&self) -> Result<()> {
        Ok(())
    }
}
