use std::sync::Arc;

use rocksdb::WriteBatch;
use sahyadri_database::prelude::DB;
use sahyadri_database::prelude::StoreResult;
use sahyadri_database::prelude::StoreResultExt;
use sahyadri_database::prelude::{BatchDbWriter, CachedDbItem};
use sahyadri_database::registry::DatabaseStorePrefixes;
use sahyadri_hashes::Hash;

/// Used in order to group stores related to the pruning point registry_unitset under a single lock
pub struct PruningMetaStores {
    registry_unitset_position_access: CachedDbItem<Hash>,
    registry_unitset_stable_flag_access: CachedDbItem<bool>,
    body_missing_anticone_blocks: CachedDbItem<Vec<Hash>>,
}

impl PruningMetaStores {
    pub fn new(db: Arc<DB>) -> Self {
        Self {
            registry_unitset_position_access: CachedDbItem::new(db.clone(), DatabaseStorePrefixes::PruningRegistryUnitsetPosition.into()),
            registry_unitset_stable_flag_access: CachedDbItem::new(db.clone(), DatabaseStorePrefixes::PruningRegistryUnitsetSyncFlag.into()),
            body_missing_anticone_blocks: CachedDbItem::new(db.clone(), DatabaseStorePrefixes::BodyMissingAnticone.into()),
        }
    }

    /// Represents the exact point of the current pruning point registry_unitset. Used in order to safely
    /// progress the pruning point registry_unitset in batches and to allow recovery if the process crashes
    /// during the pruning point registry_unitset movement
    pub fn registry_unitset_position(&self) -> StoreResult<Hash> {
        self.registry_unitset_position_access.read()
    }

    pub fn set_registry_unitset_position(&mut self, batch: &mut WriteBatch, pruning_registry_unitset_position: Hash) -> StoreResult<()> {
        self.registry_unitset_position_access.write(BatchDbWriter::new(batch), &pruning_registry_unitset_position)
    }

    /// Flip the sync flag in the same batch as your other writes
    pub fn set_pruning_registry_stable_flag(&mut self, batch: &mut WriteBatch, stable: bool) -> StoreResult<()> {
        self.registry_unitset_stable_flag_access.write(BatchDbWriter::new(batch), &stable)
    }

    /// Read the flag; default to true if missing - this is important because a node upgrading should have this value true
    /// as all non staging consensuses had a stable registry_unitset previously
    pub fn pruning_registry_unitset_stable_flag(&self) -> bool {
        self.registry_unitset_stable_flag_access.read().optional().unwrap().unwrap_or(true)
    }

    /// Represents blocks in the anticone of the current pruning point which may lack a block body
    /// These blocks need to be kept track of as they require trusted validation,
    /// so that downloading of further blocks on top of them could resume
    pub fn set_body_missing_anticone(&mut self, batch: &mut WriteBatch, body_missing_anticone: Vec<Hash>) -> StoreResult<()> {
        self.body_missing_anticone_blocks.write(BatchDbWriter::new(batch), &body_missing_anticone)
    }

    /// Default to empty if missing - this is important because a node upgrading should have this value empty
    /// since all non staging consensuses had no missing body anticone previously
    pub fn get_body_missing_anticone(&self) -> Vec<Hash> {
        self.body_missing_anticone_blocks.read().optional().unwrap().unwrap_or(vec![])
    }

    // check if there are any body missing blocks remaining in the anticone of the current pruning point
    pub fn is_anticone_fully_synced(&self) -> bool {
        self.get_body_missing_anticone().is_empty()
    }

    pub fn is_in_transitional_ibd_state(&self) -> bool {
        !self.is_anticone_fully_synced() || !self.pruning_registry_unitset_stable_flag()
    }
}
