use crate::{
    hashing::HasherExtensions,
    tx::{RegistryRef, RegistryUnit, VerifiableTransaction},
};
use sahyadri_hashes::HasherBase;
use sahyadri_muhash::MuHash;

pub trait MuHashExtensions {
    fn add_transaction(&mut self, tx: &impl VerifiableTransaction, block_daa_score: u64);
    fn add_registry_unit(&mut self, outpoint: &RegistryRef, entry: &RegistryUnit);
    fn from_transaction(tx: &impl VerifiableTransaction, block_daa_score: u64) -> Self;
    fn from_registry_unit(outpoint: &RegistryRef, entry: &RegistryUnit) -> Self;
}

impl MuHashExtensions for MuHash {
    fn add_transaction(&mut self, tx: &impl VerifiableTransaction, block_daa_score: u64) {
        let tx_id = tx.id();
        for (input, entry) in tx.populated_inputs() {
            let mut writer = self.remove_element_builder();
            write_registry_unit(&mut writer, entry, &input.previous_outpoint);
            writer.finalize();
        }
        for (i, output) in tx.outputs().iter().enumerate() {
            let outpoint = RegistryRef::new(tx_id, i as u32);
            let entry = RegistryUnit::new(output.value, output.script_public_key.clone(), block_daa_score, tx.is_coinbase());
            self.add_registry_unit(&outpoint, &entry);
        }
    }

    fn add_registry_unit(&mut self, outpoint: &RegistryRef, entry: &RegistryUnit) {
        let mut writer = self.add_element_builder();
        write_registry_unit(&mut writer, entry, outpoint);
        writer.finalize();
    }

    fn from_transaction(tx: &impl VerifiableTransaction, block_daa_score: u64) -> Self {
        let mut mh = Self::new();
        mh.add_transaction(tx, block_daa_score);
        mh
    }

    fn from_registry_unit(outpoint: &RegistryRef, entry: &RegistryUnit) -> Self {
        let mut mh = Self::new();
        mh.add_registry_unit(outpoint, entry);
        mh
    }
}

fn write_registry_unit(writer: &mut impl HasherBase, entry: &RegistryUnit, outpoint: &RegistryRef) {
    writer
        // Outpoint
        .update(outpoint.transaction_id)
        .update(outpoint.index.to_le_bytes())
        // RegistryUnit entry
        .update(entry.block_daa_score.to_le_bytes())
        .update(entry.amount.to_le_bytes())
        .write_bool(entry.is_coinbase)
        .update(entry.script_public_key.version().to_le_bytes())
        .write_var_bytes(entry.script_public_key.script());
}
