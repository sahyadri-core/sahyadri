use crate::{RpcRegistryRef, RpcRegistryUnit};
use serde::{Deserialize, Serialize};
use workflow_serializer::prelude::*;

pub type RpcAddress = sahyadri_addresses::Address;

/// Represents a REGISTRY_UNIT entry of an address returned by the `GetRegistryByAddresses` RPC.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcRegistryByAddressesEntry {
    pub address: Option<RpcAddress>,
    pub outpoint: RpcRegistryRef,
    pub registry_unit_entry: RpcRegistryUnit,
}

impl Serializer for RpcRegistryByAddressesEntry {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        store!(u8, &1, writer)?; // version
        store!(Option<RpcAddress>, &self.address, writer)?;
        serialize!(RpcRegistryRef, &self.outpoint, writer)?;
        serialize!(RpcRegistryUnit, &self.registry_unit_entry, writer)
    }
}

impl Deserializer for RpcRegistryByAddressesEntry {
    fn deserialize<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let _version: u8 = load!(u8, reader)?;
        let address = load!(Option<RpcAddress>, reader)?;
        let outpoint = deserialize!(RpcRegistryRef, reader)?;
        let registry_unit_entry = deserialize!(RpcRegistryUnit, reader)?;
        Ok(Self { address, outpoint, registry_unit_entry })
    }
}

/// Represents a balance of an address returned by the `GetBalancesByAddresses` RPC.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcBalancesByAddressesEntry {
    pub address: RpcAddress,

    /// Balance of `address` if available
    pub balance: Option<u64>,
}

impl Serializer for RpcBalancesByAddressesEntry {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        store!(u8, &1, writer)?; // version
        store!(RpcAddress, &self.address, writer)?;
        store!(Option<u64>, &self.balance, writer)
    }
}

impl Deserializer for RpcBalancesByAddressesEntry {
    fn deserialize<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let _version: u8 = load!(u8, reader)?;
        let address = load!(RpcAddress, reader)?;
        let balance = load!(Option<u64>, reader)?;
        Ok(Self { address, balance })
    }
}
