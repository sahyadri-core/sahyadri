//! SyncWave RPC types — bulk state transfer for fast node bootstrap.

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use super::hash::RpcHash;

/// Cheap metadata fetch before downloading a full snapshot.
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcSyncWaveMetadata {
    pub block_hash: RpcHash,
    pub block_height: u64,
    pub account_root: RpcHash,
    pub total_smt_nodes: u64,
    pub total_accounts: u64,
    pub total_did_states: u64,
    pub chunk_size: u32,
    pub total_chunks: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetSyncWaveMetadataRequest {
    pub block_hash: Option<RpcHash>,
}

impl GetSyncWaveMetadataRequest {
    pub fn new(block_hash: Option<RpcHash>) -> Self {
        Self { block_hash }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetSyncWaveMetadataResponse {
    pub metadata: RpcSyncWaveMetadata,
}

impl GetSyncWaveMetadataResponse {
    pub fn new(metadata: RpcSyncWaveMetadata) -> Self {
        Self { metadata }
    }
}

/// Download one chunk of a snapshot. The chunk is a bincode-encoded
/// `SyncWaveChunkWire` (defined in `consensus_core::model::sync_wave`).
/// Chunks are fetched sequentially from 0 to `total_chunks - 1`.
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct DownloadSyncWaveChunkRequest {
    pub block_hash: RpcHash,
    pub chunk_index: u32,
}

impl DownloadSyncWaveChunkRequest {
    pub fn new(block_hash: RpcHash, chunk_index: u32) -> Self {
        Self { block_hash, chunk_index }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct DownloadSyncWaveChunkResponse {
    /// Bincode-encoded `SyncWaveChunkWire`.
    pub data: Vec<u8>,
    /// Convenience: mirrors the request for sanity checks.
    pub chunk_index: u32,
    pub total_chunks: u32,
}

impl DownloadSyncWaveChunkResponse {
    pub fn new(data: Vec<u8>, chunk_index: u32, total_chunks: u32) -> Self {
        Self { data, chunk_index, total_chunks }
    }
}

// ═══════════════════════════════════════════════════════════════
// Serializer / Deserializer impls (required by wRPC client macros)
// ═══════════════════════════════════════════════════════════════

use workflow_serializer::prelude::*;

impl Serializer for RpcSyncWaveMetadata {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        store!(RpcHash, &self.block_hash, writer)?;
        store!(u64, &self.block_height, writer)?;
        store!(RpcHash, &self.account_root, writer)?;
        store!(u64, &self.total_smt_nodes, writer)?;
        store!(u64, &self.total_accounts, writer)?;
        store!(u64, &self.total_did_states, writer)?;
        store!(u32, &self.chunk_size, writer)?;
        store!(u32, &self.total_chunks, writer)?;
        Ok(())
    }
}

impl Deserializer for RpcSyncWaveMetadata {
    fn deserialize<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        Ok(Self {
            block_hash: load!(RpcHash, reader)?,
            block_height: load!(u64, reader)?,
            account_root: load!(RpcHash, reader)?,
            total_smt_nodes: load!(u64, reader)?,
            total_accounts: load!(u64, reader)?,
            total_did_states: load!(u64, reader)?,
            chunk_size: load!(u32, reader)?,
            total_chunks: load!(u32, reader)?,
        })
    }
}

impl Serializer for GetSyncWaveMetadataRequest {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        store!(Option<RpcHash>, &self.block_hash, writer)?;
        Ok(())
    }
}

impl Deserializer for GetSyncWaveMetadataRequest {
    fn deserialize<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        Ok(Self { block_hash: load!(Option<RpcHash>, reader)? })
    }
}

impl Serializer for GetSyncWaveMetadataResponse {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        store!(RpcSyncWaveMetadata, &self.metadata, writer)?;
        Ok(())
    }
}

impl Deserializer for GetSyncWaveMetadataResponse {
    fn deserialize<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        Ok(Self { metadata: load!(RpcSyncWaveMetadata, reader)? })
    }
}

impl Serializer for DownloadSyncWaveChunkRequest {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        store!(RpcHash, &self.block_hash, writer)?;
        store!(u32, &self.chunk_index, writer)?;
        Ok(())
    }
}

impl Deserializer for DownloadSyncWaveChunkRequest {
    fn deserialize<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        Ok(Self {
            block_hash: load!(RpcHash, reader)?,
            chunk_index: load!(u32, reader)?,
        })
    }
}

impl Serializer for DownloadSyncWaveChunkResponse {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        store!(Vec<u8>, &self.data, writer)?;
        store!(u32, &self.chunk_index, writer)?;
        store!(u32, &self.total_chunks, writer)?;
        Ok(())
    }
}

impl Deserializer for DownloadSyncWaveChunkResponse {
    fn deserialize<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        Ok(Self {
            data: load!(Vec<u8>, reader)?,
            chunk_index: load!(u32, reader)?,
            total_chunks: load!(u32, reader)?,
        })
    }
}

