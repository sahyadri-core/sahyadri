use crate::pb::sahyadrid_message::Payload as SahyadridMessagePayload;

#[repr(u8)]
#[derive(Debug, Copy, Clone, Eq, Hash, PartialEq)]
pub enum SahyadridMessagePayloadType {
    Addresses = 0,
    Block,
    Transaction,
    BlockLocator,
    RequestAddresses,
    RequestRelayBlocks,
    RequestTransactions,
    IbdBlock,
    InvRelayBlock,
    InvTransactions,
    Ping,
    Pong,
    Verack,
    Version,
    TransactionNotFound,
    Reject,
    PruningPointUtxoSetChunk,
    RequestIbdBlocks,
    UnexpectedPruningPoint,
    IbdBlockLocator,
    IbdBlockLocatorHighestHash,
    RequestNextPruningPointUtxoSetChunk,
    DonePruningPointUtxoSetChunks,
    IbdBlockLocatorHighestHashNotFound,
    BlockWithTrustedData,
    DoneBlocksWithTrustedData,
    RequestPruningPointAndItsAnticone,
    BlockHeaders,
    RequestNextHeaders,
    DoneHeaders,
    RequestPruningPointUtxoSet,
    RequestHeaders,
    RequestBlockLocator,
    PruningPoints,
    RequestPruningPointProof,
    PruningPointProof,
    Ready,
    BlockWithTrustedDataV4,
    TrustedData,
    RequestIbdChainBlockLocator,
    IbdChainBlockLocator,
    RequestAntipast,
    RequestNextPruningPointAndItsAnticoneBlocks,
    BlockBody,
    RequestBlockBodies,
}

impl From<&SahyadridMessagePayload> for SahyadridMessagePayloadType {
    fn from(payload: &SahyadridMessagePayload) -> Self {
        match payload {
            SahyadridMessagePayload::Addresses(_) => SahyadridMessagePayloadType::Addresses,
            SahyadridMessagePayload::Block(_) => SahyadridMessagePayloadType::Block,
            SahyadridMessagePayload::Transaction(_) => SahyadridMessagePayloadType::Transaction,
            SahyadridMessagePayload::BlockLocator(_) => SahyadridMessagePayloadType::BlockLocator,
            SahyadridMessagePayload::RequestAddresses(_) => SahyadridMessagePayloadType::RequestAddresses,
            SahyadridMessagePayload::RequestRelayBlocks(_) => SahyadridMessagePayloadType::RequestRelayBlocks,
            SahyadridMessagePayload::RequestTransactions(_) => SahyadridMessagePayloadType::RequestTransactions,
            SahyadridMessagePayload::IbdBlock(_) => SahyadridMessagePayloadType::IbdBlock,
            SahyadridMessagePayload::InvRelayBlock(_) => SahyadridMessagePayloadType::InvRelayBlock,
            SahyadridMessagePayload::InvTransactions(_) => SahyadridMessagePayloadType::InvTransactions,
            SahyadridMessagePayload::Ping(_) => SahyadridMessagePayloadType::Ping,
            SahyadridMessagePayload::Pong(_) => SahyadridMessagePayloadType::Pong,
            SahyadridMessagePayload::Verack(_) => SahyadridMessagePayloadType::Verack,
            SahyadridMessagePayload::Version(_) => SahyadridMessagePayloadType::Version,
            SahyadridMessagePayload::TransactionNotFound(_) => SahyadridMessagePayloadType::TransactionNotFound,
            SahyadridMessagePayload::Reject(_) => SahyadridMessagePayloadType::Reject,
            SahyadridMessagePayload::PruningPointUtxoSetChunk(_) => SahyadridMessagePayloadType::PruningPointUtxoSetChunk,
            SahyadridMessagePayload::RequestIbdBlocks(_) => SahyadridMessagePayloadType::RequestIbdBlocks,
            SahyadridMessagePayload::UnexpectedPruningPoint(_) => SahyadridMessagePayloadType::UnexpectedPruningPoint,
            SahyadridMessagePayload::IbdBlockLocator(_) => SahyadridMessagePayloadType::IbdBlockLocator,
            SahyadridMessagePayload::IbdBlockLocatorHighestHash(_) => SahyadridMessagePayloadType::IbdBlockLocatorHighestHash,
            SahyadridMessagePayload::RequestNextPruningPointUtxoSetChunk(_) => {
                SahyadridMessagePayloadType::RequestNextPruningPointUtxoSetChunk
            }
            SahyadridMessagePayload::DonePruningPointUtxoSetChunks(_) => SahyadridMessagePayloadType::DonePruningPointUtxoSetChunks,
            SahyadridMessagePayload::IbdBlockLocatorHighestHashNotFound(_) => {
                SahyadridMessagePayloadType::IbdBlockLocatorHighestHashNotFound
            }
            SahyadridMessagePayload::BlockWithTrustedData(_) => SahyadridMessagePayloadType::BlockWithTrustedData,
            SahyadridMessagePayload::DoneBlocksWithTrustedData(_) => SahyadridMessagePayloadType::DoneBlocksWithTrustedData,
            SahyadridMessagePayload::RequestPruningPointAndItsAnticone(_) => SahyadridMessagePayloadType::RequestPruningPointAndItsAnticone,
            SahyadridMessagePayload::BlockHeaders(_) => SahyadridMessagePayloadType::BlockHeaders,
            SahyadridMessagePayload::RequestNextHeaders(_) => SahyadridMessagePayloadType::RequestNextHeaders,
            SahyadridMessagePayload::DoneHeaders(_) => SahyadridMessagePayloadType::DoneHeaders,
            SahyadridMessagePayload::RequestPruningPointUtxoSet(_) => SahyadridMessagePayloadType::RequestPruningPointUtxoSet,
            SahyadridMessagePayload::RequestHeaders(_) => SahyadridMessagePayloadType::RequestHeaders,
            SahyadridMessagePayload::RequestBlockLocator(_) => SahyadridMessagePayloadType::RequestBlockLocator,
            SahyadridMessagePayload::PruningPoints(_) => SahyadridMessagePayloadType::PruningPoints,
            SahyadridMessagePayload::RequestPruningPointProof(_) => SahyadridMessagePayloadType::RequestPruningPointProof,
            SahyadridMessagePayload::PruningPointProof(_) => SahyadridMessagePayloadType::PruningPointProof,
            SahyadridMessagePayload::Ready(_) => SahyadridMessagePayloadType::Ready,
            SahyadridMessagePayload::BlockWithTrustedDataV4(_) => SahyadridMessagePayloadType::BlockWithTrustedDataV4,
            SahyadridMessagePayload::TrustedData(_) => SahyadridMessagePayloadType::TrustedData,
            SahyadridMessagePayload::RequestIbdChainBlockLocator(_) => SahyadridMessagePayloadType::RequestIbdChainBlockLocator,
            SahyadridMessagePayload::IbdChainBlockLocator(_) => SahyadridMessagePayloadType::IbdChainBlockLocator,
            SahyadridMessagePayload::RequestAntipast(_) => SahyadridMessagePayloadType::RequestAntipast,
            SahyadridMessagePayload::RequestNextPruningPointAndItsAnticoneBlocks(_) => {
                SahyadridMessagePayloadType::RequestNextPruningPointAndItsAnticoneBlocks
            }
            SahyadridMessagePayload::BlockBody(_) => SahyadridMessagePayloadType::BlockBody,
            SahyadridMessagePayload::RequestBlockBodies(_) => SahyadridMessagePayloadType::RequestBlockBodies,
        }
    }
}
