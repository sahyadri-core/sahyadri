use sahyadri_consensus_core::trusted::{TrustedSahyadriConsensusData, TrustedHeader};

use crate::convert::header::HeaderFormat;
use crate::pb as protowire;

// ----------------------------------------------------------------------------
// consensus_core to protowire
// ----------------------------------------------------------------------------

impl From<(HeaderFormat, &TrustedHeader)> for protowire::DaaBlockV4 {
    fn from(value: (HeaderFormat, &TrustedHeader)) -> Self {
        let (header_format, item) = value;
        Self { header: Some((header_format, &*item.header).into()), sahyadri_consensus_data: Some((&item.sahyadri_consensus).into()) }
    }
}

impl From<&TrustedSahyadriConsensusData> for protowire::BlockSahyadriConsensusDataHashPair {
    fn from(item: &TrustedSahyadriConsensusData) -> Self {
        Self { hash: Some(item.hash.into()), sahyadri_consensus_data: Some((&item.sahyadri_consensus).into()) }
    }
}
