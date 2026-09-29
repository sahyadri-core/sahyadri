use crate::converter::consensus::ConsensusConverter;
use sahyadri_notify::collector::CollectorFrom;

pub(crate) type CollectorFromConsensus = CollectorFrom<ConsensusConverter>;
