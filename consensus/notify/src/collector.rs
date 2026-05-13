use crate::notification::Notification;
use sahyadri_notify::{collector::CollectorFrom, converter::ConverterFrom};

pub type ConsensusConverter = ConverterFrom<Notification, Notification>;
pub type ConsensusCollector = CollectorFrom<ConsensusConverter>;
