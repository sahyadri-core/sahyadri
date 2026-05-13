use super::error::Result;
use core::fmt::Debug;
use sahyadri_grpc_core::{
    ops::SahyadridPayloadOps,
    protowire::{SahyadridRequest, SahyadridResponse},
};
use std::{sync::Arc, time::Duration};
use tokio::sync::oneshot;

pub(crate) mod id;
pub(crate) mod matcher;
pub(crate) mod queue;

pub(crate) trait Resolver: Send + Sync + Debug {
    fn register_request(&self, op: SahyadridPayloadOps, request: &SahyadridRequest) -> SahyadridResponseReceiver;
    fn handle_response(&self, response: SahyadridResponse);
    fn remove_expired_requests(&self, timeout: Duration);
}

pub(crate) type DynResolver = Arc<dyn Resolver>;

pub(crate) type SahyadridResponseSender = oneshot::Sender<Result<SahyadridResponse>>;
pub(crate) type SahyadridResponseReceiver = oneshot::Receiver<Result<SahyadridResponse>>;
