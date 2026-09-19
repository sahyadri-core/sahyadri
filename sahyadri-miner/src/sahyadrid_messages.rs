use crate::{
    pow::{self, HeaderHasher},
    proto::{
        sahyadrid_request::Payload as ReqPayload,
        GetBlockTemplateRequestMessage, GetInfoRequestMessage, NotifyBlockAddedRequestMessage,
        NotifyNewBlockTemplateRequestMessage, RpcBlock, RpcNotifyCommand, SahyadridRequest,
        SubmitBlockRequestMessage,
    },
    Hash,
};

impl SahyadridRequest {
    #[must_use]
    #[inline(always)]
    pub fn get_info_request(id: u64) -> Self {
        SahyadridRequest { id, payload: Some(ReqPayload::GetInfoRequest(GetInfoRequestMessage {})) }
    }
    #[must_use]
    #[inline(always)]
    pub fn notify_block_added(id: u64) -> Self {
        SahyadridRequest {
            id,
            payload: Some(ReqPayload::NotifyBlockAddedRequest(NotifyBlockAddedRequestMessage {
                command: RpcNotifyCommand::NotifyStart as i32,
            })),
        }
    }
    #[must_use]
    #[inline(always)]
    pub fn notify_new_block_template(id: u64) -> Self {
        SahyadridRequest {
            id,
            payload: Some(ReqPayload::NotifyNewBlockTemplateRequest(NotifyNewBlockTemplateRequestMessage {
                command: RpcNotifyCommand::NotifyStart as i32,
            })),
        }
    }
    #[must_use]
    #[inline(always)]
    pub fn submit_block(id: u64, block: RpcBlock) -> Self {
        SahyadridRequest {
            id,
            payload: Some(ReqPayload::SubmitBlockRequest(SubmitBlockRequestMessage {
                block: Some(block),
                allow_non_daa_blocks: false,
            })),
        }
    }
}

impl From<(u64, GetInfoRequestMessage)> for SahyadridRequest {
    #[inline(always)]
    fn from((id, a): (u64, GetInfoRequestMessage)) -> Self {
        SahyadridRequest { id, payload: Some(ReqPayload::GetInfoRequest(a)) }
    }
}

impl From<(u64, GetBlockTemplateRequestMessage)> for SahyadridRequest {
    #[inline(always)]
    fn from((id, a): (u64, GetBlockTemplateRequestMessage)) -> Self {
        SahyadridRequest { id, payload: Some(ReqPayload::GetBlockTemplateRequest(a)) }
    }
}

impl RpcBlock {
    #[must_use]
    #[inline(always)]
    pub fn block_hash(&self) -> Option<Hash> {
        let mut hasher = HeaderHasher::new();
        pow::serialize_header(&mut hasher, self.header.as_ref()?, false);
        Some(hasher.finalize())
    }
}
