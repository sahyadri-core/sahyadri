use crate::{flow_context::FlowContext, flow_trait::Flow};
use async_trait::async_trait;
use sahyadri_core::{info, warn};
use sahyadri_p2p_lib::{
    IncomingRoute, Router, BlockRootProof,
    common::ProtocolError,
    pb::sahyadrid_message::Payload,
};
use std::sync::Arc;

pub struct HandleBlockRootProofFlow {
    ctx: FlowContext,
    router: Arc<Router>,
    incoming_route: IncomingRoute,
}

#[async_trait]
impl Flow for HandleBlockRootProofFlow {
    fn router(&self) -> Option<Arc<Router>> {
        Some(self.router.clone())
    }

    async fn start(&mut self) -> Result<(), ProtocolError> {
        while let Some(msg) = self.incoming_route.recv().await {
            let Some(Payload::BlockRootProof(proto)) = msg.payload else {
                continue;
            };

            let proof: BlockRootProof = match proto.try_into() {
                Ok(p) => p,
                Err(e) => {
                    warn!("P2P: malformed BlockRootProof: {e:?}");
                    continue;
                }
            };

            info!(
                "P2P: received BlockRootProof for {} (N={}, {} bytes)",
                proof.block_hash,
                proof.aggregated_count,
                proof.proof_bytes.len()
            );

            let session = self.ctx.consensus().session().await;
            if let Err(e) = session
                .async_verify_and_insert_block_proof(
                    proof.block_hash,
                    proof.blue_score,
                    proof.aggregated_count,
                    proof.proof_bytes,
                )
                .await
            {
                warn!("P2P: failed to store BlockRootProof: {e:?}");
            }
        }
        Ok(())
    }
}

impl HandleBlockRootProofFlow {
    pub fn new(ctx: FlowContext, router: Arc<Router>, incoming_route: IncomingRoute) -> Self {
        Self { ctx, router, incoming_route }
    }
}
