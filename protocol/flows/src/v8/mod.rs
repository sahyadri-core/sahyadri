pub(crate) mod block_root_proof;
use block_root_proof::HandleBlockRootProofFlow;
use crate::v7::{
    address::{ReceiveAddressesFlow, SendAddressesFlow},
    blockrelay::{flow::HandleRelayInvsFlow, handle_requests::HandleRelayBlockRequests},
    ping::{ReceivePingsFlow, SendPingsFlow},
    request_antipast::HandleAntipastRequests,
    request_block_locator::RequestBlockLocatorFlow,
    request_headers::RequestHeadersFlow,
    request_ibd_blocks::HandleIbdBlockRequests,
    request_ibd_chain_block_locator::RequestIbdChainBlockLocatorFlow,
    request_pp_proof::RequestPruningPointProofFlow,
    request_pruning_point_and_anticone::PruningPointAndItsAnticoneRequestsFlow,
    request_pruning_point_registry_unit_set::RequestPruningPointRegistryUnitSetFlow,
    txrelay::flow::{RelayTransactionsFlow, RequestTransactionsFlow},
};
pub(crate) mod request_block_bodies;
use crate::{flow_context::FlowContext, flow_trait::Flow};

use crate::ibd::IbdFlow;
use request_block_bodies::HandleBlockBodyRequests;
use sahyadri_p2p_lib::{Router, SahyadridMessagePayloadType, SharedIncomingRoute, convert::header::HeaderFormat};
use sahyadri_utils::channel;
use std::sync::Arc;

pub fn register(ctx: FlowContext, router: Arc<Router>, protocol_version: u32) -> Vec<Box<dyn Flow>> {
    // IBD flow <-> invs flow communication uses a job channel in order to always
    // maintain at most a single pending job which can be updated
    let (ibd_sender, relay_receiver) = channel::job();
    let body_only_ibd_permitted = true;
    let header_format = HeaderFormat::from(protocol_version);
    let mut flows: Vec<Box<dyn Flow>> = vec![
        Box::new(IbdFlow::new(
            ctx.clone(),
            router.clone(),
            router.subscribe(vec![
                SahyadridMessagePayloadType::BlockHeaders,
                SahyadridMessagePayloadType::DoneHeaders,
                SahyadridMessagePayloadType::IbdBlockLocatorHighestHash,
                SahyadridMessagePayloadType::IbdBlockLocatorHighestHashNotFound,
                SahyadridMessagePayloadType::BlockWithTrustedDataV4,
                SahyadridMessagePayloadType::DoneBlocksWithTrustedData,
                SahyadridMessagePayloadType::IbdChainBlockLocator,
                SahyadridMessagePayloadType::IbdBlock,
                SahyadridMessagePayloadType::BlockBody,
                SahyadridMessagePayloadType::TrustedData,
                SahyadridMessagePayloadType::PruningPoints,
                SahyadridMessagePayloadType::PruningPointProof,
                SahyadridMessagePayloadType::UnexpectedPruningPoint,
                SahyadridMessagePayloadType::PruningPointRegistryUnitSetChunk,
                SahyadridMessagePayloadType::DonePruningPointRegistryUnitSetChunks,
            ]),
            relay_receiver,
            body_only_ibd_permitted,
            header_format,
        )),
        Box::new(HandleBlockRootProofFlow::new(
            ctx.clone(),
            router.clone(),
            router.subscribe(vec![SahyadridMessagePayloadType::BlockRootProof]),
        )),
        Box::new(HandleRelayBlockRequests::new(
            ctx.clone(),
            router.clone(),
            router.subscribe(vec![SahyadridMessagePayloadType::RequestRelayBlocks]),
            header_format,
        )),
        Box::new(ReceivePingsFlow::new(ctx.clone(), router.clone(), router.subscribe(vec![SahyadridMessagePayloadType::Ping]))),
        Box::new(SendPingsFlow::new(ctx.clone(), router.clone(), router.subscribe(vec![SahyadridMessagePayloadType::Pong]))),
        Box::new(RequestHeadersFlow::new(
            ctx.clone(),
            router.clone(),
            router.subscribe(vec![SahyadridMessagePayloadType::RequestHeaders, SahyadridMessagePayloadType::RequestNextHeaders]),
            header_format,
        )),
        Box::new(RequestPruningPointProofFlow::new(
            ctx.clone(),
            router.clone(),
            router.subscribe(vec![SahyadridMessagePayloadType::RequestPruningPointProof]),
            header_format,
        )),
        Box::new(RequestIbdChainBlockLocatorFlow::new(
            ctx.clone(),
            router.clone(),
            router.subscribe(vec![SahyadridMessagePayloadType::RequestIbdChainBlockLocator]),
        )),
        Box::new(PruningPointAndItsAnticoneRequestsFlow::new(
            ctx.clone(),
            router.clone(),
            router.subscribe(vec![
                SahyadridMessagePayloadType::RequestPruningPointAndItsAnticone,
                SahyadridMessagePayloadType::RequestNextPruningPointAndItsAnticoneBlocks,
            ]),
            header_format,
        )),
        Box::new(RequestPruningPointRegistryUnitSetFlow::new(
            ctx.clone(),
            router.clone(),
            router.subscribe(vec![
                SahyadridMessagePayloadType::RequestPruningPointRegistryUnitSet,
                SahyadridMessagePayloadType::RequestNextPruningPointRegistryUnitSetChunk,
            ]),
        )),
        Box::new(HandleIbdBlockRequests::new(
            ctx.clone(),
            router.clone(),
            router.subscribe(vec![SahyadridMessagePayloadType::RequestIbdBlocks]),
            header_format,
        )),
        Box::new(HandleBlockBodyRequests::new(
            ctx.clone(),
            router.clone(),
            router.subscribe(vec![SahyadridMessagePayloadType::RequestBlockBodies]),
        )),
        Box::new(HandleAntipastRequests::new(
            ctx.clone(),
            router.clone(),
            router.subscribe(vec![SahyadridMessagePayloadType::RequestAntipast]),
            header_format,
        )),
        Box::new(RelayTransactionsFlow::new(
            ctx.clone(),
            router.clone(),
            router.subscribe_with_capacity(
                vec![SahyadridMessagePayloadType::InvTransactions],
                RelayTransactionsFlow::invs_channel_size(),
            ),
            router.subscribe_with_capacity(
                vec![SahyadridMessagePayloadType::Transaction, SahyadridMessagePayloadType::TransactionNotFound],
                RelayTransactionsFlow::txs_channel_size(),
            ),
        )),
        Box::new(RequestTransactionsFlow::new(
            ctx.clone(),
            router.clone(),
            router.subscribe(vec![SahyadridMessagePayloadType::RequestTransactions]),
        )),
        Box::new(ReceiveAddressesFlow::new(
            ctx.clone(),
            router.clone(),
            router.subscribe(vec![SahyadridMessagePayloadType::Addresses]),
        )),
        Box::new(SendAddressesFlow::new(
            ctx.clone(),
            router.clone(),
            router.subscribe(vec![SahyadridMessagePayloadType::RequestAddresses]),
        )),
        Box::new(RequestBlockLocatorFlow::new(
            ctx.clone(),
            router.clone(),
            router.subscribe(vec![SahyadridMessagePayloadType::RequestBlockLocator]),
        )),
    ];

    let invs_route = router.subscribe_with_capacity(vec![SahyadridMessagePayloadType::InvRelayBlock], ctx.block_invs_channel_size());
    let shared_invs_route = SharedIncomingRoute::new(invs_route);

    let num_relay_flows = (ctx.config.bps() as usize / 2).max(1);
    flows.extend((0..num_relay_flows).map(|_| {
        Box::new(HandleRelayInvsFlow::new(
            ctx.clone(),
            router.clone(),
            shared_invs_route.clone(),
            router.subscribe(vec![]),
            ibd_sender.clone(),
            header_format,
        )) as Box<dyn Flow>
    }));

    // The reject message is handled as a special case by the router
    // SahyadridMessagePayloadType::Reject,

    // We do not register the below two messages since they are deprecated also in go-sahyadri
    // SahyadridMessagePayloadType::BlockWithTrustedData,
    // SahyadridMessagePayloadType::IbdBlockLocator,

    // ── Broadcast root proofs via global worker channel ────────
    // Worker thread signals when a proof is stored; we read here
    // and broadcast to all P2P peers. Event-driven, no polling.
    {
        let ctx_clone = ctx.clone();
        tokio::spawn(async move {
            loop {
                // Block on channel receive — wakes up only when signaled
                match sahyadri_consensus::PROOF_BROADCAST.1.recv_timeout(
                    std::time::Duration::from_secs(30),
                ) {
                    Ok(block_hash) => {
                        let session = ctx_clone.consensus().session().await;
                        match session.async_get_block_proof(block_hash).await {
                            Ok(Some(proof)) => {
                                let msg =
                                    sahyadri_p2p_lib::convert::messages::block_root_proof_to_message(
                                        &proof,
                                    );
                                ctx_clone.hub().broadcast(msg, None).await;
                                log::info!(
                                    "P2P: broadcast BlockRootProof for {} (N={})",
                                    block_hash,
                                    proof.aggregated_count
                                );
                            }
                            Ok(None) => {
                                log::warn!(
                                    "P2P: no proof in store for {} on broadcast",
                                    block_hash
                                );
                            }
                            Err(e) => {
                                log::warn!("P2P: fetch proof {} failed: {e:?}", block_hash);
                            }
                        }
                    }
                    Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                        // Idle — nothing to do
                        continue;
                    }
                    Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                        log::info!("P2P: PROOF_BROADCAST channel disconnected, exiting");
                        break;
                    }
                }
            }
        });
    }

    flows
}
