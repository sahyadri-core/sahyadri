use super::client::ListeningClient;
use sahyadri_addresses::Address;
use sahyadri_consensus_core::header::Header;
use sahyadri_grpc_client::GrpcClient;
use sahyadri_rpc_core::{
    BlockAddedNotification, Notification, VirtualDaaScoreChangedNotification, api::rpc::RpcApi,
};
use std::{future::Future, time::Duration};
use tokio::time::timeout;

/// Poll `success` every `sleep_millis` until it returns `true`, or panic
/// with `panic_message` after `max_iterations` attempts.
pub async fn wait_for<Fut>(
    sleep_millis: u64,
    max_iterations: u64,
    success: impl Fn() -> Fut,
    panic_message: &'static str,
) where
    Fut: Future<Output = bool>,
{
    let mut i: u64 = 0;
    loop {
        i += 1;
        tokio::time::sleep(Duration::from_millis(sleep_millis)).await;
        if success().await {
            break;
        } else if i >= max_iterations {
            panic!("{}", panic_message);
        }
    }
}

/// Mine a single block via `submitting_client` and wait for every
/// `listening_clients` node to observe the resulting BlockAdded and
/// VirtualDaaScoreChanged notifications.
pub async fn mine_block(
    pay_address: Address,
    submitting_client: &GrpcClient,
    listening_clients: &[ListeningClient],
) {
    // Discard all unreceived block added notifications in each listening client
    listening_clients.iter().for_each(|x| x.block_added_listener().unwrap().drain());

    // Mine a block
    let template = submitting_client.get_block_template(pay_address.clone(), vec![]).await.unwrap();
    let header: Header = (&template.block.header).try_into().unwrap();
    let block_hash = header.hash;
    submitting_client.submit_block(template.block, false).await.unwrap();

    // Wait for each listening client to get notified the submitted block was added to the DAG
    for client in listening_clients.iter() {
        let block_daa_score: u64 =
            match timeout(Duration::from_millis(500), client.block_added_listener().unwrap().receiver.recv())
                .await
                .unwrap()
                .unwrap()
            {
                Notification::BlockAdded(BlockAddedNotification { block }) => {
                    assert_eq!(block.header.hash, block_hash);
                    block.header.daa_score
                }
                _ => panic!("wrong notification type"),
            };
        match timeout(Duration::from_millis(500), client.virtual_daa_score_changed_listener().unwrap().receiver.recv())
            .await
            .unwrap()
            .unwrap()
        {
            Notification::VirtualDaaScoreChanged(VirtualDaaScoreChangedNotification { virtual_daa_score }) => {
                assert_eq!(virtual_daa_score, block_daa_score + 1);
            }
            _ => panic!("wrong notification type"),
        }
    }
}
