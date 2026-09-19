use crate::{
    miner::MinerManager,
    proto::{
        rpc_client::RpcClient,
        sahyadrid_request::Payload as ReqPayload,
        sahyadrid_response::Payload as ResPayload,
        GetBlockTemplateRequestMessage, GetInfoRequestMessage, RpcNotifyCommand, SahyadridRequest,
        SahyadridResponse, NotifyNewBlockTemplateRequestMessage,
    },
    Error, ShutdownHandler,
};
use log::{error, info, warn};
use tokio::sync::mpsc::{self, error::SendError, Sender};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{transport::Channel as TonicChannel, Streaming};

static EXTRA_DATA: &str = concat!(env!("CARGO_PKG_VERSION"));

#[allow(dead_code)]
pub struct SahyadridHandler {
    client: RpcClient<TonicChannel>,
    pub send_channel: Sender<SahyadridRequest>,
    stream: Streaming<SahyadridResponse>,
    miner_address: String,
    mine_when_not_synced: bool,
    devfund_address: Option<String>,
    devfund_percent: u16,
    block_template_ctr: u64,
    next_id: u64,
}

impl SahyadridHandler {
    pub async fn connect<D>(address: D, miner_address: String, mine_when_not_synced: bool) -> Result<Self, Error>
    where
        D: TryInto<tonic::transport::Endpoint>,
        D::Error: Into<Error>,
    {
        let mut client = RpcClient::connect(address).await?;
        let (send_channel, recv) = mpsc::channel(3);

        let stream = client.message_stream(ReceiverStream::new(recv)).await?.into_inner();

        let mut handler = Self {
            client,
            send_channel,
            stream,
            miner_address,
            mine_when_not_synced,
            devfund_address: None,
            devfund_percent: 0,
            block_template_ctr: 0,
            next_id: 1,
        };

        // Send initial GetInfo
        handler
            .send_channel
            .send(SahyadridRequest {
                id: handler.next_id,
                payload: Some(ReqPayload::GetInfoRequest(GetInfoRequestMessage {})),
            })
            .await?;
        handler.next_id += 1;

        // Request initial block template
        handler
            .send_channel
            .send(SahyadridRequest {
                id: handler.next_id,
                payload: Some(ReqPayload::GetBlockTemplateRequest(GetBlockTemplateRequestMessage {
                    pay_address: handler.miner_address.clone(),
                    extra_data: EXTRA_DATA.into(),
                })),
            })
            .await?;
        handler.next_id += 1;

        Ok(handler)
    }

    pub fn add_devfund(&mut self, address: String, percent: u16) {
        self.devfund_address = Some(address);
        self.devfund_percent = percent;
    }

    pub async fn client_send(
        &mut self,
        payload: ReqPayload,
    ) -> Result<(), SendError<SahyadridRequest>> {
        let id = self.next_id;
        self.next_id += 1;
        self.send_channel.send(SahyadridRequest { id, payload: Some(payload) }).await
    }

    pub async fn client_get_block_template(&mut self) -> Result<(), SendError<SahyadridRequest>> {
        let pay_address = match &self.devfund_address {
            Some(devfund_address) if (self.block_template_ctr % 10_000) as u16 <= self.devfund_percent => {
                devfund_address.clone()
            }
            _ => self.miner_address.clone(),
        };
        self.block_template_ctr += 1;
        self.client_send(ReqPayload::GetBlockTemplateRequest(GetBlockTemplateRequestMessage {
            pay_address,
            extra_data: EXTRA_DATA.into(),
        }))
        .await
    }

    pub async fn client_notify_new_block_template(
        &mut self,
    ) -> Result<(), SendError<SahyadridRequest>> {
        self.client_send(ReqPayload::NotifyNewBlockTemplateRequest(NotifyNewBlockTemplateRequestMessage {
            command: RpcNotifyCommand::NotifyStart as i32,
        }))
        .await
    }

    pub async fn listen(
        &mut self,
        miner: &mut MinerManager,
        shutdown: ShutdownHandler,
    ) -> Result<(), Error> {
        while let Some(msg) = self.stream.message().await? {
            if shutdown.is_shutdown() {
                break;
            }
            match msg.payload {
                Some(payload) => self.handle_message(payload, miner).await?,
                None => warn!("sahyadrid response payload is empty"),
            }
        }
        Ok(())
    }

    async fn handle_message(
        &mut self,
        msg: ResPayload,
        miner: &mut MinerManager,
    ) -> Result<(), Error> {
        match msg {
            ResPayload::NewBlockTemplateNotification(_) => self.client_get_block_template().await?,
            ResPayload::GetBlockTemplateResponse(template) => {
                match (template.block, template.is_synced, template.error) {
                    (Some(b), true, None) => miner.process_block(Some(b))?,
                    (Some(b), false, None) if self.mine_when_not_synced => miner.process_block(Some(b))?,
                    (_, false, None) => miner.process_block(None)?,
                    (_, _, Some(e)) => warn!("GetTemplate returned with an error: {:?}", e),
                    (None, true, None) => error!("No block and No Error!"),
                }
            }
            ResPayload::SubmitBlockResponse(res) => match res.error {
                None => info!("Block submitted successfully!"),
                Some(e) => warn!("Failed submitting block: {:?}", e),
            },
            ResPayload::GetBlockResponse(msg) => {
                if let Some(e) = msg.error {
                    return Err(e.message.into());
                }
                info!("Get block response: {:?}", msg);
            }
            ResPayload::GetInfoResponse(info) => info!("Sahyadrid version: {}", info.server_version),
            ResPayload::NotifyNewBlockTemplateResponse(res) => match res.error {
                None => info!("Registered for new template notifications"),
                Some(e) => error!("Failed registering for new template notifications: {:?}", e),
            },
            msg => info!("Got unknown msg: {:?}", msg),
        }
        Ok(())
    }
}
