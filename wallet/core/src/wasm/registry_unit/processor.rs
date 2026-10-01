use crate::error::Error;
use crate::events::{EventKind, Events};
use crate::imports::*;
use crate::result::Result;
use crate::registry_unit as native;
use crate::wasm::notify::{RegistryUnitProcessorEventTarget, RegistryUnitProcessorNotificationCallback, RegistryUnitProcessorNotificationTypeOrCallback};
use sahyadri_consensus_core::network::NetworkIdT;
use sahyadri_wallet_macros::declare_typescript_wasm_interface as declare;
use sahyadri_wasm_core::events::{Sink, get_event_targets};
use sahyadri_wrpc_wasm::RpcClient;
use workflow_log::log_error;

declare! {
    IRegistryUnitProcessorArgs,
    r#"
    /**
     * RegistryUnitProcessor constructor arguments.
     * 
     * @see {@link RegistryUnitProcessor}, {@link RegistryUnitContext}, {@link RpcClient}, {@link NetworkId}
     * @category Wallet SDK
     */
    export interface IRegistryUnitProcessorArgs {
        /**
         * The RPC client to use for network communication.
         */
        rpc : RpcClient;
        networkId : NetworkId | string;
    }
    "#,
}

pub struct Inner {
    processor: native::RegistryUnitProcessor,
    rpc: RpcClient,

    callbacks: Mutex<AHashMap<EventKind, Vec<Sink>>>,
    task_running: AtomicBool,
    task_ctl: DuplexChannel,
}

impl Inner {
    fn callbacks(&self, event: EventKind) -> Option<Vec<Sink>> {
        let callbacks = self.callbacks.lock().unwrap();
        let all = callbacks.get(&EventKind::All).cloned();
        let target = callbacks.get(&event).cloned();
        match (all, target) {
            (Some(mut vec_all), Some(vec_target)) => {
                vec_all.extend(vec_target);
                Some(vec_all)
            }
            (Some(vec_all), None) => Some(vec_all),
            (None, Some(vec_target)) => Some(vec_target),
            (None, None) => None,
        }
    }
}

cfg_if! {
    if #[cfg(any(feature = "wasm32-core", feature = "wasm32-sdk"))] {
        #[wasm_bindgen(typescript_custom_section)]
        const TS_NOTIFY: &'static str = r#"
        interface RegistryUnitProcessor {
            /**
            * @param {RegistryUnitProcessorNotificationCallback} callback
            */
            addEventListener(callback: RegistryUnitProcessorNotificationCallback): void;
            /**
            * @param {RegistryUnitProcessorEventType} event
            * @param {RegistryUnitProcessorNotificationCallback} [callback]
            */
            addEventListener<E extends keyof RegistryUnitProcessorEventMap>(
                event: E,
                callback: RegistryUnitProcessorNotificationCallback<E>
            )
        }"#;
    }
}

///
/// RegistryUnitProcessor class is the main coordinator that manages REGISTRY_UNIT processing
/// between multiple RegistryUnitContext instances. It acts as a bridge between the
/// Sahyadri node RPC connection, address subscriptions and RegistryUnitContext instances.
///
/// @see {@link IRegistryUnitProcessorArgs},
/// {@link RegistryUnitContext},
/// {@link RpcClient},
/// {@link NetworkId},
/// {@link IConnectEvent}
/// {@link IDisconnectEvent}
/// @category Wallet SDK
///
#[derive(Clone, CastFromJs)]
#[wasm_bindgen(inspectable)]
pub struct RegistryUnitProcessor {
    inner: Arc<Inner>,
}

#[wasm_bindgen]
impl RegistryUnitProcessor {
    /// RegistryUnitProcessor constructor.
    ///
    ///
    ///
    /// @see {@link IRegistryUnitProcessorArgs}
    #[wasm_bindgen(constructor)]
    pub fn ctor(js_value: IRegistryUnitProcessorArgs) -> Result<RegistryUnitProcessor> {
        let RegistryUnitProcessorCreateArgs { rpc, network_id } = js_value.try_into()?;
        let rpc_api: Arc<DynRpcApi> = rpc.client().clone();
        let rpc_ctl = rpc.client().rpc_ctl().clone();
        let rpc_binding = Rpc::new(rpc_api, rpc_ctl);
        let processor = native::RegistryUnitProcessor::new(Some(rpc_binding), Some(network_id), None, None);

        let this = RegistryUnitProcessor {
            inner: Arc::new(Inner {
                processor: processor.clone(),
                rpc,
                callbacks: Mutex::new(AHashMap::new()),
                task_running: AtomicBool::new(false),
                task_ctl: DuplexChannel::oneshot(),
            }),
        };

        Ok(this)
    }

    /// Starts the RegistryUnitProcessor and begins processing REGISTRY_UNIT and other notifications.
    pub async fn start(&self) -> Result<()> {
        self.start_notification_task(self.inner.processor.multiplexer()).await?;
        self.inner.processor.start().await?;
        Ok(())
    }

    /// Stops the RegistryUnitProcessor and ends processing REGISTRY_UNIT and other notifications.
    pub async fn stop(&self) -> Result<()> {
        self.inner.processor.stop().await?;
        self.stop_notification_task().await?;
        Ok(())
    }

    #[wasm_bindgen(getter)]
    pub fn rpc(&self) -> RpcClient {
        self.inner.rpc.clone()
    }

    #[wasm_bindgen(getter, js_name = "networkId")]
    pub fn network_id(&self) -> Option<String> {
        self.inner.processor.network_id().ok().map(|network_id| network_id.to_string())
    }

    #[wasm_bindgen(js_name = "setNetworkId")]
    pub fn set_network_id(&self, network_id: &NetworkIdT) -> Result<()> {
        let network_id = NetworkId::try_cast_from(network_id)?;
        self.inner.processor.set_network_id(network_id.as_ref());
        Ok(())
    }

    #[wasm_bindgen(getter, js_name = "isActive")]
    pub fn is_active(&self) -> bool {
        let processor = &self.inner.processor;
        processor.try_rpc_ctl().map(|ctl| ctl.is_connected()).unwrap_or(false) && processor.is_connected() && processor.is_running()
    }

    ///
    /// Set the coinbase transaction maturity period DAA score for a given network.
    /// This controls the DAA period after which the user transactions are considered mature
    /// and the wallet subsystem emits the transaction maturity event.
    ///
    /// @see {@link TransactionRecord}
    /// @see {@link IRegistryUnitProcessorEvent}
    ///
    /// @category Wallet SDK
    ///
    #[wasm_bindgen(js_name = "setCoinbaseTransactionMaturityDAA")]
    pub fn set_coinbase_transaction_maturity_period_daa_js(network_id: &NetworkIdT, value: u64) -> Result<()> {
        let network_id = NetworkId::try_cast_from(network_id)?.into_owned();
        crate::registry_unit::set_coinbase_transaction_maturity_period_daa(&network_id, value);
        Ok(())
    }

    ///
    /// Set the user transaction maturity period DAA score for a given network.
    /// This controls the DAA period after which the user transactions are considered mature
    /// and the wallet subsystem emits the transaction maturity event.
    ///
    /// @see {@link TransactionRecord}
    /// @see {@link IRegistryUnitProcessorEvent}
    ///
    /// @category Wallet SDK
    ///
    #[wasm_bindgen(js_name = "setUserTransactionMaturityDAA")]
    pub fn set_user_transaction_maturity_period_daa_js(network_id: &NetworkIdT, value: u64) -> Result<()> {
        let network_id = NetworkId::try_cast_from(network_id)?.into_owned();
        crate::registry_unit::set_user_transaction_maturity_period_daa(&network_id, value);
        Ok(())
    }
}

impl TryCastFromJs for RegistryUnitProcessor {
    type Error = workflow_wasm::error::Error;
    fn try_cast_from<'a, R>(value: &'a R) -> Result<Cast<'a, Self>, Self::Error>
    where
        R: AsRef<JsValue> + 'a,
    {
        Self::try_ref_from_js_value_as_cast(value)
    }
}

pub struct RegistryUnitProcessorCreateArgs {
    rpc: RpcClient,
    network_id: NetworkId,
}

impl TryFrom<IRegistryUnitProcessorArgs> for RegistryUnitProcessorCreateArgs {
    type Error = Error;
    fn try_from(value: IRegistryUnitProcessorArgs) -> std::result::Result<Self, Self::Error> {
        if let Some(object) = Object::try_from(&value) {
            let rpc = object.get_value("rpc")?;
            let rpc = RpcClient::try_ref_from_js_value(&rpc)?.clone();
            let network_id = object.get::<NetworkId>("networkId")?;
            Ok(RegistryUnitProcessorCreateArgs { rpc, network_id })
        } else {
            Err(Error::custom("RegistryUnitProcessor: supplied value must be an object"))
        }
    }
}

impl RegistryUnitProcessor {
    pub fn inner(&self) -> &Arc<Inner> {
        &self.inner
    }

    pub fn processor(&self) -> &native::RegistryUnitProcessor {
        &self.inner.processor
    }

    pub async fn start_notification_task(&self, multiplexer: &Multiplexer<Box<Events>>) -> Result<()> {
        let inner = self.inner.clone();

        if inner.task_running.load(Ordering::SeqCst) {
            log_error!("You are calling `RegistryUnitProcessor.start()` twice without calling `RegistryUnitProcessor.stop()`!");
            panic!("RegistryUnitProcessor background task is already running");
        } else {
            inner.task_running.store(true, Ordering::SeqCst);
        }

        let ctl_receiver = inner.task_ctl.request.receiver.clone();
        let ctl_sender = inner.task_ctl.response.sender.clone();
        let channel = multiplexer.channel();

        spawn(async move {
            loop {
                select! {
                    _ = ctl_receiver.recv().fuse() => {
                        break;
                    },
                    msg = channel.receiver.recv().fuse() => {
                        if let Ok(notification) = &msg {
                            let event_type = EventKind::from(notification.as_ref());
                            let callbacks = inner.callbacks(event_type);
                            if let Some(handlers) = callbacks {
                                for handler in handlers.into_iter() {
                                    let value = notification.as_ref().to_js_value();
                                    if let Err(err) = handler.call(&value) {
                                        log_error!("Error while executing notification callback: {:?}", err);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            channel.close();
            inner.task_running.store(false, Ordering::SeqCst);
            ctl_sender.send(()).await.ok();
        });

        Ok(())
    }

    pub async fn stop_notification_task(&self) -> Result<()> {
        let inner = &self.inner;
        if inner.task_running.load(Ordering::SeqCst) {
            inner.task_ctl.signal(()).await.map_err(|err| JsValue::from_str(&err.to_string()))?;
        }
        Ok(())
    }
}

#[wasm_bindgen]
impl RegistryUnitProcessor {
    #[wasm_bindgen(js_name = "addEventListener", skip_typescript)]
    pub fn add_event_listener(
        &self,
        event: RegistryUnitProcessorNotificationTypeOrCallback,
        callback: Option<RegistryUnitProcessorNotificationCallback>,
    ) -> Result<()> {
        if let Ok(sink) = Sink::try_from(&event) {
            let event = EventKind::All;
            self.inner.callbacks.lock().unwrap().entry(event).or_default().push(sink);
            Ok(())
        } else if let Some(Ok(sink)) = callback.map(Sink::try_from) {
            let targets: Vec<EventKind> = get_event_targets(event)?;
            for event in targets {
                self.inner.callbacks.lock().unwrap().entry(event).or_default().push(sink.clone());
            }
            Ok(())
        } else {
            Err(Error::custom("Invalid event listener callback"))
        }
    }

    #[wasm_bindgen(js_name = "removeEventListener")]
    pub fn remove_event_listener(
        &self,
        event: RegistryUnitProcessorEventTarget,
        callback: Option<RegistryUnitProcessorNotificationCallback>,
    ) -> Result<()> {
        let mut callbacks = self.inner.callbacks.lock().unwrap();
        if let Ok(sink) = Sink::try_from(&event) {
            // remove callback from all events
            for handlers in callbacks.values_mut() {
                handlers.retain(|handler| handler != &sink);
            }
        } else if let Some(Ok(sink)) = callback.map(Sink::try_from) {
            // remove callback from specific events
            let targets: Vec<EventKind> = get_event_targets(event)?;
            for target in targets.into_iter() {
                callbacks.entry(target).and_modify(|handlers| {
                    handlers.retain(|handler| handler != &sink);
                });
            }
        } else {
            // remove all callbacks for the event
            let targets: Vec<EventKind> = get_event_targets(event)?;
            for event in targets {
                callbacks.remove(&event);
            }
        }
        Ok(())
    }
}
