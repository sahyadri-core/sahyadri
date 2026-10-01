use crate::imports::*;
use crate::result::Result;
use crate::registry_unit as native;
use crate::registry_unit::{RegistryUnitContextBinding, RegistryUnitContextId};
use crate::wasm::registry_unit::RegistryUnitProcessor;
use crate::wasm::{Balance, BalanceStrings};
use sahyadri_addresses::AddressOrStringArrayT;
use sahyadri_consensus_client::RegistryUnitRefArrayT;
use sahyadri_hashes::Hash;
use sahyadri_wallet_macros::declare_typescript_wasm_interface as declare;

declare! {
    IRegistryUnitContextArgs,
    r#"
    /**
     * RegistryUnitContext constructor arguments.
     * 
     * @see {@link RegistryUnitProcessor}, {@link RegistryUnitContext}, {@link RpcClient}
     * @category Wallet SDK
     */
    export interface IRegistryUnitContextArgs {
        /**
         * Associated RegistryUnitProcessor.
         */
        processor: RegistryUnitProcessor;
        /**
         * Optional id for the RegistryUnitContext.
         * **The id must be a valid 32-byte hex string.**
         * You can use {@link sha256FromBinary} or {@link sha256FromText} to generate a valid id.
         * 
         * If not provided, a random id will be generated.
         * The IDs are deterministic, based on the order RegistryUnitContexts are created.
         */
        id?: HexString;
    }
    "#,
}

///
/// RegistryUnitContext is a class that provides a way to track addresses activity
/// on the Sahyadri network.  When an address is registered with RegistryUnitContext
/// it aggregates all REGISTRY_UNIT entries for that address and emits events when
/// any activity against these addresses occurs.
///
/// RegistryUnitContext constructor accepts {@link IRegistryUnitContextArgs} interface that
/// can contain an optional id parameter.  If supplied, this `id` parameter
/// will be included in all notifications emitted by the RegistryUnitContext as
/// well as included as a part of {@link ITransactionRecord} emitted when
/// transactions occur. If not provided, a random id will be generated. This id
/// typically represents an account id in the context of a wallet application.
/// The integrated Wallet API uses RegistryUnitContext to represent wallet accounts.
///
/// **Exchanges:** if you are building an exchange wallet, it is recommended
/// to use RegistryUnitContext for each user account.  This way you can track and isolate
/// each user activity (use address set, balances, transaction records).
///
/// RegistryUnitContext maintains a real-time cumulative balance of all addresses
/// registered against it and provides balance update notification events
/// when the balance changes.
///
/// The RegistryUnitContext balance is comprised of 3 values:
/// - `mature`: amount of funds available for spending.
/// - `pending`: amount of funds that are being received.
/// - `outgoing`: amount of funds that are being sent but are not yet accepted by the network.
///
/// Please see {@link IBalance} interface for more details.
///
/// RegistryUnitContext can be supplied as a REGISTRY_UNIT source to the transaction {@link Generator}
/// allowing the {@link Generator} to create transactions using the
/// REGISTRY_UNIT entries it manages.
///
/// **IMPORTANT:** RegistryUnitContext is meant to represent a single account.  It is not
/// designed to be used as a global REGISTRY_UNIT manager for all addresses in a very large
/// wallet (such as an exchange wallet). For such use cases, it is recommended to
/// perform manual REGISTRY_UNIT management by subscribing to REGISTRY_UNIT notifications using
/// {@link RpcClient.subscribeRegistryChanged} and {@link RpcClient.getRegistryByAddresses}.
///
/// @see {@link IRegistryUnitContextArgs},
/// {@link RegistryUnitProcessor},
/// {@link Generator},
/// {@link createTransactions},
/// {@link IBalance},
/// {@link IBalanceEvent},
/// {@link IPendingEvent},
/// {@link IReorgEvent},
/// {@link IStasisEvent},
/// {@link IMaturityEvent},
/// {@link IDiscoveryEvent},
/// {@link IBalanceEvent},
/// {@link ITransactionRecord}
///
/// @category Wallet SDK
///
#[derive(Clone, CastFromJs)]
#[wasm_bindgen(inspectable)]
pub struct RegistryUnitContext {
    inner: native::RegistryUnitContext,
}

impl RegistryUnitContext {
    pub fn inner(&self) -> &native::RegistryUnitContext {
        &self.inner
    }

    pub fn context(&self) -> MutexGuard<'_, native::context::Context> {
        self.inner.context()
    }

    pub fn processor(&self) -> &native::RegistryUnitProcessor {
        self.inner.processor()
    }
}

#[wasm_bindgen]
impl RegistryUnitContext {
    #[wasm_bindgen(constructor)]
    pub fn ctor(js_value: IRegistryUnitContextArgs) -> Result<RegistryUnitContext> {
        let RegistryUnitContextCreateArgs { processor, binding } = js_value.try_into()?;
        let inner = native::RegistryUnitContext::new(processor.processor(), binding);
        Ok(RegistryUnitContext { inner })
    }

    /// Performs a scan of the given addresses and registers them in the context for event notifications.
    #[wasm_bindgen(js_name = "trackAddresses")]
    pub async fn track_addresses(&self, addresses: AddressOrStringArrayT, optional_current_daa_score: Option<BigInt>) -> Result<()> {
        let current_daa_score = if let Some(big_int) = optional_current_daa_score {
            Some(big_int.try_into().map_err(|v| Error::custom(format!("Unable to convert BigInt value {v:?}")))?)
        } else {
            None
        };
        let addresses: Vec<Address> = addresses.try_into()?;
        self.inner().scan_and_register_addresses(addresses, current_daa_score).await?;
        Ok(())
    }

    /// Unregister a list of addresses from the context. This will stop tracking of these addresses.
    #[wasm_bindgen(js_name = "unregisterAddresses")]
    pub async fn unregister_addresses(&self, addresses: AddressOrStringArrayT) -> Result<()> {
        let addresses: Vec<Address> = addresses.try_into()?;
        self.inner().unregister_addresses(addresses).await
    }

    /// Clear the RegistryUnitContext.  Unregister all addresses and clear all REGISTRY_UNIT entries.
    /// IMPORTANT: This function must be manually called when disconnecting or re-connecting to the node
    /// (followed by address re-registration).  
    pub async fn clear(&self) -> Result<()> {
        self.inner().clear().await
    }

    #[wasm_bindgen(getter, js_name = "isActive")]
    pub fn active(&self) -> bool {
        let processor = self.inner().processor();
        processor.try_rpc_ctl().map(|ctl| ctl.is_connected()).unwrap_or(false) && processor.is_connected() && processor.is_running()
    }

    // Returns all mature REGISTRY_UNIT entries that are currently managed by the RegistryUnitContext and are available for spending.
    // This function is for informational purposes only.
    // pub fn mature(&self) -> Result<IRegistryUnitRefArray> {
    //     let context = self.context();
    //     let array = Array::new();
    //     for entry in context.mature.iter() {
    //         array.push(&JsValue::from(entry.clone()));
    //     }
    //     Ok(array.unchecked_into())
    // }

    ///
    /// Returns a range of mature REGISTRY_UNIT entries that are currently
    /// managed by the RegistryUnitContext and are available for spending.
    ///
    /// NOTE: This function is provided for informational purposes only.
    /// **You should not manage REGISTRY_UNIT entries manually if they are owned by RegistryUnitContext.**
    ///
    /// The resulting range may be less than requested if REGISTRY_UNIT entries
    /// have been spent asynchronously by RegistryUnitContext or by other means
    /// (i.e. RegistryUnitContext has received notification from the network that
    /// RegistryUnitEntries have been spent externally).
    ///
    /// RegistryUnitEntries are kept in in the ascending sorted order by their amount.
    ///
    #[wasm_bindgen(js_name = "getMatureRange")]
    pub fn mature_range(&self, mut from: usize, mut to: usize) -> Result<RegistryUnitRefArrayT> {
        let context = self.context();
        if from > to {
            return Err(Error::custom("'from' must be less than or equal to 'to'"));
        }
        if from > context.mature.len() {
            from = context.mature.len();
        }
        if to > context.mature.len() {
            to = context.mature.len();
        }
        if from == to {
            return Ok(Array::new().unchecked_into());
        }
        let slice = context.mature.get(from..to).unwrap();
        let array = Array::new();
        for entry in slice.iter() {
            array.push(&JsValue::from(entry.clone()));
        }
        Ok(array.unchecked_into())
    }

    /// Obtain the length of the mature REGISTRY_UNIT entries that are currently
    /// managed by the RegistryUnitContext.
    #[wasm_bindgen(getter, js_name = "matureLength")]
    pub fn mature_length(&self) -> usize {
        self.context().mature.len()
    }

    /// Returns pending REGISTRY_UNIT entries that are currently managed by the RegistryUnitContext.
    #[wasm_bindgen(js_name = "getPending")]
    pub fn pending(&self) -> Result<RegistryUnitRefArrayT> {
        let context = self.context();
        let array = Array::new();
        for entry in context.pending.values() {
            array.push(&JsValue::from(entry.clone()));
        }
        Ok(array.unchecked_into())
    }

    /// Current {@link Balance} of the RegistryUnitContext.
    #[wasm_bindgen(getter, js_name = "balance")]
    pub fn balance(&self) -> Option<Balance> {
        self.inner().balance().map(Balance::from)
    }

    /// Current {@link BalanceStrings} of the RegistryUnitContext.
    #[wasm_bindgen(getter, js_name = "balanceStrings")]
    pub fn balance_strings(&self) -> Result<Option<BalanceStrings>> {
        let network_id = self.inner.processor().network_id().ok();
        if let (Some(network_id), Some(balance)) = (network_id, self.inner().balance()) {
            let balance_strings = balance.to_balance_strings(&network_id.into(), None);
            Ok(Some(BalanceStrings::from(balance_strings)))
        } else {
            Ok(None)
        }
    }
}

impl From<native::RegistryUnitContext> for RegistryUnitContext {
    fn from(inner: native::RegistryUnitContext) -> Self {
        Self { inner }
    }
}

impl From<RegistryUnitContext> for native::RegistryUnitContext {
    fn from(registry_unit_context: RegistryUnitContext) -> Self {
        registry_unit_context.inner
    }
}

impl TryCastFromJs for RegistryUnitContext {
    type Error = Error;
    fn try_cast_from<'a, R>(value: &'a R) -> Result<Cast<'a, Self>, Self::Error>
    where
        R: AsRef<JsValue> + 'a,
    {
        Ok(Self::try_ref_from_js_value_as_cast(value)?)
    }
}

pub struct RegistryUnitContextCreateArgs {
    processor: RegistryUnitProcessor,
    binding: RegistryUnitContextBinding,
}

impl TryFrom<IRegistryUnitContextArgs> for RegistryUnitContextCreateArgs {
    type Error = Error;
    fn try_from(value: IRegistryUnitContextArgs) -> std::result::Result<Self, Self::Error> {
        if let Some(object) = Object::try_from(&value) {
            let processor = object.cast_into::<RegistryUnitProcessor>("processor")?;

            let binding = if let Some(id) = object.try_cast_into::<Hash>("id")? {
                RegistryUnitContextBinding::Id(RegistryUnitContextId::new(id))
            } else {
                RegistryUnitContextBinding::default()
            };

            Ok(RegistryUnitContextCreateArgs { binding, processor })
        } else {
            Err(Error::custom("RegistryUnitProcessor: supplied value must be an object"))
        }
    }
}
