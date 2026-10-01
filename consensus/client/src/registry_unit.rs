//!
//! # REGISTRY_UNIT client-side data structures.
//!
//! This module provides client-side data structures for REGISTRY_UNIT management.
//! In particular, the [`RegistryUnit`] and [`RegistryUnitRef`] structs
//! are used to represent REGISTRY_UNIT entries in the wallet subsystem and WASM bindings.
//!

#![allow(non_snake_case)]

use crate::imports::*;
use crate::outpoint::{RegistryRef, RegistryRefInner};
use crate::result::Result;
use sahyadri_addresses::Address;
use sahyadri_consensus_core::mass::{RegistryUnitCell, RegistryUnitPlurality};

#[wasm_bindgen(typescript_custom_section)]
const TS_REGISTRY_UNIT_ENTRY: &'static str = r#"
/**
 * Interface defines the structure of a REGISTRY_UNIT entry.
 * 
 * @category Consensus
 */
export interface IRegistryUnit {
    /** @readonly */
    address?: Address;
    /** @readonly */
    outpoint: IRegistryRef;
    /** @readonly */
    amount : bigint;
    /** @readonly */
    scriptPublicKey : IScriptPublicKey;
    /** @readonly */
    blockDaaScore: bigint;
    /** @readonly */
    isCoinbase: boolean;
}

"#;

#[wasm_bindgen]
extern "C" {
    /// WASM type representing an array of [`RegistryUnitRef`] objects (i.e. `RegistryUnitRef[]`)
    #[wasm_bindgen(extends = Array, typescript_type = "RegistryUnitRef[]")]
    pub type RegistryUnitRefArrayT;
    /// WASM type representing a REGISTRY_UNIT entry interface (a REGISTRY_UNIT-like object)
    #[wasm_bindgen(typescript_type = "IRegistryUnit")]
    pub type IRegistryUnit;
    /// WASM type representing an array of REGISTRY_UNIT entries (i.e. `IRegistryUnit[]`)
    #[wasm_bindgen(typescript_type = "IRegistryUnit[]")]
    pub type IRegistryUnitArray;
}

/// A REGISTRY_UNIT entry Id is a unique identifier for a REGISTRY_UNIT entry defined by the `txid+output_index`.
pub type RegistryUnitId = RegistryRefInner;

/// [`RegistryUnit`] struct represents a client-side REGISTRY_UNIT entry.
///
/// @category Wallet SDK
#[derive(Clone, Debug, Serialize, Deserialize, CastFromJs)]
#[serde(rename_all = "camelCase")]
#[wasm_bindgen(inspectable)]
pub struct RegistryUnit {
    #[wasm_bindgen(getter_with_clone)]
    pub address: Option<Address>,
    #[wasm_bindgen(getter_with_clone)]
    pub outpoint: RegistryRef,
    pub amount: u64,
    #[wasm_bindgen(js_name = scriptPublicKey, getter_with_clone)]
    pub script_public_key: ScriptPublicKey,
    #[wasm_bindgen(js_name = blockDaaScore)]
    pub block_daa_score: u64,
    #[wasm_bindgen(js_name = isCoinbase)]
    pub is_coinbase: bool,
}

#[wasm_bindgen]
impl RegistryUnit {
    #[wasm_bindgen(js_name = toString)]
    pub fn js_to_string(&self) -> Result<js_sys::JsString> {
        //SerializableRegistryUnit::from(self).serialize_to_json()
        Ok(js_sys::JSON::stringify(&self.to_js_object()?.into())?)
    }
}

impl RegistryUnit {
    #[inline(always)]
    pub fn amount(&self) -> u64 {
        self.amount
    }
    #[inline(always)]
    pub fn block_daa_score(&self) -> u64 {
        self.block_daa_score
    }

    #[inline(always)]
    pub fn is_coinbase(&self) -> bool {
        self.is_coinbase
    }

    fn to_js_object(&self) -> Result<js_sys::Object> {
        let obj = js_sys::Object::new();
        if let Some(address) = &self.address {
            obj.set("address", &address.to_string().into())?;
        }

        let outpoint = js_sys::Object::new();
        outpoint.set("transactionId", &self.outpoint.transaction_id().to_string().into())?;
        outpoint.set("index", &self.outpoint.index().into())?;

        obj.set("amount", &self.amount.to_string().into())?;
        obj.set("outpoint", &outpoint.into())?;
        obj.set("scriptPublicKey", &workflow_wasm::serde::to_value(&self.script_public_key)?)?;
        obj.set("blockDaaScore", &self.block_daa_score.to_string().into())?;
        obj.set("isCoinbase", &self.is_coinbase.into())?;

        Ok(obj)
    }
}

impl AsRef<RegistryUnit> for RegistryUnit {
    fn as_ref(&self) -> &RegistryUnit {
        self
    }
}

impl From<&RegistryUnit> for cctx::RegistryUnit {
    fn from(registry_unit: &RegistryUnit) -> Self {
        cctx::RegistryUnit {
            amount: registry_unit.amount,
            script_public_key: registry_unit.script_public_key.clone(),
            block_daa_score: registry_unit.block_daa_score,
            is_coinbase: registry_unit.is_coinbase,
        }
        // value.entry.clone()
    }
}

/// [`Arc`] reference to a [`RegistryUnit`] used by the wallet subsystems.
///
/// @category Wallet SDK
#[derive(Clone, Debug, Serialize, Deserialize, CastFromJs)]
#[wasm_bindgen(inspectable)]
pub struct RegistryUnitRef {
    #[wasm_bindgen(skip)]
    pub registry_unit: Arc<RegistryUnit>,
}

#[wasm_bindgen]
impl RegistryUnitRef {
    #[wasm_bindgen(js_name = toString)]
    pub fn js_to_string(&self) -> Result<js_sys::JsString> {
        //let entry = workflow_wasm::serde::to_value(&SerializableRegistryUnit::from(self))?;
        let object = js_sys::Object::new();
        object.set("entry", &self.registry_unit.to_js_object()?.into())?;
        Ok(js_sys::JSON::stringify(&object)?)
    }

    #[wasm_bindgen(getter)]
    pub fn entry(&self) -> RegistryUnit {
        self.as_ref().clone()
    }

    #[wasm_bindgen(getter)]
    pub fn outpoint(&self) -> RegistryRef {
        self.registry_unit.outpoint.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn address(&self) -> Option<Address> {
        self.registry_unit.address.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn amount(&self) -> u64 {
        self.registry_unit.amount()
    }

    #[wasm_bindgen(getter, js_name = "isCoinbase")]
    pub fn is_coinbase(&self) -> bool {
        self.registry_unit.is_coinbase
    }

    #[wasm_bindgen(getter, js_name = "blockDaaScore")]
    pub fn block_daa_score(&self) -> u64 {
        self.registry_unit.block_daa_score
    }

    #[wasm_bindgen(getter, js_name = "scriptPublicKey")]
    pub fn script_public_key(&self) -> ScriptPublicKey {
        self.registry_unit.script_public_key.clone()
    }
}

impl RegistryUnitRef {
    #[inline(always)]
    pub fn id(&self) -> RegistryUnitId {
        self.registry_unit.outpoint.inner().clone()
    }

    #[inline(always)]
    pub fn id_as_ref(&self) -> &RegistryUnitId {
        self.registry_unit.outpoint.inner()
    }

    #[inline(always)]
    pub fn amount_as_ref(&self) -> &u64 {
        &self.registry_unit.amount
    }

    #[inline(always)]
    pub fn transaction_id(&self) -> TransactionId {
        self.registry_unit.outpoint.transaction_id()
    }

    #[inline(always)]
    pub fn transaction_id_as_ref(&self) -> &TransactionId {
        self.registry_unit.outpoint.transaction_id_as_ref()
    }
}

impl std::hash::Hash for RegistryUnitRef {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id().hash(state);
    }
}

impl AsRef<RegistryUnit> for RegistryUnitRef {
    fn as_ref(&self) -> &RegistryUnit {
        &self.registry_unit
    }
}

impl From<RegistryUnitRef> for RegistryUnit {
    fn from(value: RegistryUnitRef) -> Self {
        (*value.registry_unit).clone()
    }
}

impl From<&RegistryUnitRef> for cctx::RegistryUnit {
    fn from(value: &RegistryUnitRef) -> Self {
        value.registry_unit.as_ref().into()
        // (*value.registry_unit).clone()
    }
}

impl From<RegistryUnit> for RegistryUnitRef {
    fn from(entry: RegistryUnit) -> Self {
        Self { registry_unit: Arc::new(entry) }
    }
}

impl From<&RegistryUnitRef> for RegistryUnitCell {
    fn from(entry: &RegistryUnitRef) -> Self {
        Self::new(entry.registry_unit.script_public_key.plurality(), entry.amount())
    }
}

impl Eq for RegistryUnitRef {}

impl PartialEq for RegistryUnitRef {
    fn eq(&self, other: &Self) -> bool {
        self.id() == other.id()
    }
}

impl Ord for RegistryUnitRef {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.id().cmp(&other.id())
    }
}

impl PartialOrd for RegistryUnitRef {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// An extension trait to convert a JS value into a vec of REGISTRY_UNIT entry references.
pub trait TryIntoRegistryUnitRefs {
    fn try_into_registry_unit_entry_references(&self) -> Result<Vec<RegistryUnitRef>>;
}

impl TryIntoRegistryUnitRefs for JsValue {
    fn try_into_registry_unit_entry_references(&self) -> Result<Vec<RegistryUnitRef>> {
        Array::from(self).iter().map(RegistryUnitRef::try_owned_from).collect()
    }
}

impl TryCastFromJs for RegistryUnit {
    type Error = Error;
    fn try_cast_from<'a, R>(value: &'a R) -> Result<Cast<'a, Self>, Self::Error>
    where
        R: AsRef<JsValue> + 'a,
    {
        Ok(Self::try_ref_from_js_value_as_cast(value)?)
    }
}

/// A simple collection of REGISTRY_UNIT entries. This struct is used to
/// retain a set of REGISTRY_UNIT entries in the WASM memory for faster
/// processing. This struct keeps a list of entries represented
/// by `RegistryUnitRef` struct. This data structure is used
/// internally by the framework, but is exposed for convenience.
/// Please consider using `RegistryUnitContext` instead.
/// @category Wallet SDK
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
#[wasm_bindgen(inspectable)]
pub struct RegistryUnitEntries(Arc<Vec<RegistryUnitRef>>);

impl RegistryUnitEntries {
    pub fn contains(&self, entry: &RegistryUnitRef) -> bool {
        self.0.contains(entry)
    }

    pub fn iter(&self) -> impl Iterator<Item = &RegistryUnitRef> {
        self.0.iter()
    }
}

#[wasm_bindgen]
impl RegistryUnitEntries {
    /// Create a new `RegistryUnitEntries` struct with a set of entries.
    #[wasm_bindgen(constructor)]
    pub fn js_ctor(js_value: JsValue) -> Result<RegistryUnitEntries> {
        js_value.try_into()
    }

    #[wasm_bindgen(getter = items)]
    pub fn get_items_as_js_array(&self) -> JsValue {
        let items = self.0.as_ref().clone().into_iter().map(<RegistryUnitRef as Into<JsValue>>::into);
        Array::from_iter(items).into()
    }

    #[wasm_bindgen(setter = items)]
    pub fn set_items_from_js_array(&mut self, js_value: &JsValue) {
        let items = Array::from(js_value)
            .iter()
            .map(|js_value| {
                RegistryUnitRef::try_owned_from(&js_value).unwrap_or_else(|err| panic!("invalid RegistryUnitRef: {err}"))
            })
            .collect::<Vec<_>>();
        self.0 = Arc::new(items);
    }

    /// Sort the contained entries by amount. Please note that
    /// this function is not intended for use with large REGISTRY_UNIT sets
    /// as it duplicates the whole contained REGISTRY_UNIT set while sorting.
    pub fn sort(&mut self) {
        let mut items = (*self.0).clone();
        items.sort_by_key(|e| e.amount());
        self.0 = Arc::new(items);
    }

    pub fn amount(&self) -> u64 {
        self.0.iter().map(|e| e.amount()).sum()
    }
}

impl RegistryUnitEntries {
    pub fn items(&self) -> Arc<Vec<RegistryUnitRef>> {
        self.0.clone()
    }
}

impl From<RegistryUnitEntries> for Vec<Option<RegistryUnit>> {
    fn from(value: RegistryUnitEntries) -> Self {
        value.0.as_ref().iter().map(|entry| Some(entry.as_ref().clone())).collect::<Vec<_>>()
    }
}

impl From<Vec<RegistryUnit>> for RegistryUnitEntries {
    fn from(items: Vec<RegistryUnit>) -> Self {
        Self(Arc::new(items.into_iter().map(RegistryUnitRef::from).collect::<_>()))
    }
}

impl From<RegistryUnitEntries> for Vec<Option<cctx::RegistryUnit>> {
    fn from(value: RegistryUnitEntries) -> Self {
        value.0.as_ref().iter().map(|entry| Some(entry.registry_unit.as_ref().into())).collect::<Vec<_>>()
    }
}

impl TryFrom<Vec<Option<RegistryUnit>>> for RegistryUnitEntries {
    type Error = Error;
    fn try_from(value: Vec<Option<RegistryUnit>>) -> std::result::Result<Self, Self::Error> {
        let mut list = vec![];
        for entry in value.into_iter() {
            list.push(entry.ok_or(Error::Custom("Unable to cast `Vec<Option<RegistryUnit>>` into `RegistryUnitEntries`.".to_string()))?.into());
        }

        Ok(Self(Arc::new(list)))
    }
}

impl From<Vec<RegistryUnitRef>> for RegistryUnitEntries {
    fn from(list: Vec<RegistryUnitRef>) -> Self {
        Self(Arc::new(list))
    }
}

impl TryFrom<JsValue> for RegistryUnitEntries {
    type Error = Error;
    fn try_from(js_value: JsValue) -> std::result::Result<Self, Self::Error> {
        if !js_value.is_array() {
            return Err("Data type supplied to RegistryUnitEntries must be an Array".into());
        }

        Ok(Self(Arc::new(js_value.try_into_registry_unit_entry_references()?)))
    }
}

impl TryCastFromJs for RegistryUnitRef {
    type Error = Error;
    fn try_cast_from<'a, R>(value: &'a R) -> Result<Cast<'a, Self>, Self::Error>
    where
        R: AsRef<JsValue> + 'a,
    {
        Self::resolve(value, || {
            if let Ok(registry_unit_entry) = RegistryUnit::try_ref_from_js_value(&value) {
                Ok(Self::from(registry_unit_entry.clone()))
            } else if let Some(object) = Object::try_from(value.as_ref()) {
                let address = object.try_cast_into::<Address>("address")?;
                let outpoint = RegistryRef::try_from(object.get_value("outpoint")?.as_ref())?;
                let registry_unit_entry = Object::from(object.get_value("registry_unitEntry")?);

                let registry_unit_entry = if !registry_unit_entry.is_undefined() {
                    let amount = registry_unit_entry.get_u64("amount").map_err(|_| {
                        Error::custom("Supplied object does not contain `registry_unitEntry.amount` property (or it is not a numerical value)")
                    })?;
                    let script_public_key = ScriptPublicKey::try_owned_from(registry_unit_entry.get_value("scriptPublicKey")?)
                        .map_err(|_|Error::custom("Supplied object does not contain `registry_unitEntry.scriptPublicKey` property (or it is not a hex string or a ScriptPublicKey class)"))?;
                    let block_daa_score = registry_unit_entry.get_u64("blockDaaScore").map_err(|_| {
                        Error::custom(
                            "Supplied object does not contain `registry_unitEntry.blockDaaScore` property (or it is not a numerical value)",
                        )
                    })?;
                    let is_coinbase = registry_unit_entry.get_bool("isCoinbase")?;

                    RegistryUnit { address, outpoint, amount, script_public_key, block_daa_score, is_coinbase }
                } else {
                    let amount = object.get_u64("amount").map_err(|_| {
                        Error::custom("Supplied object does not contain `amount` property (or it is not a numerical value)")
                    })?;
                    let script_public_key = ScriptPublicKey::try_owned_from(object.get_value("scriptPublicKey")?)
                        .map_err(|_|Error::custom("Supplied object does not contain `scriptPublicKey` property (or it is not a hex string or a ScriptPublicKey class)"))?;
                    let block_daa_score = object.get_u64("blockDaaScore").map_err(|_| {
                        Error::custom("Supplied object does not contain `blockDaaScore` property (or it is not a numerical value)")
                    })?;
                    let is_coinbase = object.try_get_bool("isCoinbase")?.unwrap_or(false);

                    RegistryUnit { address, outpoint, amount, script_public_key, block_daa_score, is_coinbase }
                };

                Ok(RegistryUnitRef::from(registry_unit_entry))
            } else {
                Err("Data type supplied to RegistryUnitRef must be an object".into())
            }
        })
    }
}

impl RegistryUnitRef {
    pub fn simulated(amount: u64) -> Self {
        use sahyadri_addresses::{Prefix, Version};
        let address = Address::new(Prefix::Testnet, Version::PubKey, &rand::random::<[u8; 32]>());
        Self::simulated_with_address(amount, &address)
    }

    pub fn simulated_with_address(amount: u64, address: &Address) -> Self {
        let outpoint = RegistryRef::simulated();
        let script_public_key = sahyadri_txscript::pay_to_address_script(address);
        let block_daa_score = 0;
        let is_coinbase = false;

        let registry_unit_entry =
            RegistryUnit { address: Some(address.clone()), outpoint, amount, script_public_key, block_daa_score, is_coinbase };

        RegistryUnitRef::from(registry_unit_entry)
    }
}
