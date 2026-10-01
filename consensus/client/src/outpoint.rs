//!
//! Implementation of the client-side [`RegistryRef`] used by the [`TransactionInput`] struct.
//!

#![allow(non_snake_case)]

use cfg_if::cfg_if;

use crate::imports::*;
use crate::result::Result;

#[wasm_bindgen(typescript_custom_section)]
const TS_TRANSACTION_OUTPOINT: &'static str = r#"
/**
 * Interface defines the structure of a transaction outpoint (used by transaction input).
 * 
 * @category Consensus
 */
export interface IRegistryRef {
    transactionId: HexString;
    index: number;
}
"#;

/// Inner type used by [`RegistryRef`]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Ord, PartialOrd)]
#[serde(rename_all = "camelCase")]
pub struct RegistryRefInner {
    pub transaction_id: TransactionId,
    pub index: TransactionIndexType,
}

impl std::fmt::Display for RegistryRefInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}-{}", self.transaction_id, self.index)
    }
}

impl RegistryRefInner {
    pub fn new(transaction_id: TransactionId, index: TransactionIndexType) -> Self {
        Self { transaction_id, index }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut data = self.transaction_id.as_bytes().to_vec();
        data.extend(self.index.to_be_bytes());
        data
    }
}

impl From<cctx::RegistryRef> for RegistryRefInner {
    fn from(outpoint: cctx::RegistryRef) -> Self {
        RegistryRefInner { transaction_id: outpoint.transaction_id, index: outpoint.index }
    }
}

impl TryFrom<&JsValue> for RegistryRefInner {
    type Error = Error;
    fn try_from(js_value: &JsValue) -> Result<Self, Self::Error> {
        if let Some(string) = js_value.as_string() {
            let vec = string.split('-').collect::<Vec<_>>();
            if vec.len() == 2 {
                let transaction_id: TransactionId = vec[0].parse()?;
                let id: u32 = vec[1].parse()?;
                Ok(RegistryRefInner::new(transaction_id, id))
            } else {
                Err(Error::InvalidRegistryRef(string))
            }
        } else if let Some(object) = js_sys::Object::try_from(js_value) {
            let transaction_id: TransactionId = object.get_value("transactionId")?.try_into_owned()?;
            let index = object.get_u32("index")?;
            Ok(RegistryRefInner::new(transaction_id, index))
        } else {
            Err("outpoint is not an object".into())
        }
    }
}

/// Represents a Sahyadri transaction outpoint.
/// NOTE: This struct is immutable - to create a custom outpoint
/// use the `RegistryRef::new` constructor. (in JavaScript
/// use `new RegistryRef(transactionId, index)`).
/// @category Consensus
#[derive(Clone, Debug, Serialize, Deserialize, CastFromJs)]
#[serde(rename_all = "camelCase")]
#[wasm_bindgen(inspectable)]
pub struct RegistryRef {
    inner: Arc<RegistryRefInner>,
}

impl RegistryRef {
    pub fn new(transaction_id: TransactionId, index: u32) -> RegistryRef {
        Self { inner: Arc::new(RegistryRefInner { transaction_id, index }) }
    }

    #[inline(always)]
    pub fn inner(&self) -> &RegistryRefInner {
        &self.inner
    }

    #[inline(always)]
    pub fn transaction_id(&self) -> TransactionId {
        self.inner().transaction_id
    }

    #[inline(always)]
    pub fn index(&self) -> TransactionIndexType {
        self.inner().index
    }

    #[inline(always)]
    pub fn transaction_id_as_ref(&self) -> &TransactionId {
        &self.inner().transaction_id
    }

    #[inline(always)]
    pub fn id(&self) -> &RegistryRefInner {
        self.inner()
    }
}

cfg_if! {
    if #[cfg(feature = "wasm32-sdk")] {

        #[wasm_bindgen]
        impl RegistryRef {
            #[wasm_bindgen(constructor)]
            pub fn ctor(transaction_id: TransactionId, index: u32) -> RegistryRef {
                Self { inner: Arc::new(RegistryRefInner { transaction_id, index }) }
            }

            #[wasm_bindgen(js_name = "getId")]
            pub fn id_string(&self) -> String {
                format!("{}-{}", self.get_transaction_id_as_string(), self.get_index())
            }

            #[wasm_bindgen(getter, js_name = transactionId)]
            pub fn get_transaction_id_as_string(&self) -> String {
                self.inner().transaction_id.to_string()
            }

            #[wasm_bindgen(getter, js_name = index)]
            pub fn get_index(&self) -> TransactionIndexType {
                self.inner().index
            }
        }
    }
}

impl std::fmt::Display for RegistryRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let inner = self.inner();
        write!(f, "({}, {})", inner.transaction_id, inner.index)
    }
}

impl TryFrom<&JsValue> for RegistryRef {
    type Error = Error;
    fn try_from(js_value: &JsValue) -> Result<Self, Self::Error> {
        let inner: RegistryRefInner = js_value.as_ref().try_into()?;
        Ok(RegistryRef { inner: Arc::new(inner) })
    }
}

impl From<cctx::RegistryRef> for RegistryRef {
    fn from(outpoint: cctx::RegistryRef) -> Self {
        let transaction_id = outpoint.transaction_id;
        let index = outpoint.index;
        RegistryRef::new(transaction_id, index)
    }
}

impl From<RegistryRef> for cctx::RegistryRef {
    fn from(outpoint: RegistryRef) -> Self {
        let inner = outpoint.inner();
        let transaction_id = inner.transaction_id;
        let index = inner.index;
        cctx::RegistryRef::new(transaction_id, index)
    }
}

impl From<&RegistryRef> for cctx::RegistryRef {
    fn from(outpoint: &RegistryRef) -> Self {
        let inner = outpoint.inner();
        let transaction_id = inner.transaction_id;
        let index = inner.index;
        cctx::RegistryRef::new(transaction_id, index)
    }
}

impl RegistryRef {
    pub fn simulated() -> Self {
        Self::new(TransactionId::from_slice(&rand::random::<[u8; sahyadri_hashes::HASH_SIZE]>()), 0)
    }
}
