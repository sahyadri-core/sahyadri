use crate::error::Error;
use crate::result::Result;
use sahyadri_consensus_core::constants::KANA_PER_SAHYADRI;
use std::fmt::Display;

pub fn try_parse_required_nonzero_sahyadri_as_kana_u64<S: ToString + Display>(sahyadri_amount: Option<S>) -> Result<u64> {
    if let Some(sahyadri_amount) = sahyadri_amount {
        let kana_amount = sahyadri_amount
            .to_string()
            .parse::<f64>()
            .map_err(|_| Error::custom(format!("Supplied Sahyadri amount is not valid: '{sahyadri_amount}'")))?
            * KANA_PER_SAHYADRI as f64;
        if kana_amount < 0.0 {
            Err(Error::custom("Supplied Sahyadri amount is not valid: '{sahyadri_amount}'"))
        } else {
            let kana_amount = kana_amount as u64;
            if kana_amount == 0 {
                Err(Error::custom("Supplied required sahyadri amount must not be a zero: '{sahyadri_amount}'"))
            } else {
                Ok(kana_amount)
            }
        }
    } else {
        Err(Error::custom("Missing Sahyadri amount"))
    }
}

pub fn try_parse_required_sahyadri_as_kana_u64<S: ToString + Display>(sahyadri_amount: Option<S>) -> Result<u64> {
    if let Some(sahyadri_amount) = sahyadri_amount {
        let kana_amount = sahyadri_amount
            .to_string()
            .parse::<f64>()
            .map_err(|_| Error::custom(format!("Supplied Kasapa amount is not valid: '{sahyadri_amount}'")))?
            * KANA_PER_SAHYADRI as f64;
        if kana_amount < 0.0 {
            Err(Error::custom("Supplied Sahyadri amount is not valid: '{sahyadri_amount}'"))
        } else {
            Ok(kana_amount as u64)
        }
    } else {
        Err(Error::custom("Missing Sahyadri amount"))
    }
}

pub fn try_parse_optional_sahyadri_as_kana_i64<S: ToString + Display>(sahyadri_amount: Option<S>) -> Result<Option<i64>> {
    if let Some(sahyadri_amount) = sahyadri_amount {
        let kana_amount = sahyadri_amount
            .to_string()
            .parse::<f64>()
            .map_err(|_e| Error::custom(format!("Supplied Kasapa amount is not valid: '{sahyadri_amount}'")))?
            * KANA_PER_SAHYADRI as f64;
        if kana_amount < 0.0 {
            Err(Error::custom("Supplied Sahyadri amount is not valid: '{sahyadri_amount}'"))
        } else {
            Ok(Some(kana_amount as i64))
        }
    } else {
        Ok(None)
    }
}
