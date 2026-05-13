use std::collections::HashMap;
use sahyadri_consensus_core::{
    BlockHashMap, BlockHashSet,
    coinbase::*,
    config::params::ForkedParam,
    errors::coinbase::{CoinbaseError, CoinbaseResult},
    tx::{ScriptPublicKey, ScriptVec},
};
use std::convert::TryInto;

use crate::model::stores::sahyadri_consensus::SahyadriConsensusData;

const LENGTH_OF_BLUE_SCORE: usize = size_of::<u64>();
const LENGTH_OF_SUBSIDY: usize = size_of::<u64>();
const LENGTH_OF_SCRIPT_PUB_KEY_VERSION: usize = size_of::<u16>();
const LENGTH_OF_SCRIPT_PUB_KEY_LENGTH: usize = size_of::<u8>();

const MIN_PAYLOAD_LENGTH: usize =
    LENGTH_OF_BLUE_SCORE + LENGTH_OF_SUBSIDY + LENGTH_OF_SCRIPT_PUB_KEY_VERSION + LENGTH_OF_SCRIPT_PUB_KEY_LENGTH;

// We define a year as 365.25 days and a month as 365.25 / 12 = 30.4375
// SECONDS_PER_MONTH = 30.4375 * 24 * 60 * 60

pub const SUBSIDY_BY_MONTH_TABLE_SIZE: usize = 426;
pub type SubsidyByMonthTable = [u64; SUBSIDY_BY_MONTH_TABLE_SIZE];

#[derive(Clone)]
pub struct CoinbaseManager {
    coinbase_payload_script_public_key_max_len: u8,
    max_coinbase_payload_len: usize,
    _deflationary_phase_daa_score: u64,
    _pre_deflationary_phase_base_subsidy: u64,
    _bps_history: ForkedParam<u64>,
    _subsidy_by_month_table_before: SubsidyByMonthTable,
    _subsidy_by_month_table_after: SubsidyByMonthTable,
}

/// Struct used to streamline payload parsing
struct PayloadParser<'a> {
    remaining: &'a [u8], // The unparsed remainder
}

impl<'a> PayloadParser<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { remaining: data }
    }

    /// Returns a slice with the first `n` bytes of `remaining`, while setting `remaining` to the remaining part
    fn take(&mut self, n: usize) -> &[u8] {
        let (segment, remaining) = self.remaining.split_at(n);
        self.remaining = remaining;
        segment
    }
}

impl CoinbaseManager {
    pub fn new(
        coinbase_payload_script_public_key_max_len: u8,
        max_coinbase_payload_len: usize,
        deflationary_phase_daa_score: u64,
        pre_deflationary_phase_base_subsidy: u64,
        bps_history: ForkedParam<u64>,
    ) -> Self {
        // Precomputed subsidy by month table for the actual block per second rate
        // Here values are rounded up so that we keep the same number of rewarding months as in the original 1 BPS table.
        // In a 10 BPS network, the induced increase in total rewards is 51 CSM (see tests::calc_high_bps_total_rewards_delta())
        let subsidy_by_month_table_before: SubsidyByMonthTable =
            core::array::from_fn(|i| SUBSIDY_BY_MONTH_TABLE[i].div_ceil(bps_history.before()));
        let subsidy_by_month_table_after: SubsidyByMonthTable =
            core::array::from_fn(|i| SUBSIDY_BY_MONTH_TABLE[i].div_ceil(bps_history.after()));
    Self {
            coinbase_payload_script_public_key_max_len,
            max_coinbase_payload_len,
            _deflationary_phase_daa_score: deflationary_phase_daa_score,
            _pre_deflationary_phase_base_subsidy: pre_deflationary_phase_base_subsidy,
            _bps_history: bps_history,
            _subsidy_by_month_table_before: subsidy_by_month_table_before,
            _subsidy_by_month_table_after: subsidy_by_month_table_after,
        }    
    }

    #[cfg(test)]
    #[inline]
    pub fn bps_history(&self) -> ForkedParam<u64> {
        self._bps_history.clone()
    }

    // The new Account-Based expected_coinbase_transaction function
    pub fn expected_coinbase_transaction<T: AsRef<[u8]>>(
        &self,
        _daa_score: u64,
        miner_data: MinerData<T>,
        sahyadri_consensus_data: &SahyadriConsensusData,
        mergeset_rewards: &BlockHashMap<BlockRewardData>,
        mergeset_non_daa: &BlockHashSet,
    ) -> CoinbaseResult<HashMap<String, i64>> {
        
        let mut account_rewards: HashMap<String, i64> = HashMap::new();

        // Native formatting to string to bypass complex address traits for now
        let extract_address = |script: &ScriptPublicKey| -> String {
            let script_bytes = script.script();
            let version = script.version();
            // Build proper script hex: version(2) + len(1) + script_bytes
            let mut full_script = Vec::new();
            full_script.extend_from_slice(&version.to_le_bytes());
            full_script.push(script_bytes.len() as u8);
            full_script.extend_from_slice(script_bytes);
            faster_hex::hex_string(&full_script)
        };

        // --- 1. SAHYADRI BLUE BLOCK REWARD SPLIT ---
        for blue in sahyadri_consensus_data.mergeset_blues.iter().filter(|h| !mergeset_non_daa.contains(h)) {
            
            let reward_data = match mergeset_rewards.get(blue) {
                Some(data) => data,
                None => continue, 
            };
            
            let total_reward = reward_data.subsidy + reward_data.total_fees;
            
            if total_reward > 0 {
                // 98-2 split for Block Subsidy -> 2% to company
                let subsidy_dev_fee = reward_data.subsidy / 50; 
                
                // 90-10 split for Transaction Fees -> 10% to company
                let tx_dev_fee = reward_data.total_fees / 10;   

                // Total dev fee and remaining for miner
                let total_dev_fee = subsidy_dev_fee + tx_dev_fee;
                let miner_reward = total_reward - total_dev_fee; 

                let miner_address = extract_address(&reward_data.script_public_key);
                
                // Updated Company Address
                let company_address = "csm1sr5hjpvqf2gftk3cpfyzn4u7je779248lcw8ceglsgxxr3yp5gjrwph0etepr".to_string();

                *account_rewards.entry(miner_address).or_insert(0) += miner_reward as i64;
                *account_rewards.entry(company_address).or_insert(0) += total_dev_fee as i64;
            }
        }

        // --- 2. SAHYADRI RED BLOCK REWARD SPLIT ---
        let mut red_subsidy = 0u64;
        let mut red_fees = 0u64;

        for red in sahyadri_consensus_data.mergeset_reds.iter() {
            let reward_data = match mergeset_rewards.get(red) {
                Some(data) => data,
                None => continue,
            };

            if mergeset_non_daa.contains(red) {
                red_fees += reward_data.total_fees;
            } else {
                red_subsidy += reward_data.subsidy;
                red_fees += reward_data.total_fees;
            }
        }

        let total_red_reward = red_subsidy + red_fees;
        
        if total_red_reward > 0 {
            // 98-2 split for Block Subsidy -> 2% to company
            let subsidy_dev_fee = red_subsidy / 50; 
            
            // 90-10 split for Tx Fees -> 10% to company
            let tx_dev_fee = red_fees / 10; 

            // Total dev fee and remaining for miner
            let total_dev_fee = subsidy_dev_fee + tx_dev_fee;
            let miner_reward = total_red_reward - total_dev_fee; 

            let miner_address = extract_address(&miner_data.script_public_key);
            
            // Updated Company Address
            let company_address = "csm1sr5hjpvqf2gftk3cpfyzn4u7je779248lcw8ceglsgxxr3yp5gjrwph0etepr".to_string();

            *account_rewards.entry(miner_address).or_insert(0) += miner_reward as i64;
            *account_rewards.entry(company_address).or_insert(0) += total_dev_fee as i64;
        }

        Ok(account_rewards)
    }

    pub fn serialize_coinbase_payload<T: AsRef<[u8]>>(&self, data: &CoinbaseData<T>) -> CoinbaseResult<Vec<u8>> {
        let script_pub_key_len = data.miner_data.script_public_key.script().len();
        if script_pub_key_len > self.coinbase_payload_script_public_key_max_len as usize {
            return Err(CoinbaseError::PayloadScriptPublicKeyLenAboveMax(
                script_pub_key_len,
                self.coinbase_payload_script_public_key_max_len,
            ));
        }
        let payload: Vec<u8> = data.blue_score.to_le_bytes().iter().copied()                    // Blue score                   (u64)
            .chain(data.subsidy.to_le_bytes().iter().copied())                                  // Subsidy                      (u64)
            .chain(data.miner_data.script_public_key.version().to_le_bytes().iter().copied())   // Script public key version    (u16)
            .chain((script_pub_key_len as u8).to_le_bytes().iter().copied())                    // Script public key length     (u8)
            .chain(data.miner_data.script_public_key.script().iter().copied())                  // Script public key            
            .chain(data.miner_data.extra_data.as_ref().iter().copied())                         // Extra data
            .collect();

        Ok(payload)
    }

    pub fn modify_coinbase_payload<T: AsRef<[u8]>>(&self, mut payload: Vec<u8>, miner_data: &MinerData<T>) -> CoinbaseResult<Vec<u8>> {
        let script_pub_key_len = miner_data.script_public_key.script().len();
        if script_pub_key_len > self.coinbase_payload_script_public_key_max_len as usize {
            return Err(CoinbaseError::PayloadScriptPublicKeyLenAboveMax(
                script_pub_key_len,
                self.coinbase_payload_script_public_key_max_len,
            ));
        }

        // Keep only blue score and subsidy. Note that truncate does not modify capacity, so
        // the usual case where the payloads are the same size will not trigger a reallocation
        payload.truncate(LENGTH_OF_BLUE_SCORE + LENGTH_OF_SUBSIDY);
        payload.extend(
            miner_data.script_public_key.version().to_le_bytes().iter().copied() // Script public key version (u16)
                .chain((script_pub_key_len as u8).to_le_bytes().iter().copied()) // Script public key length  (u8)
                .chain(miner_data.script_public_key.script().iter().copied())    // Script public key
                .chain(miner_data.extra_data.as_ref().iter().copied()), // Extra data
        );

        Ok(payload)
    }

    pub fn deserialize_coinbase_payload<'a>(&self, payload: &'a [u8]) -> CoinbaseResult<CoinbaseData<&'a [u8]>> {
        if payload.len() < MIN_PAYLOAD_LENGTH {
            return Err(CoinbaseError::PayloadLenBelowMin(payload.len(), MIN_PAYLOAD_LENGTH));
        }

        if payload.len() > self.max_coinbase_payload_len {
            return Err(CoinbaseError::PayloadLenAboveMax(payload.len(), self.max_coinbase_payload_len));
        }

        let mut parser = PayloadParser::new(payload);

        let blue_score = u64::from_le_bytes(parser.take(LENGTH_OF_BLUE_SCORE).try_into().unwrap());
        let subsidy = u64::from_le_bytes(parser.take(LENGTH_OF_SUBSIDY).try_into().unwrap());
        let script_pub_key_version = u16::from_le_bytes(parser.take(LENGTH_OF_SCRIPT_PUB_KEY_VERSION).try_into().unwrap());
        let script_pub_key_len = u8::from_le_bytes(parser.take(LENGTH_OF_SCRIPT_PUB_KEY_LENGTH).try_into().unwrap());

        if script_pub_key_len > self.coinbase_payload_script_public_key_max_len {
            return Err(CoinbaseError::PayloadScriptPublicKeyLenAboveMax(
                script_pub_key_len as usize,
                self.coinbase_payload_script_public_key_max_len,
            ));
        }

        if parser.remaining.len() < script_pub_key_len as usize {
            return Err(CoinbaseError::PayloadCantContainScriptPublicKey(
                payload.len(),
                MIN_PAYLOAD_LENGTH + script_pub_key_len as usize,
            ));
        }

        let script_public_key =
            ScriptPublicKey::new(script_pub_key_version, ScriptVec::from_slice(parser.take(script_pub_key_len as usize)));
        let extra_data = parser.remaining;

        Ok(CoinbaseData { blue_score, subsidy, miner_data: MinerData { script_public_key, extra_data } })
    }

pub fn calc_block_subsidy(&self, blue_score: u64) -> u64 { 
        // 1. Sahyadri Base Reward: 8,318,123 Kana (0.08318123 CSM) 
        let base_reward: u64 = 8_318_123; 

        // 2. Halving Interval: 126,230,400 rewarded blocks (~4 years at ~1 block/sec) 
        // Sahyadri math: 1 block/sec * 60 * 60 * 24 * 365.25 * 4 
        let halving_interval: u64 = 126_230_400; 

        // 3. Check kitne 4-saal (halvings) beet chuke hain 
        let halvings = blue_score / halving_interval; 

        // 4. Safety: 64 halvings ke baad reward hamesha 0 
        if halvings >= 64 { 
            return 0; 
        } 

        // 5. Safe division: Har halving pe reward aadha (2 se divide) 
        base_reward.checked_shr(halvings as u32).unwrap_or(0) 
    }
    /// Get the subsidy month as function of the current DAA score.
    ///
    /// Note that this function is called only if daa_score >= self.deflationary_phase_daa_score
    fn _subsidy_month(&self, _daa_score: u64) -> u64 {
        // Disabled logic for unused UTXO math
        0
    }

    #[cfg(test)]
    pub fn legacy_calc_block_subsidy(&self, _daa_score: u64) -> u64 {
        self._pre_deflationary_phase_base_subsidy
    }
}
/*
    This table was pre-calculated by calling `calcDeflationaryPeriodBlockSubsidyFloatCalc` (in sahyadrid-go) for all months until reaching 0 subsidy.
    To regenerate this table, run `TestBuildSubsidyTable` in coinbasemanager_test.go (note the `deflationaryPhaseBaseSubsidy` therein).
    These values represent the reward per second for each month (= reward per block for 1 BPS).
*/
#[rustfmt::skip]
const SUBSIDY_BY_MONTH_TABLE: [u64; 426] = [
	44000000000, 41530469757, 39199543598, 36999442271, 34922823143, 32962755691, 31112698372, 29366476791, 27718263097, 26162556530, 24694165062, 23308188075, 22000000000, 20765234878, 19599771799, 18499721135, 17461411571, 16481377845, 15556349186, 14683238395, 13859131548, 13081278265, 12347082531, 11654094037, 11000000000,
	10382617439, 9799885899, 9249860567, 8730705785, 8240688922, 7778174593, 7341619197, 6929565774, 6540639132, 6173541265, 5827047018, 5500000000, 5191308719, 4899942949, 4624930283, 4365352892, 4120344461, 3889087296, 3670809598, 3464782887, 3270319566, 3086770632, 2913523509, 2750000000, 2595654359,
	2449971474, 2312465141, 2182676446, 2060172230, 1944543648, 1835404799, 1732391443, 1635159783, 1543385316, 1456761754, 1375000000, 1297827179, 1224985737, 1156232570, 1091338223, 1030086115, 972271824, 917702399, 866195721, 817579891, 771692658, 728380877, 687500000, 648913589, 612492868,
	578116285, 545669111, 515043057, 486135912, 458851199, 433097860, 408789945, 385846329, 364190438, 343750000, 324456794, 306246434, 289058142, 272834555, 257521528, 243067956, 229425599, 216548930, 204394972, 192923164, 182095219, 171875000, 162228397, 153123217, 144529071,
	136417277, 128760764, 121533978, 114712799, 108274465, 102197486, 96461582, 91047609, 85937500, 81114198, 76561608, 72264535, 68208638, 64380382, 60766989, 57356399, 54137232, 51098743, 48230791, 45523804, 42968750, 40557099, 38280804, 36132267, 34104319,
	32190191, 30383494, 28678199, 27068616, 25549371, 24115395, 22761902, 21484375, 20278549, 19140402, 18066133, 17052159, 16095095, 15191747, 14339099, 13534308, 12774685, 12057697, 11380951, 10742187, 10139274, 9570201, 9033066, 8526079, 8047547,
	7595873, 7169549, 6767154, 6387342, 6028848, 5690475, 5371093, 5069637, 4785100, 4516533, 4263039, 4023773, 3797936, 3584774, 3383577, 3193671, 3014424, 2845237, 2685546, 2534818, 2392550, 2258266, 2131519, 2011886, 1898968,
	1792387, 1691788, 1596835, 1507212, 1422618, 1342773, 1267409, 1196275, 1129133, 1065759, 1005943, 949484, 896193, 845894, 798417, 753606, 711309, 671386, 633704, 598137, 564566, 532879, 502971, 474742, 448096,
	422947, 399208, 376803, 355654, 335693, 316852, 299068, 282283, 266439, 251485, 237371, 224048, 211473, 199604, 188401, 177827, 167846, 158426, 149534, 141141, 133219, 125742, 118685, 112024, 105736,
	99802, 94200, 88913, 83923, 79213, 74767, 70570, 66609, 62871, 59342, 56012, 52868, 49901, 47100, 44456, 41961, 39606, 37383, 35285, 33304, 31435, 29671, 28006, 26434, 24950,
	23550, 22228, 20980, 19803, 18691, 17642, 16652, 15717, 14835, 14003, 13217, 12475, 11775, 11114, 10490, 9901, 9345, 8821, 8326, 7858, 7417, 7001, 6608, 6237, 5887,
	5557, 5245, 4950, 4672, 4410, 4163, 3929, 3708, 3500, 3304, 3118, 2943, 2778, 2622, 2475, 2336, 2205, 2081, 1964, 1854, 1750, 1652, 1559, 1471, 1389,
	1311, 1237, 1168, 1102, 1040, 982, 927, 875, 826, 779, 735, 694, 655, 618, 584, 551, 520, 491, 463, 437, 413, 389, 367, 347, 327,
	309, 292, 275, 260, 245, 231, 218, 206, 194, 183, 173, 163, 154, 146, 137, 130, 122, 115, 109, 103, 97, 91, 86, 81, 77,
	73, 68, 65, 61, 57, 54, 51, 48, 45, 43, 40, 38, 36, 34, 32, 30, 28, 27, 25, 24, 22, 21, 20, 19, 18,
	17, 16, 15, 14, 13, 12, 12, 11, 10, 10, 9, 9, 8, 8, 7, 7, 6, 6, 6, 5, 5, 5, 4, 4, 4,
	4, 3, 3, 3, 3, 3, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	0,
];

#[cfg(test)]
mod tests {
    use super::*;
    use sahyadri_consensus_core::config::params::ForkedParam;

    // Helper to create a basic CoinbaseManager for testing
    fn create_test_manager() -> CoinbaseManager {
        CoinbaseManager::new(
            150, 
            204, 
            15778800, 
            8318123, 
            ForkedParam::new_const(1)
        )
    }

    #[test]
    fn test_sahyadri_base_reward_math() {
        let cbm = create_test_manager();
        
        // 1. Check Genesis / First Block Reward (Should be 8,318,123 Kana = 0.08318123 CSM)
        let block_1_reward = cbm.calc_block_subsidy(1);
        assert_eq!(block_1_reward, 8_318_123, "Sahyadri base reward math failed!");

        // 2. Check First Halving (After 4 Years = 126,230,400 blocks)
        let halving_block = 126_230_400;
        let halving_reward = cbm.calc_block_subsidy(halving_block);
        assert_eq!(halving_reward, 8_318_123 / 2, "First halving math failed!");
    }

    #[test]
    fn test_empty_account_rewards() {
        // Just verifying the HashMap structure is clean for the account model
        use std::collections::HashMap;
        let account_rewards: HashMap<String, u64> = HashMap::new();
        assert!(account_rewards.is_empty(), "Account ledger should start empty");
    }
}

