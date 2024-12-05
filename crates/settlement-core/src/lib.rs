use alloy_sol_types::sol;
use crypto_bigint::U256;
use serde::{Deserialize, Serialize};
pub mod payments;
pub mod spv;
pub mod vaults;

sol!("../../../contracts/src/libraries/Types.sol");

pub type Sha256Digest = [u8; 32];
