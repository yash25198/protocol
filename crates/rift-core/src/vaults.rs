// Effectively a Rust impl of `contracts/src/libraries/CommitmentVerificationLib.sol`
use crate::DepositVault;
use alloy_sol_types::SolType;
use tiny_keccak::{Hasher, Keccak};

pub fn hash_deposit_vault(vault: &DepositVault) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    let mut output = [0u8; 32];

    let abi_encoded = DepositVault::abi_encode(vault);

    hasher.update(&abi_encoded);
    hasher.finalize(&mut output);
    output
}

pub fn generate_aggregate_vault_commitment(vaults: &[DepositVault]) -> [u8; 32] {
    let mut vault_hashes: Vec<[u8; 32]> = Vec::with_capacity(vaults.len());

    for vault in vaults {
        vault_hashes.push(hash_deposit_vault(vault));
    }

    let mut hasher = Keccak::v256();
    let mut output = [0u8; 32];

    // concatenating a list of [u8; 32] is the same as abi.encode(vault_hashes)
    let abi_encoded = vault_hashes.concat();
    hasher.update(&abi_encoded);
    hasher.finalize(&mut output);
    output
}

pub fn validate_aggregate_vault_commitment(
    vaults: &[DepositVault],
    aggregate_vault_commitment: &[u8; 32],
) {
    assert!(!vaults.is_empty());
    assert_eq!(
        generate_aggregate_vault_commitment(vaults),
        *aggregate_vault_commitment
    )
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use alloy::{
        hex,
        primitives::{Address, FixedBytes, U256},
    };

    #[test]
    fn test_hash_single_deposit_vault() {
        let vault = DepositVault {
            vaultIndex: U256::from(599290588),
            depositTimestamp: 8269061,
            depositAmount: U256::from(2151u64),
            depositFee: U256::from(15751u64),
            expectedSats: 1358,
            btcPayoutScriptPubKey: FixedBytes::from_slice(&hex!(
                "00000000000000000000000000000000000000000000"
            )),
            specifiedPayoutAddress: Address::from_str("0x0000000000000000000000000000000000004412")
                .unwrap(),
            ownerAddress: Address::from_str("0x00000000000000000000000000000000000003C6").unwrap(),
            nonce: FixedBytes::from_slice(&hex!(
                "0000000000000000000000000000000000000000000000000000000000000814"
            )),
        };
        let hash = hash_deposit_vault(&vault);
        assert_eq!(
            hash,
            hex!("7ead9803c320ed36c103bf881ae2f1878baffec3c8bc50a07e4a772c18e2912a")
        );
    }

    #[test]
    fn test_generate_aggregate_vault_commitment_single_vault() {
        let vaults = vec![DepositVault {
            vaultIndex: U256::from(2352788318891644112_u64),
            depositTimestamp: 16495808206466222_u64,
            depositAmount: U256::from(13118724207801340719_u64),
            depositFee: U256::from(49529989_u64),
            expectedSats: 107119_u64,
            btcPayoutScriptPubKey: FixedBytes::from_slice(&hex!(
                "594999912a9da219544c96a3e8401a55611b27f8bfb6"
            )),
            specifiedPayoutAddress: Address::from_str("0x149904752bae499DaF3Bd35F519fE3930Bf7a6f7")
                .unwrap(),
            ownerAddress: Address::from_str("0xc23B149abBCA3418851A76840B1BE28c0c014B68").unwrap(),
            nonce: FixedBytes::from_slice(&hex!(
                "bf63e291b6d434dec2192a765823d457e4f5bc267f77a60616368d746abdec79"
            )),
        }];
        let commitment = generate_aggregate_vault_commitment(&vaults);
        assert_eq!(
            commitment,
            hex!("d91dc455b8660243e6029563a88a172829046d8d4df7d0b6feb395212f254ad7")
        );
    }

    #[test]
    fn test_validate_aggregate_vault_commitment_single_vault() {
        // [DepositVault({ vaultIndex: 182703594 [1.827e8], depositTimestamp: 58354780695128 [5.835e13], depositAmount: 794244050849892961 [7.942e17], depositFee: 12450933242548896328 [1.245e19], expectedSats: 12, btcPayoutScriptPubKey: 0xe1c332ed3cf0d5a0683654807fdd20a20107409fbb06, specifiedPayoutAddress: 0xe98288B4a6C8363FD601C183Dd7a5cA0A405f147, ownerAddress: 0x914ab584Ab2E8461ED9765faA4d7168F6548C078, nonce: 0xaa8c039742c7144acaffb34ee4fb5ec45882c28dc382f6a2ee920964c16800c0 }), DepositVault({ vaultIndex: 605812733071243 [6.058e14], depositTimestamp: 1180297774819 [1.18e12], depositAmount: 2279090703277556659 [2.279e18], depositFee: 1969586198045072918 [1.969e18], expectedSats: 18446744073709551612 [1.844e19], btcPayoutScriptPubKey: 0x0d8b0047b3ced2b44d737d20a890336d0c5f2da96ae1, specifiedPayoutAddress: 0xF83aB6eccFbD25fa4B5ebF330dfa99D173e8137a, ownerAddress: 0x3CB74A28651906320D3DE66453F423c85632273B, nonce: 0x5a48aeda6f156a173f75917838e46d044fa948c770ab12e3dc82fbeddbc5e030 })]
        let vaults = vec![
            DepositVault {
                vaultIndex: U256::from(182703594_u64),
                depositTimestamp: 58354780695128_u64,
                depositAmount: U256::from(794244050849892961_u64),
                depositFee: U256::from(12450933242548896328_u64),
                expectedSats: 12_u64,
                btcPayoutScriptPubKey: FixedBytes::from_slice(&hex!(
                    "e1c332ed3cf0d5a0683654807fdd20a20107409fbb06"
                )),
                specifiedPayoutAddress: Address::from_str(
                    "0xe98288B4a6C8363FD601C183Dd7a5cA0A405f147",
                )
                .unwrap(),
                ownerAddress: Address::from_str("0x914ab584Ab2E8461ED9765faA4d7168F6548C078")
                    .unwrap(),
                nonce: FixedBytes::from_slice(&hex!(
                    "aa8c039742c7144acaffb34ee4fb5ec45882c28dc382f6a2ee920964c16800c0"
                )),
            },
            DepositVault {
                vaultIndex: U256::from(605812733071243_u64),
                depositTimestamp: 1180297774819_u64,
                depositAmount: U256::from(2279090703277556659_u64),
                depositFee: U256::from(1969586198045072918_u64),
                expectedSats: 18446744073709551612_u64,
                btcPayoutScriptPubKey: FixedBytes::from_slice(&hex!(
                    "0d8b0047b3ced2b44d737d20a890336d0c5f2da96ae1"
                )),
                specifiedPayoutAddress: Address::from_str(
                    "0xF83aB6eccFbD25fa4B5ebF330dfa99D173e8137a",
                )
                .unwrap(),
                ownerAddress: Address::from_str("0x3CB74A28651906320D3DE66453F423c85632273B")
                    .unwrap(),
                nonce: FixedBytes::from_slice(&hex!(
                    "5a48aeda6f156a173f75917838e46d044fa948c770ab12e3dc82fbeddbc5e030"
                )),
            },
        ];
        let commitment = generate_aggregate_vault_commitment(&vaults);
        assert_eq!(
            commitment,
            hex!("bb301bb50fb67464f1054d565165557e6deb9aa1b63b18ce8712596ff97fd09a")
        );
    }
}
