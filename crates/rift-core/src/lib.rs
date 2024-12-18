#![allow(clippy::too_many_arguments)]

pub mod payments;
pub mod spv;
pub mod types;
pub mod vaults;

use crate::spv::{generate_bitcoin_txn_hash, verify_bitcoin_txn_merkle_proof, MerkleProofStep};
use crate::vaults::validate_aggregate_vault_commitment;

use crate::payments::validate_bitcoin_payment;
use crate::types::DepositVault;

use bitcoin::consensus::encode::deserialize;
use bitcoin::hashes::Hash;
use bitcoin_core_rs::get_block_hash;
use bitcoin_light_client_core::light_client::Header;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RiftTransactionPublicInput {
    pub aggregate_vault_commitment: [u8; 32],
    pub block_hash: [u8; 32],
}

impl RiftTransactionPublicInput {
    pub fn contract_serialize_length() -> usize {
        64
    }

    pub fn contract_serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(Self::contract_serialize_length());
        bytes.extend_from_slice(&self.aggregate_vault_commitment);
        bytes.extend_from_slice(&self.block_hash);
        bytes
    }

    pub fn contract_deserialize(bytes: &[u8]) -> Self {
        assert!(bytes.len() == Self::contract_serialize_length());
        let mut aggregate_vault_commitment = [0u8; 32];
        let mut block_hash = [0u8; 32];
        aggregate_vault_commitment.copy_from_slice(&bytes[..32]);
        block_hash.copy_from_slice(&bytes[32..]);
        Self {
            aggregate_vault_commitment,
            block_hash,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RiftTransaction {
    // no segwit data serialized bitcoin transaction
    pub txn: Vec<u8>,
    // the vaults reserved for this transaction
    pub reserved_vaults: Vec<DepositVault>,
    // the aggregate vault commitment of the reserved vaults (passed from public input)
    pub aggregate_vault_commitment: [u8; 32],
    // block header where the txn is included
    pub block_header: Header,
    // block hash (passed from public input)
    pub block_hash: [u8; 32],
    // merkle proof of the txn hash in the block
    pub txn_merkle_proof: Vec<MerkleProofStep>,
}

impl RiftTransaction {
    pub fn public_input(&self) -> RiftTransactionPublicInput {
        RiftTransactionPublicInput {
            aggregate_vault_commitment: self.aggregate_vault_commitment,
            block_hash: self.block_hash,
        }
    }
}

pub fn validate_rift_transaction(rift_txn: RiftTransaction) -> RiftTransactionPublicInput {
    assert!(!rift_txn.reserved_vaults.is_empty());
    let block_header = &rift_txn.block_header.as_bytes();

    // [0] Validate the block header
    assert_eq!(
        get_block_hash(block_header).expect("Failed to get block hash"),
        rift_txn.block_hash
    );

    // [1] Validate Bitcoin merkle proof of the transaction hash
    let block_header_merkle_root = deserialize::<bitcoin::block::Header>(block_header)
        .expect("Failed to deserialize block header")
        .merkle_root
        .to_raw_hash()
        .to_byte_array();

    let txn_hash = generate_bitcoin_txn_hash(&rift_txn.txn);
    verify_bitcoin_txn_merkle_proof(
        block_header_merkle_root,
        txn_hash,
        &rift_txn.txn_merkle_proof,
    );

    // [2] Validate aggregate vault commitment of the reserved vaults match what is onchain
    validate_aggregate_vault_commitment(
        &rift_txn.reserved_vaults,
        &rift_txn.aggregate_vault_commitment,
    );

    // [3] Validate Bitcoin payment given the deposit vaults
    validate_bitcoin_payment(
        &rift_txn.txn,
        &rift_txn.reserved_vaults,
        &rift_txn.aggregate_vault_commitment,
    );

    rift_txn.public_input()
}

// Combine Light Client and Rift Transaction "programs"
pub mod giga {
    use super::*;
    use bitcoin_light_client_core::{
        commit_new_chain, hasher::Keccak256Hasher, BitcoinLightClientPublicInput,
    };

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[repr(u8)]
    pub enum ProofType {
        LightClient = 0,
        RiftTransaction = 1,
        Full = 2,
    }

    impl ProofType {
        pub fn from_u8(value: u8) -> Option<Self> {
            match value {
                0 => Some(Self::LightClient),
                1 => Some(Self::RiftTransaction),
                2 => Some(Self::Full),
                _ => None,
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RiftProgramInput {
        pub proof_type: ProofType,
        pub light_client_input: bitcoin_light_client_core::ChainTransition,
        pub rift_transaction_input: RiftTransaction,
    }

    impl RiftProgramInput {
        pub fn builder() -> RiftProgramInputBuilder {
            RiftProgramInputBuilder::default()
        }
    }

    #[derive(Default)]
    pub struct RiftProgramInputBuilder {
        proof_type: Option<ProofType>,
        light_client_input: Option<bitcoin_light_client_core::ChainTransition>,
        rift_transaction_input: Option<RiftTransaction>,
    }

    impl RiftProgramInputBuilder {
        pub fn proof_type(mut self, proof_type: ProofType) -> Self {
            self.proof_type = Some(proof_type);
            self
        }

        pub fn light_client_input(
            mut self,
            input: bitcoin_light_client_core::ChainTransition,
        ) -> Self {
            self.light_client_input = Some(input);
            self
        }

        pub fn rift_transaction_input(mut self, input: RiftTransaction) -> Self {
            self.rift_transaction_input = Some(input);
            self
        }

        pub fn build(self) -> Result<RiftProgramInput, &'static str> {
            let proof_type = self.proof_type.ok_or("proof_type is required")?;

            match proof_type {
                ProofType::LightClient => {
                    let light_client_input = self
                        .light_client_input
                        .ok_or("light_client_input is required for LightClient proof type")?;
                    Ok(RiftProgramInput {
                        proof_type,
                        light_client_input,
                        rift_transaction_input: RiftTransaction::default(),
                    })
                }
                ProofType::RiftTransaction => {
                    let rift_transaction_input = self.rift_transaction_input.ok_or(
                        "rift_transaction_input is required for RiftTransaction proof type",
                    )?;
                    Ok(RiftProgramInput {
                        proof_type,
                        light_client_input: bitcoin_light_client_core::ChainTransition::default(), // You'll need to implement Default
                        rift_transaction_input,
                    })
                }
                ProofType::Full => {
                    let light_client_input = self
                        .light_client_input
                        .ok_or("light_client_input is required for Full proof type")?;
                    let rift_transaction_input = self
                        .rift_transaction_input
                        .ok_or("rift_transaction_input is required for Full proof type")?;
                    Ok(RiftProgramInput {
                        proof_type,
                        light_client_input,
                        rift_transaction_input,
                    })
                }
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RiftProgramPublicInput {
        pub proof_type: ProofType,
        #[serde(flatten)]
        pub light_client_public_input: bitcoin_light_client_core::BitcoinLightClientPublicInput,
        #[serde(flatten)]
        pub rift_transaction_public_input: RiftTransactionPublicInput,
    }

    impl RiftProgramPublicInput {
        pub fn contract_serialize_length() -> usize {
            1 + bitcoin_light_client_core::BitcoinLightClientPublicInput::contract_serialize_length(
            ) + RiftTransactionPublicInput::contract_serialize_length()
        }

        pub fn contract_serialize(&self) -> Vec<u8> {
            let mut bytes = Vec::with_capacity(Self::contract_serialize_length());
            // Add proof_type as a single byte
            bytes.push(self.proof_type.clone() as u8);
            // Add light client public input
            bytes.extend_from_slice(&self.light_client_public_input.contract_serialize());
            // Add rift transaction public input
            bytes.extend_from_slice(&self.rift_transaction_public_input.contract_serialize());
            bytes
        }

        pub fn contract_deserialize(bytes: &[u8]) -> Self {
            assert!(bytes.len() == Self::contract_serialize_length());
            // First byte is proof_type
            let proof_type = ProofType::from_u8(bytes[0]).expect("Invalid proof type");

            // Next bytes are light client public input
            let light_client_public_input =
                bitcoin_light_client_core::BitcoinLightClientPublicInput::contract_deserialize(
                    &bytes[1..bitcoin_light_client_core::BitcoinLightClientPublicInput::contract_serialize_length() + 1],
                );

            // Remaining bytes are rift transaction public input
            let rift_transaction_public_input = RiftTransactionPublicInput::contract_deserialize(
                &bytes[bitcoin_light_client_core::BitcoinLightClientPublicInput::contract_serialize_length() + 1..]
            );

            Self {
                proof_type,
                light_client_public_input,
                rift_transaction_public_input,
            }
        }
    }

    impl RiftProgramInput {
        pub fn verify_input(self) -> RiftProgramPublicInput {
            match self.proof_type {
                ProofType::LightClient => {
                    let light_client_public_input =
                        commit_new_chain::<Keccak256Hasher>(self.light_client_input);
                    RiftProgramPublicInput {
                        proof_type: self.proof_type,
                        light_client_public_input,
                        rift_transaction_public_input: RiftTransactionPublicInput::default(),
                    }
                }
                ProofType::RiftTransaction => {
                    let rift_transaction_public_input =
                        validate_rift_transaction(self.rift_transaction_input);
                    RiftProgramPublicInput {
                        proof_type: self.proof_type,
                        light_client_public_input: BitcoinLightClientPublicInput::default(),
                        rift_transaction_public_input,
                    }
                }
                ProofType::Full => {
                    let light_client_public_input =
                        commit_new_chain::<Keccak256Hasher>(self.light_client_input);
                    let rift_transaction_public_input =
                        validate_rift_transaction(self.rift_transaction_input);
                    RiftProgramPublicInput {
                        proof_type: self.proof_type,
                        light_client_public_input,
                        rift_transaction_public_input,
                    }
                }
            }
        }
    }
}
