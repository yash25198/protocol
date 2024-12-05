use crate::Sha256Digest;
use bitcoin_core_rs::sha256;
use serde::{Deserialize, Serialize};

#[derive(Default, Serialize, Deserialize, Clone, Copy, Debug)]
pub struct MerkleProofStep {
    pub hash: Sha256Digest,
    pub direction: bool,
}

// Expects leaves to be in reverse byte order (as shown on explorers)
pub fn generate_bitcoin_txn_merkle_proof(
    transaction_hashes: Vec<Sha256Digest>,
    target_transaction_hash: Sha256Digest,
) -> (Vec<MerkleProofStep>, Sha256Digest) {
    let mut current_level = transaction_hashes;
    let mut proof: Vec<MerkleProofStep> = Vec::new();
    let mut target_index = current_level
        .iter()
        .position(|&leaf| leaf == target_transaction_hash)
        .expect("Desired leaf not found in the list of leaves");

    while current_level.len() > 1 {
        let mut next_level = Vec::new();
        let mut i = 0;

        while i < current_level.len() {
            let left = current_level[i];
            let right = if i + 1 < current_level.len() {
                current_level[i + 1]
            } else {
                left
            };

            let parent_hash = bitcoin_merkle_hash_pair(left, right);
            next_level.push(parent_hash);

            if i == target_index || i + 1 == target_index {
                let proof_step = if i == target_index {
                    MerkleProofStep {
                        hash: right,
                        direction: true,
                    }
                } else {
                    MerkleProofStep {
                        hash: left,
                        direction: false,
                    }
                };
                proof.push(proof_step);
                target_index /= 2;
            }

            i += 2;
        }

        current_level = next_level;
    }

    let merkle_root = current_level[0];
    (proof, merkle_root)
}

pub fn bitcoin_merkle_hash_pair(hash_1: Sha256Digest, hash_2: Sha256Digest) -> Sha256Digest {
    // [0] & [1] Combine hashes into one 64 byte array, reversing byte order
    let combined_hashes: [u8; 64] = hash_1
        .into_iter()
        .rev()
        .chain(hash_2.into_iter().rev())
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap();

    // [2] Double sha256 combined hashes, then reverse byte order
    let mut combined_hash = sha256(&sha256(&combined_hashes));
    combined_hash.reverse();

    combined_hash
}

/// Validate that a proposed transaction hash (network byte order) is included in the merkle root
pub fn verify_bitcoin_txn_merkle_proof(
    merkle_root: Sha256Digest,
    proposed_txn_hash: Sha256Digest,
    proposed_merkle_proof: &[MerkleProofStep],
) {
    let mut current_hash: Sha256Digest = proposed_txn_hash;
    for proof_step in proposed_merkle_proof {
        if proof_step.direction {
            current_hash = bitcoin_merkle_hash_pair(current_hash, proof_step.hash);
        } else {
            current_hash = bitcoin_merkle_hash_pair(proof_step.hash, current_hash);
        }
    }
    assert!(
        current_hash == merkle_root,
        "Merkle proof verification failed"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use btc_light_client_utils::;

}
