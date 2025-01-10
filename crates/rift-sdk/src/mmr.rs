use accumulators::mmr::{
    element_index_to_leaf_index, elements_count_to_leaf_count, Proof as ClientMMRProof,
};
use accumulators::{
    hasher::keccak::KeccakHasher as ClientKeccakHasher, mmr::MMR as ClientMMR,
    store::memory::InMemoryStore,
};
use alloy::hex;
use bitcoin_light_client_core::mmr::{get_root, MMRProof};
use std::sync::Arc;

use bitcoin_light_client_core::hasher::Digest;
use bitcoin_light_client_core::hasher::Hasher;

pub fn digest_to_hex(digest: &Digest) -> String {
    format!("0x{}", hex::encode(digest))
}

pub fn client_mmr_proof_to_minimal_mmr_proof(proof: &ClientMMRProof) -> MMRProof {
    MMRProof {
        siblings: proof
            .siblings_hashes
            .iter()
            .map(|s| {
                hex::decode(s.trim_start_matches("0x"))
                    .unwrap()
                    .try_into()
                    .unwrap()
            })
            .collect(),
        leaf_hash: hex::decode(proof.element_hash.clone().trim_start_matches("0x"))
            .unwrap()
            .try_into()
            .unwrap(),
        peaks: proof
            .peaks_hashes
            .iter()
            .map(|s| {
                hex::decode(s.trim_start_matches("0x"))
                    .unwrap()
                    .try_into()
                    .unwrap()
            })
            .collect(),
        leaf_count: elements_count_to_leaf_count(proof.elements_count).unwrap() as u32,
        leaf_index: element_index_to_leaf_index(proof.element_index).unwrap() as u32,
    }
}

pub fn create_keccak256_client_mmr() -> ClientMMR {
    let store = InMemoryStore::default();
    let store_rc = Arc::new(store);
    let hasher = Arc::new(ClientKeccakHasher::new());
    ClientMMR::new(store_rc, hasher, None)
}

pub async fn client_mmr_to_root<H: Hasher>(client_mmr: &ClientMMR) -> Digest {
    let bagged_peak: [u8; 32] = hex::decode(
        client_mmr
            .bag_the_peaks(None)
            .await
            .unwrap()
            .strip_prefix("0x")
            .unwrap(),
    )
    .unwrap()
    .try_into()
    .unwrap();

    get_root::<H>(
        client_mmr.leaves_count.get().await.unwrap() as u32,
        &bagged_peak,
    )
}
