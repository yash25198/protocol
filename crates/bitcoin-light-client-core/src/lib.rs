pub mod hasher;
pub mod leaves;
pub mod light_client;
pub mod mmr;

use crypto_bigint::U256;
use hasher::DIGEST_BYTE_COUNT;
use serde::{Deserialize, Serialize};

use crate::hasher::{Digest, Hasher};
use crate::leaves::create_new_leaves;
use crate::leaves::{BlockLeaf, BlockLeafCompressor};
use crate::light_client::Header;
use crate::mmr::{CompactMerkleMountainRange, MMRProof};

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitcoinLightClientPublicInput {
    pub new_mmr_root: Digest,
    pub previous_mmr_root: Digest,
    pub new_leaves_commitment: Digest,
}

impl BitcoinLightClientPublicInput {
    pub fn new(
        new_mmr_root: Digest,
        previous_mmr_root: Digest,
        new_leaves_commitment: Digest,
    ) -> Self {
        Self {
            new_mmr_root,
            previous_mmr_root,
            new_leaves_commitment,
        }
    }

    pub fn eth_abi_serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(DIGEST_BYTE_COUNT * 3);
        bytes.extend_from_slice(&self.new_mmr_root);
        bytes.extend_from_slice(&self.previous_mmr_root);
        bytes.extend_from_slice(&self.new_leaves_commitment);
        bytes
    }

    pub fn eth_abi_deserialize(bytes: &[u8]) -> Self {
        assert!(bytes.len() == DIGEST_BYTE_COUNT * 3);

        let mut new_mmr_root = [0u8; DIGEST_BYTE_COUNT];
        let mut previous_mmr_root = [0u8; DIGEST_BYTE_COUNT];
        let mut new_leaves_commitment = [0u8; DIGEST_BYTE_COUNT];

        new_mmr_root.copy_from_slice(&bytes[..DIGEST_BYTE_COUNT]);
        previous_mmr_root.copy_from_slice(&bytes[DIGEST_BYTE_COUNT..DIGEST_BYTE_COUNT * 2]);
        new_leaves_commitment.copy_from_slice(&bytes[DIGEST_BYTE_COUNT * 2..]);

        Self::new(new_mmr_root, previous_mmr_root, new_leaves_commitment)
    }
}

fn validate_leaf_block_hashes(
    parent_header: &Header,
    parent_leaf: &BlockLeaf,
    parent_retarget_header: &Header,
    parent_retarget_leaf: &BlockLeaf,
    previous_tip_header: &Header,
    previous_tip_leaf: &BlockLeaf,
) {
    assert!(
        parent_leaf.compare_by_natural_block_hash(
            &bitcoin_core_rs::get_block_hash(&parent_header.as_bytes())
                .expect("Failed to get parent header block hash")
        ),
        "Parent leaf block hash does not match parent header block hash"
    );

    assert!(
        parent_retarget_leaf.compare_by_natural_block_hash(
            &bitcoin_core_rs::get_block_hash(&parent_retarget_header.as_bytes())
                .expect("Failed to get parent retarget header block hash")
        ),
        "Parent retarget leaf block hash does not match parent retarget header block hash"
    );

    assert!(
        previous_tip_leaf.compare_by_natural_block_hash(
            &bitcoin_core_rs::get_block_hash(&previous_tip_header.as_bytes())
                .expect("Failed to get previous tip header block hash")
        ),
        "Previous tip leaf block hash does not match previous tip header block hash"
    );
}

fn validate_mmr_proofs<H: Hasher>(
    parent_leaf_hash: &Digest,
    previous_tip_leaf_hash: &Digest,
    parent_retarget_leaf_hash: &Digest,
    parent_leaf_inclusion_proof: &MMRProof,
    previous_tip_leaf_inclusion_proof: &MMRProof,
    parent_retarget_leaf_inclusion_proof: &MMRProof,
    previous_mmr_root: &Digest,
    previous_mmr_leaf_count: u32,
) {
    // [1] Validate parent leaf hashes match inclusion proof leaf hashes
    assert_eq!(
        parent_leaf_hash, &parent_leaf_inclusion_proof.leaf_hash,
        "Parent leaf hash does not match parent leaf inclusion proof leaf"
    );

    assert_eq!(
        previous_tip_leaf_hash, &previous_tip_leaf_inclusion_proof.leaf_hash,
        "Previous tip leaf hash does not match previous tip leaf inclusion proof leaf"
    );

    assert_eq!(
        parent_retarget_leaf_hash, &parent_retarget_leaf_inclusion_proof.leaf_hash,
        "Parent retarget leaf hash does not match parent retarget leaf inclusion proof leaf"
    );

    // [2] Ensure the leaf count is the same for all proofs
    assert_eq!(
        previous_mmr_leaf_count, parent_leaf_inclusion_proof.leaf_count,
        "Previous MMR leaf count does not match parent leaf count in proof"
    );

    assert_eq!(
        previous_mmr_leaf_count, previous_tip_leaf_inclusion_proof.leaf_count,
        "Previous MMR leaf count does not match previous tip leaf count in proof"
    );

    assert_eq!(
        previous_mmr_leaf_count, parent_retarget_leaf_inclusion_proof.leaf_count,
        "Previous MMR leaf count does not match parent retarget leaf count in proof"
    );

    // [3] Verify the proofs are valid
    assert!(
        mmr::verify_mmr_proof::<H>(previous_mmr_root, parent_leaf_inclusion_proof),
        "Parent leaf inclusion proof is invalid"
    );

    assert!(
        mmr::verify_mmr_proof::<H>(previous_mmr_root, previous_tip_leaf_inclusion_proof),
        "Previous tip leaf inclusion proof is invalid"
    );

    assert!(
        mmr::verify_mmr_proof::<H>(previous_mmr_root, parent_retarget_leaf_inclusion_proof),
        "Parent retarget leaf inclusion proof is invalid"
    );
}

fn validate_reorg_conditions(
    parent_leaf: &BlockLeaf,
    previous_tip_leaf: &BlockLeaf,
    parent_leaf_hash: &Digest,
    previous_tip_leaf_hash: &Digest,
    disposed_leaf_hashes: &[Digest],
) {
    assert!(
        previous_tip_leaf.height as i64 - parent_leaf.height as i64
            == disposed_leaf_hashes.len() as i64,
        "Disposed leaves should be the difference between the previous tip leaf height and the parent leaf height"
    );

    if parent_leaf_hash != previous_tip_leaf_hash {
        assert!(
            !disposed_leaf_hashes.is_empty(),
            "Disposed leaves should not be empty for a reorg"
        );
    }
}

fn validate_chainwork(
    parent_leaf: &BlockLeaf,
    previous_tip_leaf: &BlockLeaf,
    new_headers: &[Header],
) -> (Vec<U256>, U256) {
    let (new_chain_works, new_chain_cumulative_work) =
        light_client::calculate_cumulative_work(parent_leaf.chainwork_as_u256(), new_headers);

    if new_chain_cumulative_work <= previous_tip_leaf.chainwork_as_u256() {
        panic!("New chain cumulative work is not greater than previous tip cumulative work");
    }

    (new_chain_works, new_chain_cumulative_work)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockPosition {
    pub header: Header,
    pub leaf: BlockLeaf,
    pub inclusion_proof: MMRProof,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainTransition {
    // Previous MMR state
    pub previous_mmr_root: Digest,
    pub previous_mmr_bagged_peak: Digest, // bagged peak of the old MMR, when hashed with the leaf count gives the previous MMR root

    // Block positions
    pub parent: BlockPosition,          // parent of the new chain
    pub parent_retarget: BlockPosition, // retarget block of the parent
    pub previous_tip: BlockPosition,    // previous tip of the old MMR

    // New chain data
    pub parent_leaf_peaks: Vec<Digest>, // peaks of the MMR with parent as the tip
    pub disposed_leaf_hashes: Vec<Digest>, // leaves that are being removed from the old MMR => all of the leaves after parent in the old MMR
    pub new_headers: Vec<Header>,
}

impl ChainTransition {
    pub fn new(
        previous_mmr_root: Digest,
        previous_mmr_bagged_peak: Digest,
        parent: BlockPosition,
        parent_retarget: BlockPosition,
        previous_tip: BlockPosition,
        parent_leaf_peaks: Vec<Digest>,
        disposed_leaf_hashes: Vec<Digest>,
        new_headers: Vec<Header>,
    ) -> Self {
        Self {
            previous_mmr_root,
            previous_mmr_bagged_peak,
            parent,
            parent_retarget,
            previous_tip,
            parent_leaf_peaks,
            disposed_leaf_hashes,
            new_headers,
        }
    }
}

/// Commit to a new chain, validating the new headers are valid under PoW
/// and that the new chain extends the previous chain from a previous header.
pub fn commit_new_chain<H: Hasher>(ctx: ChainTransition) -> BitcoinLightClientPublicInput {
    // [0] Validate block hashes
    validate_leaf_block_hashes(
        &ctx.parent.header,
        &ctx.parent.leaf,
        &ctx.parent_retarget.header,
        &ctx.parent_retarget.leaf,
        &ctx.previous_tip.header,
        &ctx.previous_tip.leaf,
    );

    // [1] Precompute leaf hashes and total amount of leaves
    let parent_leaf_hash = ctx.parent.leaf.hash::<H>();
    let previous_tip_leaf_hash = ctx.previous_tip.leaf.hash::<H>();
    let parent_retarget_leaf_hash = ctx.parent_retarget.leaf.hash::<H>();

    // block heights are 0-indexed so add 1 to get the number of leaves, keep in mind this is only true if the chain begins with the genesis block
    let previous_tip_chain_leaf_count = ctx.previous_tip.leaf.height + 1;
    let parent_chain_leaf_count = ctx.parent.leaf.height + 1;

    // [2] Validate header chain
    light_client::validate_header_chain(
        ctx.parent.leaf.height,
        &ctx.parent.header,
        &ctx.parent_retarget.header,
        &ctx.new_headers,
    );

    // [3] Validate chainwork and get new chain works
    let (new_chain_works, _) =
        validate_chainwork(&ctx.parent.leaf, &ctx.previous_tip.leaf, &ctx.new_headers);

    // [4] Create new leaves
    let new_leaves = create_new_leaves(&ctx.parent.leaf, &ctx.new_headers, &new_chain_works);

    // [5] Validate MMR proofs
    validate_mmr_proofs::<H>(
        &parent_leaf_hash,
        &previous_tip_leaf_hash,
        &parent_retarget_leaf_hash,
        &ctx.parent.inclusion_proof,
        &ctx.previous_tip.inclusion_proof,
        &ctx.parent_retarget.inclusion_proof,
        &ctx.previous_mmr_root,
        previous_tip_chain_leaf_count,
    );

    // [6-7] Validate reorg conditions
    validate_reorg_conditions(
        &ctx.parent.leaf,
        &ctx.previous_tip.leaf,
        &parent_leaf_hash,
        &previous_tip_leaf_hash,
        &ctx.disposed_leaf_hashes,
    );

    assert!(
        mmr::get_root::<H>(previous_tip_chain_leaf_count, &ctx.previous_mmr_bagged_peak)
            == ctx.previous_mmr_root,
        "Previous MMR root should be the same as the bagged peak + leaf count"
    );

    // [9] validate parent MMR via passing disposed leaves and asserting the root is the  previous
    let mut new_mmr: CompactMerkleMountainRange<H> =
        CompactMerkleMountainRange::from_peaks(&ctx.parent_leaf_peaks, parent_chain_leaf_count);

    new_mmr.validate_mmr_transition(&ctx.disposed_leaf_hashes, &ctx.previous_mmr_root);

    // [10] append the new leaves to the parent MMR
    for leaf in &new_leaves {
        new_mmr.append(&leaf.hash::<H>());
    }

    // [11] Compress the leaves
    let compressed_leaves: Vec<u8> = new_leaves.compress();

    // [12] Compute the new leaves commitment
    let new_leaves_commitment = H::hash(&compressed_leaves);

    // [13] return the Public Input to commit to witness
    BitcoinLightClientPublicInput::new(
        new_mmr.get_root(),
        ctx.previous_mmr_root,
        new_leaves_commitment,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use accumulators::mmr::MMR as ClientMMR;
    use hasher::Keccak256Hasher;
    use leaves::get_genesis_leaf;
    use mmr::tests::{
        client_mmr_proof_to_minimal_mmr_proof, create_keccak256_client_mmr, digest_to_hex,
    };
    use mmr::CompactMerkleMountainRange;
    use test_data_utils::TEST_HEADERS;

    #[test]
    fn validate_headers_available() {
        assert!(!TEST_HEADERS.is_empty(), "Headers should be loaded");
    }

    // TODO Tests:
    //  - Test for reorgs using actual chain data by using downloading a bitcoin forks blocks which will have < chainwork
    //  - Test for chain extension starting from  after block  33k (once difficulty started changing)

    // create a baby MMR from genesis (no other leaves)
    async fn create_from_genesis() -> (
        usize,
        Header,
        BlockLeaf,
        ClientMMR,
        CompactMerkleMountainRange<Keccak256Hasher>,
    ) {
        let genesis_header = TEST_HEADERS[0].1;
        let genesis_leaf = get_genesis_leaf();
        let mut client_mmr = create_keccak256_client_mmr();
        let mut mmr: mmr::CompactMerkleMountainRange<Keccak256Hasher> =
            mmr::CompactMerkleMountainRange::new();

        let genesis_leaf_hash = genesis_leaf.hash::<Keccak256Hasher>();
        let append_result = client_mmr
            .append(digest_to_hex(&genesis_leaf_hash))
            .await
            .unwrap();

        let genesis_client_index = append_result.element_index;

        mmr.append(&genesis_leaf_hash);
        (
            genesis_client_index,
            Header(genesis_header.clone()),
            genesis_leaf.clone(),
            client_mmr,
            mmr,
        )
    }

    #[tokio::test]
    // Test committing 3 new blocks to an existing chain
    async fn test_basic_chain_extension() {
        let (genesis_client_index, genesis_header, genesis_leaf, client_mmr, mmr) =
            create_from_genesis().await;
        let new_headers: Vec<Header> = TEST_HEADERS[1..4]
            .iter()
            .map(|(_, header)| Header(header.clone()))
            .collect();

        let public_input = commit_new_chain::<Keccak256Hasher>(ChainTransition::new(
            mmr.get_root(),
            mmr.bag_peaks().unwrap(),
            BlockPosition {
                header: genesis_header,
                leaf: genesis_leaf,
                inclusion_proof: client_mmr_proof_to_minimal_mmr_proof(
                    &client_mmr
                        .get_proof(genesis_client_index, None)
                        .await
                        .unwrap(),
                ),
            },
            BlockPosition {
                header: genesis_header.clone(),
                leaf: genesis_leaf.clone(),
                inclusion_proof: client_mmr_proof_to_minimal_mmr_proof(
                    &client_mmr
                        .get_proof(genesis_client_index, None)
                        .await
                        .unwrap(),
                ),
            },
            BlockPosition {
                header: genesis_header.clone(),
                leaf: genesis_leaf.clone(),
                inclusion_proof: client_mmr_proof_to_minimal_mmr_proof(
                    &client_mmr
                        .get_proof(genesis_client_index, None)
                        .await
                        .unwrap(),
                ),
            },
            mmr.peaks,
            vec![],
            new_headers.to_vec(),
        ));

        println!("Public input: {:?}", public_input);
        // Verify the new MMR root and public inputs
    }
}
