pub mod light_client;
pub mod mmr;
pub mod types;

use crypto_bigint::Encoding;
use crypto_bigint::U256;

use crate::types::{BitcoinLightClientPublicInput, BlockLeaf, Hasher, Header, MerkleProof};

fn create_new_leaves(
    parent_leaf: &BlockLeaf,
    new_headers: &[Header],
    new_chain_works: &[U256],
) -> Vec<BlockLeaf> {
    assert!(new_headers.len() == new_chain_works.len());
    new_headers
        .iter()
        .map(|header| {
            bitcoin_core_rs::get_block_hash(&header.as_bytes()).expect("Failed to get block hash")
        })
        .zip(new_chain_works.iter())
        .zip((parent_leaf.height + 1..).into_iter())
        .map(|((block_hash, cumulative_chainwork), height)| {
            BlockLeaf::new(block_hash, height, cumulative_chainwork.to_le_bytes())
        })
        .collect()
}

fn validate_leaf_block_hashes<H: Hasher>(
    parent_header: &Header,
    parent_leaf: &BlockLeaf,
    parent_retarget_header: &Header,
    parent_retarget_leaf: &BlockLeaf,
    previous_tip_header: &Header,
    previous_tip_leaf: &BlockLeaf,
) {
    assert!(
        parent_leaf.compare_by_block_hash(
            &bitcoin_core_rs::get_block_hash(&parent_header.as_bytes())
                .expect("Failed to get parent header block hash")
        ),
        "Parent leaf block hash does not match parent header block hash"
    );

    assert!(
        parent_retarget_leaf.compare_by_block_hash(
            &bitcoin_core_rs::get_block_hash(&parent_retarget_header.as_bytes())
                .expect("Failed to get parent retarget header block hash")
        ),
        "Parent retarget leaf block hash does not match parent retarget header block hash"
    );

    assert!(
        previous_tip_leaf.compare_by_block_hash(
            &bitcoin_core_rs::get_block_hash(&previous_tip_header.as_bytes())
                .expect("Failed to get previous tip header block hash")
        ),
        "Previous tip leaf block hash does not match previous tip header block hash"
    );
}

fn validate_mmr_proofs<H: Hasher>(
    parent_leaf_hash: &H::Digest,
    previous_tip_leaf_hash: &H::Digest,
    parent_retarget_leaf_hash: &H::Digest,
    parent_leaf_inclusion_proof: &MerkleProof<H>,
    previous_tip_leaf_inclusion_proof: &MerkleProof<H>,
    parent_retarget_leaf_inclusion_proof: &MerkleProof<H>,
    previous_mmr_root: &H::Digest,
) {
    assert!(
        mmr::verify_merkle_proof::<H>(
            parent_leaf_inclusion_proof,
            parent_leaf_hash,
            previous_mmr_root,
        ),
        "Parent leaf inclusion proof is invalid"
    );

    assert!(
        mmr::verify_merkle_proof::<H>(
            previous_tip_leaf_inclusion_proof,
            previous_tip_leaf_hash,
            previous_mmr_root,
        ),
        "Previous tip leaf inclusion proof is invalid"
    );

    assert!(
        mmr::verify_merkle_proof::<H>(
            parent_retarget_leaf_inclusion_proof,
            parent_retarget_leaf_hash,
            previous_mmr_root,
        ),
        "Parent retarget leaf inclusion proof is invalid"
    );
}

fn validate_reorg_conditions<H: Hasher>(
    parent_leaf: &BlockLeaf,
    previous_tip_leaf: &BlockLeaf,
    parent_leaf_hash: &H::Digest,
    previous_tip_leaf_hash: &H::Digest,
    disposed_leaf_hashes: &[H::Digest],
) {
    assert!(
        previous_tip_leaf.height as i64 - parent_leaf.height as i64
            == disposed_leaf_hashes.len() as i64,
        "Disposed leaves should be the difference between the previous tip leaf height and the parent leaf height"
    );

    if parent_leaf_hash.as_ref() != previous_tip_leaf_hash.as_ref() {
        assert!(
            !disposed_leaf_hashes.is_empty(),
            "Disposed leaves should not be empty for a reorg"
        );
    }
}

/// Commit to a new chain, validating the new headers are valid under PoW
/// and that the new chain extends the previous chain from a previous header.
pub fn commit_new_chain<H: Hasher>(
    previous_mmr_root: &H::Digest,
    previous_mmr_bagged_peak: &H::Digest,

    parent_header: &Header, // this is the already existing header that the new chain will connect to, not always the tip b/c of reorgs
    parent_leaf: &BlockLeaf,
    parent_leaf_inclusion_proof: &MerkleProof<H>, // proof that the parent leaf is in the previous MMR

    parent_retarget_header: &Header, // this is the already existing header from the last difficulty adjustment period that sets the current target difficulty (nBits)
    parent_retarget_leaf: &BlockLeaf, // the leaf at the height of the parent retarget header
    parent_retarget_leaf_inclusion_proof: &MerkleProof<H>, // proof that the parent retarget leaf is in the previous MMR

    previous_tip_header: &Header, // the header at the tip of the old chain
    previous_tip_leaf: &BlockLeaf,
    previous_tip_leaf_inclusion_proof: &MerkleProof<H>, // proof that the tip leaf is in the old MMR

    parent_leaf_peaks: &[H::Digest], // the peaks of the MMR that uses the parent leaf as the newest leaf, used to build a new chain

    disposed_leaf_hashes: &[H::Digest], // leaves that are no longer part of the chain, in the previous MMR
    new_headers: &[Header],
) -> BitcoinLightClientPublicInput {
    // [0] Validate block hashes
    validate_leaf_block_hashes::<H>(
        parent_header,
        parent_leaf,
        parent_retarget_header,
        parent_retarget_leaf,
        previous_tip_header,
        previous_tip_leaf,
    );

    // [1] Precompute leaf hashes
    let parent_leaf_hash = parent_leaf.hash::<H>();
    let previous_tip_leaf_hash = previous_tip_leaf.hash::<H>();
    let parent_retarget_leaf_hash = parent_retarget_leaf.hash::<H>();

    // [2] Validate header chain
    light_client::validate_header_chain(
        parent_leaf.height,
        parent_header,
        parent_retarget_header,
        new_headers,
    );

    // [3] Validate chainwork
    let (new_chain_works, new_chain_cumulative_work) = light_client::calculate_cumulative_work(
        U256::from_le_bytes(parent_leaf.cumulativeChainwork.to_le_bytes()),
        new_headers,
    );

    if new_chain_cumulative_work
        <= U256::from_le_bytes(previous_tip_leaf.cumulativeChainwork.to_le_bytes())
    {
        panic!("New chain cumulative work is not greater than previous tip cumulative work");
    }

    // [4] Create new leaves
    let new_leaves = create_new_leaves(parent_leaf, new_headers, &new_chain_works);

    // [5] Validate MMR proofs
    validate_mmr_proofs::<H>(
        &parent_leaf_hash,
        &previous_tip_leaf_hash,
        &parent_retarget_leaf_hash,
        parent_leaf_inclusion_proof,
        previous_tip_leaf_inclusion_proof,
        parent_retarget_leaf_inclusion_proof,
        previous_mmr_root,
    );

    // [6-7] Validate reorg conditions
    validate_reorg_conditions::<H>(
        parent_leaf,
        previous_tip_leaf,
        &parent_leaf_hash,
        &previous_tip_leaf_hash,
        disposed_leaf_hashes,
    );

    // - first check (step 5) ensures merkle inclusion of the previous leaf tip
    // [8] second check (here) ensures that the passed tip leaf is actually the latest tip of the old MMR based on the previous leaf tip height
    assert!(
        mmr::get_root::<H>(previous_tip_leaf.height, previous_mmr_bagged_peak).as_ref()
            == previous_mmr_root.as_ref(),
        "Previous MMR root should be the same as the bagged peak + leaf count"
    );

    // [9] validate parent_mmr and disposed leaves
    let mut new_mmr: mmr::CompactMerkleMountainRange<H> =
        mmr::CompactMerkleMountainRange::from_peaks(
            parent_leaf_peaks,
            parent_leaf.height,
            previous_mmr_root,
        );
    new_mmr.validate_mmr_transition(disposed_leaf_hashes, &previous_mmr_root);

    // [10] append the new leaves to the parent MMR
    for leaf in new_leaves {
        new_mmr.append(&leaf.hash::<H>());
    }

    // TODO: Make BitcoinLightClientPublicInput hash lengths const generic over the digest size < 32
    // for now we can just assert that the root length is 32 bytes
    assert!(
        new_mmr.get_root().as_ref().len() == 32 && previous_mmr_root.as_ref().len() == 32,
        "Roots should be 32 bytes"
    );

    // [12] return the Public Input to be commmitted to
    let new_mmr_bytes: [u8; 32] = new_mmr.get_root().into();
    let previous_mmr_bytes: [u8; 32] = (*previous_mmr_root).into();

    BitcoinLightClientPublicInput {
        newMmrRoot: new_mmr_bytes.into(),
        previousMmrRoot: previous_mmr_bytes.into(),
        newLeavesCommitment: new_mmr_bytes.into(),
    }
}
