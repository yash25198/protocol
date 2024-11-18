pub mod light_client;
pub mod types;

use crate::types::{BlockLeaf, Hash, Header, HeaderChainUpdate};

/// Commit to a new chain, validating the new headers are valid under PoW
/// and that the new chain extends the previous chain from a previous header.
pub fn commit_new_chain(
    previous_mmr_root: Hash,
    parent_leaf: BlockLeaf,
    parent_header: Header, // this is the header that the new chain will connect to
    parent_retarget_header: Header, // this is the header from the last difficulty adjustment period that sets the current target difficulty (nBits)
    parent_header_inclusion_proof: &[Hash], // proof that the parent header is in the previous MMR
    parent_retarget_header_inclusion_proof: &[Hash], // proof that the parent retarget header is in the previous MMR
    new_headers: &[Header],
) -> HeaderChainUpdate {
    // Prove that parent_header and parent_retarget_header hashes and heights are in the previous MMR

    // Prove that new_headers are valid headers and create a chain starting from parent_header under PoW
    light_client::validate_header_chain(
        parent_header.height,
        &parent_header,
        &parent_retarget_header,
        new_headers,
    );

    todo!();
    // Return the new MMR root and the new leaves
}
