use alloy_sol_types::sol;

pub type Header = [u8; 80];

pub type Hash = [u8; 32];

sol! {
    #[derive(Debug, PartialEq, Eq)]
    struct BitcoinLightClientPublicInput {
        bytes32 previousMmrRoot;
        bytes32 newLeavesCommitment;
    }

    #[derive(Debug, PartialEq, Eq)]
    struct BlockLeaf {
        bytes32 blockHash;
        uint64 height;
        uint256 cumulativeChainwork;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderChainUpdate {
    pub previous_root: Hash,
    pub new_root: Hash,
    pub new_leaves: Vec<BlockLeaf>,
    pub public_input: BitcoinLightClientPublicInput,
}
