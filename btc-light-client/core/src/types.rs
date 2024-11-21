use alloy_sol_types::sol_data::Uint;
use alloy_sol_types::SolType;
use alloy_sol_types::{abi::token::WordToken, sol};
use sha2::{Digest, Sha256};
use tiny_keccak::{Hasher as TinyKeccakHasher, Keccak};

#[derive(Copy, Clone)]
pub struct Header([u8; 80]);

impl Header {
    pub fn from_bytes(bytes: [u8; 80]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> [u8; 80] {
        self.0
    }
}

pub type MerkleProof<H> = [(<H as Hasher>::Digest, bool)];

sol! {
    #[derive(Debug, PartialEq, Eq)]
    struct BitcoinLightClientPublicInput {
        bytes32 newMmrRoot;
        bytes32 previousMmrRoot;
        bytes32 newLeavesCommitment;
    }

    #[derive(Debug, PartialEq, Eq)]
    // blockHash and cumulativeChainwork are stored in reverse byte order
    // as per Bitcoin core
    struct BlockLeaf {
        bytes32 blockHash;
        uint32 height;
        uint256 cumulativeChainwork;
    }
}

impl BlockLeaf {
    pub fn new(block_hash: [u8; 32], height: u32, cumulative_chainwork: [u8; 32]) -> Self {
        let mut block_hash = block_hash;
        block_hash.reverse();

        let mut cumulative_chainwork = cumulative_chainwork;
        cumulative_chainwork.reverse();

        let chainwork_token = WordToken::new(cumulative_chainwork);
        let cumulative_chainwork = <Uint<256>>::detokenize(chainwork_token);

        Self {
            blockHash: block_hash.into(),
            height,
            cumulativeChainwork: cumulative_chainwork,
        }
    }

    // Compare internal hash to a "natural" hash
    pub fn compare_by_block_hash(&self, other: &[u8; 32]) -> bool {
        let mut self_hash: [u8; 32] = self.blockHash.clone().into();
        self_hash.reverse();
        self_hash == *other
    }

    pub fn hash<H: Hasher>(&self) -> H::Digest {
        // Concatenate all fields into a single buffer
        let mut buffer = Vec::with_capacity(32 + 4 + 32);
        buffer.extend_from_slice(&self.blockHash.as_ref());
        buffer.extend_from_slice(&self.height.to_be_bytes());
        buffer.extend_from_slice(&self.cumulativeChainwork.to_le_bytes::<32>().as_ref());

        // Hash the concatenated buffer
        H::hash(&buffer)
    }
}

pub trait Hasher {
    const HASH_SIZE: usize = 32;
    type Digest: AsRef<[u8]> + AsMut<[u8]> + Copy + Sized + Into<[u8; 32]>;
    fn hash(data: &[u8]) -> Self::Digest;
}

/// Sha256 implementation
pub struct Sha256Hasher;
impl Hasher for Sha256Hasher {
    const HASH_SIZE: usize = 32;
    type Digest = [u8; Self::HASH_SIZE];

    fn hash(data: &[u8]) -> Self::Digest {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        result.into()
    }
}

/// Keccak implementation
pub struct Keccak256Hasher;
impl Hasher for Keccak256Hasher {
    const HASH_SIZE: usize = 32;
    type Digest = [u8; Self::HASH_SIZE];

    fn hash(data: &[u8]) -> Self::Digest {
        let mut hasher = Keccak::v256();
        hasher.update(data);
        let mut result = [0u8; Self::HASH_SIZE];
        hasher.finalize(&mut result);
        result
    }
}
