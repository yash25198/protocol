use crate::types::Hasher;
use std::fmt;

/// represents a Merkle Mountain Range with minimal state
pub struct CompactMerkleMountainRange<H: Hasher> {
    peaks: Vec<H::Digest>,
    leaf_count: u32,
    _hasher: std::marker::PhantomData<H>,
}

impl<H: Hasher> CompactMerkleMountainRange<H> {
    /// creates a new empty MMR
    pub fn new() -> Self {
        CompactMerkleMountainRange {
            peaks: vec![],
            leaf_count: 0,
            _hasher: std::marker::PhantomData,
        }
    }

    /// appends a new leaf to the MMR and updates peaks.
    pub fn append(&mut self, leaf: &H::Digest) {
        self.leaf_count += 1;
        let mut current_peak = leaf.clone();
        let t = self.leaf_count.trailing_zeros() as usize;

        for _ in 0..t {
            let left_peak = self.peaks.pop().expect("No peak to pop");
            current_peak = hash_nodes::<H>(&left_peak.as_ref(), &current_peak.as_ref());
        }

        self.peaks.push(current_peak);
    }

    /// creates a new MMR from existing peaks
    pub fn from_peaks(peaks: &[H::Digest], leaf_count: u32, expected_root: &H::Digest) -> Self {
        // [0] validate peak count is correct
        let expected_peak_count = Self::get_mmr_peak_heights(leaf_count).len();
        if peaks.len() != expected_peak_count {
            panic!("Invalid peak count");
        }

        let mmr: CompactMerkleMountainRange<H> = CompactMerkleMountainRange {
            peaks: peaks.to_vec(),
            leaf_count,
            _hasher: std::marker::PhantomData,
        };

        // [1] validate peaks hash to root
        if mmr.get_root().as_ref() != expected_root.as_ref() {
            panic!("Invalid peaks: calculated root does not match provided root");
        }

        mmr
    }

    // Combines peaks into a single hash from right to left
    pub fn bag_peaks(&self) -> Option<H::Digest> {
        self.peaks.iter().rev().fold(None, |acc, peak| match acc {
            None => Some(peak.clone()),
            Some(prev) => Some(hash_nodes::<H>(peak.as_ref(), &prev.as_ref())),
        })
    }

    // combines bagged peaks with leaf count to produce final root
    pub fn get_root(&self) -> H::Digest {
        let leaf_count = self.leaf_count;
        let bagged_peaks = self.bag_peaks().unwrap_or_else(|| panic!("No peaks found"));
        get_root::<H>(leaf_count, &bagged_peaks)
    }

    pub fn validate_mmr_transition(&self, leaf_hashes: &[H::Digest], expected_root: &H::Digest) {
        // [0] clone self, to not modify the original
        let mut new_mmr = self.clone();

        // [1] append leaves to new_mmr
        for leaf_hash in leaf_hashes {
            new_mmr.append(&leaf_hash);
        }

        // [2] verify new mmr root matches expected_root
        if new_mmr.get_root().as_ref() != expected_root.as_ref() {
            panic!("Invalid MMR: root mismatch");
        }
    }

    // returns the expected peak heights in order from right to left for the MMR of size n
    fn get_mmr_peak_heights(n: u32) -> Vec<u32> {
        let mut heights = Vec::new();
        let mut position = 0;
        let mut remaining = n;

        while remaining > 0 {
            if remaining & 1 == 1 {
                // Check if least significant bit is 1
                heights.push(position);
            }
            remaining >>= 1; // Right shift to process next bit
            position += 1;
        }

        heights
    }
}

impl<H: Hasher> Clone for CompactMerkleMountainRange<H> {
    fn clone(&self) -> Self {
        CompactMerkleMountainRange {
            peaks: self.peaks.clone(),
            leaf_count: self.leaf_count,
            _hasher: std::marker::PhantomData,
        }
    }
}

impl<H: Hasher> fmt::Display for CompactMerkleMountainRange<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "CompactMerkleMountainRange {{")?;
        writeln!(f, "  Leaf count: {}", self.leaf_count)?;
        writeln!(f, "  Peaks:")?;
        for (i, peak) in self.peaks.iter().enumerate() {
            writeln!(f, "  {}: 0x{}", i, hex::encode(peak))?;
        }
        if let Some(bagged) = self.bag_peaks() {
            writeln!(f, "  Bagged peaks: 0x{}", hex::encode(bagged))?;
        }
        writeln!(f, "  Root: 0x{}", hex::encode(self.get_root()))?;
        write!(f, "}}")
    }
}

pub fn hash_nodes<H: Hasher>(left: &[u8], right: &[u8]) -> H::Digest {
    let mut combined = Vec::new();
    combined.extend_from_slice(left);
    combined.extend_from_slice(right);
    H::hash(&combined)
}

pub fn get_root<H: Hasher>(leaf_count: u32, bagged_peak: &H::Digest) -> H::Digest {
    hash_nodes::<H>(&leaf_count.to_be_bytes(), &bagged_peak.as_ref())
}

/// verifies an inclusion proof of a leaf
pub fn verify_merkle_proof<H: Hasher>(
    proof: &[(H::Digest, bool)],
    leaf_hash: &H::Digest,
    root: &H::Digest,
) -> bool {
    let mut hash = leaf_hash.clone();
    for (sibling, is_left) in proof {
        hash = if *is_left {
            hash_nodes::<H>(sibling.as_ref(), hash.as_ref())
        } else {
            hash_nodes::<H>(hash.as_ref(), sibling.as_ref())
        };
    }
    hash.as_ref() == root.as_ref()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Keccak256Hasher;
    use hex;

    #[test]
    fn test_basic_mmr_operations() {
        // [0] create new empty MMR
        let mut mmr = CompactMerkleMountainRange::<Keccak256Hasher>::new();

        // [1] create test leaves by hashing simple strings
        let items = vec![b"a", b"b", b"c", b"d", b"e"]
            .iter()
            .map(|s| Keccak256Hasher::hash(*s))
            .collect::<Vec<_>>();

        // [2] append each leaf and print progress
        for (i, item) in items.iter().enumerate() {
            println!("[{}] appending: 0x{}", i, hex::encode(item));
            mmr.append(&item);
        }

        // [3] print expected peak count based on number of leaves
        println!(
            "Expected peak count: {}",
            CompactMerkleMountainRange::<Keccak256Hasher>::get_mmr_peak_heights(items.len() as u32)
                .len()
        );

        println!("{}", mmr);
    }

    #[test]
    fn test_mmr_reconstruction_from_peaks() {
        // [0] build an MMR with a set of leaves
        let mut mmr = CompactMerkleMountainRange::<Keccak256Hasher>::new();
        let items = (0..20)
            .map(|i| {
                let data = format!("leaf_{}", i);
                Keccak256Hasher::hash(data.as_bytes())
            })
            .collect::<Vec<_>>();

        for item in &items {
            mmr.append(&item);
        }

        // [1] get the peaks and root from the original MMR
        let original_peaks = mmr.peaks.clone();
        let original_leaf_count = mmr.leaf_count;
        let original_root = mmr.get_root();

        // [2] reconstruct the MMR from peaks
        let reconstructed_mmr = CompactMerkleMountainRange::<Keccak256Hasher>::from_peaks(
            &original_peaks,
            original_leaf_count,
            &original_root,
        );

        // [3] verify that the root of the reconstructed MMR matches the original root
        assert_eq!(
            original_root.as_ref(),
            reconstructed_mmr.get_root().as_ref(),
            "Reconstructed MMR root does not match the original root"
        );

        // [4] print out the reconstructed MMR for visual verification
        println!("Original MMR:");
        println!("{}", mmr);
        println!("\nReconstructed MMR:");
        println!("{}", reconstructed_mmr);
    }

    #[test]
    fn test_validate_subset_mmr() {
        // [0] create full MMR by appending a series of leaves
        let mut full_mmr = CompactMerkleMountainRange::<Keccak256Hasher>::new();
        let total_leaves = 10;
        let items = (0..total_leaves)
            .map(|i| {
                let data = format!("leaf_{}", i);
                Keccak256Hasher::hash(data.as_bytes())
            })
            .collect::<Vec<_>>();

        for item in &items {
            full_mmr.append(&item);
        }

        // [1] compute the expected root of the full MMR
        let expected_root = full_mmr.get_root();

        // [2] create a subset MMR by cloning the state after appending half of the leaves
        let subset_leaf_count = total_leaves / 2;
        let mut subset_mmr = CompactMerkleMountainRange::<Keccak256Hasher>::new();
        for item in &items[..subset_leaf_count] {
            subset_mmr.append(&item);
        }

        // [3] collect the remaining leaves to append
        let remaining_leaves = items[subset_leaf_count..].to_vec();

        // [4] validate subset mmr with expected root
        subset_mmr.validate_mmr_transition(&remaining_leaves, &expected_root);

        // [5] assert that the validation passes (no panic occurs)

        // [6] test with purposely incorrect leaves
        let mut incorrect_leaves = remaining_leaves.clone();

        // [7] modify one of the leaves
        incorrect_leaves[0] = Keccak256Hasher::hash(b"incorrect_leaf");

        let result = std::panic::catch_unwind(|| {
            subset_mmr.validate_mmr_transition(&incorrect_leaves, &expected_root);
        });
        assert!(
            result.is_err(),
            "Validation should fail with incorrect leaves"
        );

        // [8] test with incorrect expected root
        let incorrect_root = Keccak256Hasher::hash(b"incorrect_root");
        let result = std::panic::catch_unwind(|| {
            subset_mmr.validate_mmr_transition(&remaining_leaves, &incorrect_root);
        });
        assert!(
            result.is_err(),
            "Validation should fail with incorrect expected root"
        );

        println!("test_validate_subset_mmr passed successfully.");
    }

    #[test]
    fn test_verify_merkle_proof() {
        // [0] define and compute leaf hashes
        let leaf_data = vec![b"leaf1", b"leaf2", b"leaf3"];
        let leaf_hashes: Vec<<Keccak256Hasher as Hasher>::Digest> = leaf_data
            .iter()
            .map(|data| Keccak256Hasher::hash(*data))
            .collect();

        // [1] manually build the MMR and compute peaks
        let mut mmr = CompactMerkleMountainRange::<Keccak256Hasher>::new();
        for leaf_hash in &leaf_hashes {
            mmr.append(leaf_hash);
        }

        // [2] get the root from the MMR
        let root_hash = mmr.get_root();

        // [3] generate a proof for the first leaf (index 0)
        // manually construct proof since MMR doesn't have a method to generate proofs

        // [4] get leaf hashes at level 1
        let h0 = &leaf_hashes[0];
        let h1 = &leaf_hashes[1];
        let h2 = &leaf_hashes[2];

        // [5] combine h0 and h1 at level 2 to get h01
        //let h01 = hash_nodes::<Keccak256Hasher>(h0.as_ref(), h1.as_ref());

        // [6] compute bagged peaks (h01 and h2)
        //let bagged_peaks = hash_nodes::<Keccak256Hasher>(h01.as_ref(), h2.as_ref());

        // [7] compute expected root by hashing leaf count and bagged peaks
        //let expected_root =
        //    hash_nodes::<Keccak256Hasher>(&mmr.leaf_count.to_be_bytes(), bagged_peaks.as_ref());

        // [8] construct proof for leaf 0 with siblings and left/right indicators
        let proof: Vec<(<Keccak256Hasher as Hasher>::Digest, bool)> = vec![
            (h1.clone(), false), // h1 is right sibling of h0
            (h2.clone(), false), // h2 is next peak to right
        ];

        // [9] verify the proof
        let is_valid = {
            let mut hash = h0.clone();
            for (sibling, is_left) in &proof {
                hash = if *is_left {
                    hash_nodes::<Keccak256Hasher>(sibling.as_ref(), hash.as_ref())
                } else {
                    hash_nodes::<Keccak256Hasher>(hash.as_ref(), sibling.as_ref())
                };
            }
            // [10] combine with leaf count for final root hash
            hash = hash_nodes::<Keccak256Hasher>(&mmr.leaf_count.to_be_bytes(), hash.as_ref());
            hash.as_ref() == root_hash.as_ref()
        };

        assert!(is_valid, "The proof should be valid for leaf 0");

        // [11] test with invalid proof by modifying siblings
        let invalid_proof = vec![
            (Keccak256Hasher::hash(b"fake_sibling"), false),
            (h2.clone(), false),
        ];

        let is_invalid = {
            let mut hash = h0.clone();
            for (sibling, is_left) in &invalid_proof {
                hash = if *is_left {
                    hash_nodes::<Keccak256Hasher>(sibling.as_ref(), hash.as_ref())
                } else {
                    hash_nodes::<Keccak256Hasher>(hash.as_ref(), sibling.as_ref())
                };
            }
            // [12] combine with leaf count
            hash = hash_nodes::<Keccak256Hasher>(&mmr.leaf_count.to_be_bytes(), hash.as_ref());
            hash.as_ref() == root_hash.as_ref()
        };

        assert!(
            !is_invalid,
            "The proof should be invalid with incorrect siblings"
        );
    }
}
