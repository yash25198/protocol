#![no_main]
sp1_zkvm::entrypoint!(main);

use bitcoin_light_client_core::{commit_new_chain, hasher::Keccak256Hasher, ChainTransition};

pub fn main() {
    // Read the chain transition data from the prover
    let chain_transition = sp1_zkvm::io::read::<ChainTransition>();

    // Prove that the chain update is valid under bitcoin consensus and MMR transition rules
    let public_input = commit_new_chain::<Keccak256Hasher>(chain_transition);

    // Encode the public values of the program.
    let bytes = public_input.eth_abi_serialize();

    // Commit to the public values of the program. The final proof will have a commitment to all the bytes that were committed to.
    sp1_zkvm::io::commit_slice(&bytes);
}
