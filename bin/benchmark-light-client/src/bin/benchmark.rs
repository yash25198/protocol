//! Benchmark the cycle count of the btc-light-client program for various numbers of blocks.
use bitcoin_light_client_core::hasher::Keccak256Hasher;
use bitcoin_light_client_core::leaves::get_genesis_leaf;
use bitcoin_light_client_core::light_client::Header;
use bitcoin_light_client_core::mmr::{CompactMerkleMountainRange, MMRProof};
use bitcoin_light_client_core::{BlockPosition, ChainTransition};
use prettytable::{row, Table};
use sp1_sdk::{include_elf, ProverClient, SP1Stdin};
use std::time::Instant;
use test_data_utils::EXHAUSTIVE_TEST_HEADERS;

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const RIFT_PROGRAM_ELF: &[u8] = include_elf!("rift-program");

fn create_genesis_mmr() -> CompactMerkleMountainRange<Keccak256Hasher> {
    let genesis_leaf = get_genesis_leaf();
    let genesis_leaf_hash = genesis_leaf.hash::<Keccak256Hasher>();
    let mut mmr = CompactMerkleMountainRange::<Keccak256Hasher>::new();
    mmr.append(&genesis_leaf_hash);
    mmr
}

fn create_chain_transition_from_genesis(num_blocks: usize) -> ChainTransition {
    let genesis_header = Header(EXHAUSTIVE_TEST_HEADERS[0].1);
    let genesis_leaf = get_genesis_leaf();
    let genesis_leaf_hash = genesis_leaf.hash::<Keccak256Hasher>();
    let genesis_mmr = create_genesis_mmr();
    let genesis_leaf_inclusion_proof = MMRProof {
        leaf_hash: genesis_leaf_hash,
        leaf_index: 0,
        siblings: vec![],
        peaks: vec![genesis_leaf_hash],
        leaf_count: 1,
    };
    let genesis_leaf_mmr_position = BlockPosition {
        header: genesis_header,
        leaf: genesis_leaf,
        inclusion_proof: genesis_leaf_inclusion_proof,
    };
    let chain_transition = ChainTransition {
        previous_mmr_root: genesis_mmr.get_root(),
        previous_mmr_bagged_peak: genesis_mmr.bag_peaks().unwrap(),
        parent: genesis_leaf_mmr_position.clone(),
        parent_retarget: genesis_leaf_mmr_position.clone(),
        previous_tip: genesis_leaf_mmr_position.clone(),
        parent_leaf_peaks: genesis_mmr.peaks.clone(),
        disposed_leaf_hashes: vec![],
        new_headers: EXHAUSTIVE_TEST_HEADERS[1..num_blocks + 1]
            .iter()
            .map(|(_, header)| Header(header.clone()))
            .collect(),
    };
    chain_transition
}

fn prove_chain_transition(chain_transition: ChainTransition) -> u64 {
    // Setup the prover client.
    let client = ProverClient::new();

    let program_input = rift_core::giga::RiftProgramInput::builder()
        .proof_type(rift_core::giga::ProofType::LightClient)
        .light_client_input(chain_transition)
        .build()
        .unwrap();

    // Setup the inputs.
    let mut stdin = SP1Stdin::new();
    stdin.write(&program_input);

    // Execute the program
    let (output, report) = client.execute(RIFT_PROGRAM_ELF, stdin).run().unwrap();

    // Record the number of cycles executed.
    report.total_instruction_count()
}

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();

    // Create a table for pretty printing.
    let mut table = Table::new();
    table.add_row(row!["Num Blocks", "Cycle Count", "Time to Execute (ms)"]);

    // Prove at log intervals: 1, 10, 100, 1000, 10000, 100000
    [1, 10, 100, 1000, 10000, 100000]
        .iter()
        .for_each(|&num_blocks| {
            println!("Starting benchmark for {} blocks...", num_blocks);
            let start_time = Instant::now();
            let chain_transition = create_chain_transition_from_genesis(num_blocks);
            let cycles = prove_chain_transition(chain_transition);
            let duration = start_time.elapsed().as_millis();
            table.add_row(row![num_blocks, cycles, duration]);
            println!("Completed benchmark for {} blocks.", num_blocks);
        });

    // Print the table at the end.
    table.printstd();
}
