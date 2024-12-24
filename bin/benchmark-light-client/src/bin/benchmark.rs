//! Benchmark the cycle count of the btc-light-client program for various numbers of blocks.
use bitcoin_light_client_core::hasher::Keccak256Hasher;
use bitcoin_light_client_core::leaves::get_genesis_leaf;
use bitcoin_light_client_core::light_client::Header;
use bitcoin_light_client_core::mmr::{CompactMerkleMountainRange, MMRProof};
use bitcoin_light_client_core::{BlockPosition, ChainTransition};
use clap::Parser;
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
            .map(|(_, header)| Header(*header))
            .collect(),
    };
    chain_transition
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BenchmarkType {
    Execute,
    Prove,
}

#[derive(Debug)]
struct BenchmarkResult {
    cycles: Option<u64>,
    duration: std::time::Duration,
}

fn prove_chain_transition(
    chain_transition: ChainTransition,
    benchmark_type: BenchmarkType,
) -> BenchmarkResult {
    // Setup the prover client.
    println!("Creating prover client...");
    // set the SP1_PROVER env to network
    std::env::set_var("SP1_PROVER", "local");
    let client = ProverClient::new();
    println!("Prover client created.");

    println!("Setting up program...");
    let (pk, _vk) = client.setup(RIFT_PROGRAM_ELF);
    println!("Program setup complete.");

    let program_input = rift_core::giga::RiftProgramInput::builder()
        .proof_type(rift_core::giga::ProofType::LightClient)
        .light_client_input(chain_transition)
        .build()
        .unwrap();

    // Setup the inputs.
    let mut stdin = SP1Stdin::new();
    stdin.write(&program_input);

    // Execute the program
    let result = match benchmark_type {
        BenchmarkType::Execute => {
            let start = Instant::now();
            let (_output, report) = client.execute(RIFT_PROGRAM_ELF, stdin).run().unwrap();
            let duration = start.elapsed();
            let cycles = report.total_instruction_count();
            BenchmarkResult {
                cycles: Some(cycles),
                duration,
            }
        }
        BenchmarkType::Prove => {
            let start = Instant::now();
            client.prove(&pk, stdin).groth16().run().unwrap();
            let duration = start.elapsed();
            BenchmarkResult {
                cycles: None,
                duration,
            }
        }
    };

    result
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The type of benchmark to run: "execute" or "prove"
    #[arg(short, long, default_value = "execute")]
    r#type: String,
}

fn format_duration(duration: std::time::Duration) -> String {
    if duration.as_secs() == 0 {
        return format!("{} ms", duration.as_millis());
    }
    if duration.as_secs() < 60 {
        return format!("{:.2} s", duration.as_secs_f64());
    }
    if duration.as_secs() < 3600 {
        return format!("{:.2} min", duration.as_secs_f64() / 60.0);
    }
    format!("{:.2} h", duration.as_secs_f64() / 3600.0)
}

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();

    // Parse command line arguments
    let args = Args::parse();
    let benchmark_type = match args.r#type.to_lowercase().as_str() {
        "execute" => BenchmarkType::Execute,
        "prove" => BenchmarkType::Prove,
        _ => panic!("Invalid benchmark type. Must be either 'execute' or 'prove'"),
    };

    // Create a table for pretty printing.
    let mut table = Table::new();
    if benchmark_type == BenchmarkType::Execute {
        table.add_row(row!["Num Blocks", "Cycle Count"]);
    } else {
        table.add_row(row!["Num Blocks", "Time to Prove"]);
    }

    // explicitly load data
    create_chain_transition_from_genesis(1);

    // Prove at log intervals: 1, 10, 100, 1000, 10000, 100000
    [1, 10, 100, 1000, 10000].iter().for_each(|&num_blocks| {
        println!("Starting benchmark for {} blocks...", num_blocks);
        let chain_transition = create_chain_transition_from_genesis(num_blocks);
        println!("Chain transition created.");
        let benchmark_result = prove_chain_transition(chain_transition, benchmark_type);
        println!("Benchmark result: {:?}", benchmark_result);
        if benchmark_result.cycles.is_some() {
            table.add_row(row![num_blocks, benchmark_result.cycles.unwrap(),]);
        } else {
            table.add_row(row![num_blocks, format_duration(benchmark_result.duration)]);
        }
        println!("Completed benchmark for {} blocks.", num_blocks);
    });

    // Print the table at the end.
    table.printstd();
}
