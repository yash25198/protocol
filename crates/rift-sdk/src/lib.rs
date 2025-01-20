pub mod bindings;
pub mod mmr;
pub mod transaction;

mod errors;
use bitcoin::hashes::hex::FromHex;
use bitcoin::hashes::Hash;
use sp1_sdk::include_elf;
use std::fmt::Write;
use std::str::FromStr;

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const RIFT_PROGRAM_ELF: &[u8] = include_elf!("rift-program");

pub fn load_hex_bytes(file: &str) -> Vec<u8> {
    let hex_string = std::fs::read_to_string(file).expect("Failed to read file");
    Vec::<u8>::from_hex(&hex_string).expect("Failed to parse hex")
}

pub fn to_hex_string(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}

pub fn get_retarget_height_from_block_height(block_height: u64) -> u64 {
    block_height - (block_height % 2016)
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Where to store the database (in-memory or on disk).
pub enum DatabaseLocation {
    InMemory,
    File(String),
}

impl FromStr for DatabaseLocation {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "memory" => Ok(DatabaseLocation::InMemory),
            s => Ok(DatabaseLocation::File(s.to_string())),
        }
    }
}
