pub mod bindings;
pub mod proof;
pub mod transaction;

mod errors;
use bitcoin::hashes::hex::FromHex;
use bitcoin::hashes::Hash;
use std::fmt::Write;

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
