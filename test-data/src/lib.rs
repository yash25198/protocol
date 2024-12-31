use bitcoin::consensus::encode::deserialize;
use bitcoin::Block;
use hex::FromHex;

use once_cell::sync::Lazy;
use serde_json::Value;

pub static TEST_HEADERS: Lazy<Vec<(u32, [u8; 80])>> = Lazy::new(|| load_test_headers(false));
pub static EXHAUSTIVE_TEST_HEADERS: Lazy<Vec<(u32, [u8; 80])>> =
    Lazy::new(|| load_test_headers(true));

pub static TEST_BCH_HEADERS: Lazy<Vec<(u32, [u8; 80])>> = Lazy::new(load_test_bch_headers);

pub static TEST_BLOCKS: Lazy<Vec<Block>> = Lazy::new(load_test_blocks);

fn load_test_blocks() -> Vec<Block> {
    let block_hex_strings = [
        include_str!("../data/blocks/block_799990.hex"),
        include_str!("../data/blocks/block_799991.hex"),
        include_str!("../data/blocks/block_799992.hex"),
        include_str!("../data/blocks/block_799993.hex"),
        include_str!("../data/blocks/block_799994.hex"),
        include_str!("../data/blocks/block_799995.hex"),
        include_str!("../data/blocks/block_799996.hex"),
        include_str!("../data/blocks/block_799997.hex"),
        include_str!("../data/blocks/block_799998.hex"),
        include_str!("../data/blocks/block_799999.hex"),
        include_str!("../data/blocks/block_800000.hex"),
    ];

    let mut blocks = Vec::new();
    for hex_string in block_hex_strings {
        let block_bytes = Vec::<u8>::from_hex(hex_string).expect("Failed to parse hex");
        let block = deserialize::<Block>(&block_bytes).unwrap();
        blocks.push(block);
    }
    blocks
}

fn load_test_headers(exhaustive: bool) -> Vec<(u32, [u8; 80])> {
    const INITIAL_BLOCK_HEADERS_STR: &str = include_str!("../data/headers_0_9999.json");
    const EXHAUSTIVE_BLOCK_HEADERS_STR: &str = include_str!("../data/headers_10000_800000.json");
    let start = std::time::Instant::now();
    let mut json: Value =
        serde_json::from_str(INITIAL_BLOCK_HEADERS_STR).expect("Failed to parse JSON");
    let obj: &mut serde_json::Map<String, Value> =
        json.as_object_mut().expect("JSON must be an object");
    if exhaustive {
        obj.extend(
            serde_json::from_str::<Value>(EXHAUSTIVE_BLOCK_HEADERS_STR)
                .expect("Failed to parse JSON")
                .as_object()
                .expect("JSON must be an object")
                .iter()
                .map(|(k, v)| (k.clone(), v.clone())),
        );
    }

    let mut headers = Vec::with_capacity(obj.len());
    for (height_str, header_hex) in obj {
        let height = height_str.parse::<u32>().expect("Invalid height value");
        if let Value::String(hex_str) = header_hex {
            let bytes = hex::decode(hex_str).expect("Invalid hex string");
            headers.push((height, bytes.try_into().expect("Invalid header length")));
        }
    }
    headers.sort_by_key(|(height, _)| *height);
    println!("Time to load headers: {:?}", start.elapsed());
    headers
}

fn load_test_bch_headers() -> Vec<(u32, [u8; 80])> {
    const INITIAL_BLOCK_HEADERS_STR: &str = include_str!("../data/bch_headers_478559_578559.json");
    let mut json: Value =
        serde_json::from_str(INITIAL_BLOCK_HEADERS_STR).expect("Failed to parse JSON");
    let obj: &mut serde_json::Map<String, Value> =
        json.as_object_mut().expect("JSON must be an object");
    let mut headers = Vec::with_capacity(obj.len());
    for (height_str, header_hex) in obj {
        let height = height_str.parse::<u32>().expect("Invalid height value");
        if let Value::String(hex_str) = header_hex {
            let bytes = hex::decode(hex_str).expect("Invalid hex string");
            headers.push((height, bytes.try_into().expect("Invalid header length")));
        }
    }
    headers
}
