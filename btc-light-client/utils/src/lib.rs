use once_cell::sync::Lazy;
use serde_json::Value;

pub const TEST_DATA_STR: &str = include_str!("../../../test-data/data/blocks_0_9999.json");
pub const EXHAUSTIVE_TEST_DATA_STR: &str =
    include_str!("../../../test-data/data/blocks_10000_800000.json");

pub static TEST_HEADERS: Lazy<Vec<(u32, [u8; 80])>> = Lazy::new(|| load_test_headers(false));
pub static EXHAUSTIVE_TEST_HEADERS: Lazy<Vec<(u32, [u8; 80])>> =
    Lazy::new(|| load_test_headers(true));

fn load_test_headers(exhaustive: bool) -> Vec<(u32, [u8; 80])> {
    let start = std::time::Instant::now();
    let mut json: Value = serde_json::from_str(TEST_DATA_STR).expect("Failed to parse JSON");
    let obj: &mut serde_json::Map<String, Value> =
        json.as_object_mut().expect("JSON must be an object");
    if exhaustive {
        obj.extend(
            serde_json::from_str::<Value>(EXHAUSTIVE_TEST_DATA_STR)
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
