use once_cell::sync::Lazy;
use serde_json::Value;

pub static TEST_HEADERS: Lazy<Vec<(u32, [u8; 80])>> = Lazy::new(|| load_test_headers(false));
pub static EXHAUSTIVE_TEST_HEADERS: Lazy<Vec<(u32, [u8; 80])>> =
    Lazy::new(|| load_test_headers(true));

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
