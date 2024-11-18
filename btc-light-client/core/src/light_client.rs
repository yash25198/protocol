use crate::types::Header;
use crypto_bigint::CheckedAdd;
use crypto_bigint::Encoding;
use crypto_bigint::U256;

// parent_ variables are assumed to be valid in the context of the header chain
pub fn validate_header_chain(
    parent_height: u32,
    parent_header: &Header,
    parent_retarget_header: &Header,
    header_chain: &[Header],
) {
    assert!(!header_chain.is_empty(), "Header chain must not be empty");

    let mut retarget_header = *parent_retarget_header;

    for (i, pair) in std::iter::once(parent_header)
        .chain(header_chain.iter())
        .collect::<Vec<_>>()
        .windows(2)
        .enumerate()
    {
        let previous_header = pair[0];
        let previous_height = parent_height + i as u32;
        let current_header = pair[1];

        assert!(
            bitcoin_core_rs::check_proof_of_work(current_header),
            "Header fails PoW check"
        );

        assert!(
            bitcoin_core_rs::check_header_connection(previous_header, current_header),
            "Header chain link is not connected"
        );

        let next_retarget = bitcoin_core_rs::validate_next_work_required(
            &retarget_header,
            previous_height,
            previous_header,
            current_header,
        );
        assert!(
            next_retarget.is_ok(),
            "Failed to validate work requirement: {:?}",
            next_retarget.err().unwrap()
        );
        retarget_header = next_retarget.unwrap();
    }
}

pub fn calculate_cumulative_work(parent_cumulative_work: U256, header_chain: &[Header]) -> U256 {
    header_chain
        .iter()
        .fold(parent_cumulative_work, |acc, header| {
            let header_proof =
                bitcoin_core_rs::get_block_proof(header).expect("Header proof calculation failed");
            U256::from_le_bytes(header_proof)
                .checked_add(&acc)
                .expect("Chainwork addition overflow")
        })
}
