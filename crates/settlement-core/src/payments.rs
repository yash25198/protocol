use bitcoin::consensus::encode::deserialize;
use bitcoin::{Transaction, TxOut};
/*

// Constants
const MAX_INPUT_COUNT: u64 = 1;
const OP_RETURN_CODE: u8 = 0x6a;
const OP_PUSHBYTES_32: u8 = 0x20;

// Parses a transaction (with segwit data removed), and asserts that for every lp passed,
// there exists a UTXO in the transaction that matches the expected sats and script pub key.
fn assert_payment_utxos_exist(
    txn_data: &[u8],
    reserved_vaults: &[DepositVault],
    lp_count: u64,
    order_nonce: [u8; 32],
) {
    let transaction: Transaction =
        deserialize(txn_data).expect("Failed to deserialize transaction");
    assert_eq!(transaction.input.len() as u64, MAX_INPUT_COUNT);

    let output_counter = transaction.output.len() as u64;
    // LP count must be at least less than total outputs by 1
    assert!(lp_count < output_counter);

    for (i, lp) in reserved_liquidity_providers.iter().enumerate() {
        if i < lp_count as usize {
            let tx_out: &TxOut = &transaction.output[i];
            assert_eq!(tx_out.value, lp.expected_sats);
            assert_eq!(tx_out.script_pubkey.as_bytes(), lp.script_pub_key);
        }
    }

    let op_return_output = &transaction.output[transaction.output.len() - 1];
    assert_eq!(op_return_output.script_pubkey[0], OP_RETURN_CODE);
    assert_eq!(op_return_output.script_pubkey[1], OP_PUSHBYTES_32);

    let inscribed_order_nonce = &op_return_output.script_pubkey[2..34];
    assert_eq!(inscribed_order_nonce, &order_nonce);
}

pub fn assert_bitcoin_payment(
    txn_data_no_segwit: &[u8],
    lp_reservation_data_encoded: Vec<[[u8; 32]; 2]>,
    order_nonce: [u8; 32],
    lp_count: u64,
) {
    assert!(lp_reservation_data_encoded.len() <= MAX_LIQUIDITY_PROVIDERS);
    let liquidity_providers = decode_liqudity_providers(lp_reservation_data_encoded);
    assert_payment_utxos_exist(
        txn_data_no_segwit,
        &liquidity_providers,
        lp_count,
        order_nonce,
    );
}

*/
