use bitcoin::consensus::encode::deserialize;
use bitcoin::{Transaction, TxOut};

use sol_types::Types::DepositVault;

// Constants
const OP_RETURN_CODE: u8 = 0x6a;
const OP_PUSHBYTES_32: u8 = 0x20;

// Parses a transaction (with segwit data removed), and asserts that for every lp passed,
// there exists a UTXO in the transaction that matches the expected sats and script pub key.
pub fn validate_bitcoin_payment(
    txn_data: &[u8],
    reserved_vault: &DepositVault,
    vault_commitment: &[u8; 32],
) {
    let transaction: Transaction =
        deserialize(txn_data).expect("Failed to deserialize transaction");

    let output_counter = transaction.output.len() as u64;

    // The number of outputs must be at least 2 (1 LP output + 1 OP_RETURN output)
    assert!(output_counter >= 2);

    // the first output in the bitcoin transaction is ALWAYS the LP output
    let tx_out: &TxOut = &transaction.output[0];
    assert_eq!(tx_out.value.to_sat(), reserved_vault.expectedSats);
    assert_eq!(
        tx_out.script_pubkey.as_bytes(),
        reserved_vault.btcPayoutScriptPubKey
    );

    // the second output in the bitcoin transaction is ALWAYS the OP_RETURN output inscribing the vault commitment
    let op_return_output = &transaction.output[1];
    let op_return_script_pubkey = op_return_output.script_pubkey.as_bytes();
    assert_eq!(op_return_script_pubkey[0], OP_RETURN_CODE);
    assert_eq!(op_return_script_pubkey[1], OP_PUSHBYTES_32);

    let inscribed_vault_commitment = op_return_output.script_pubkey[2..34].as_bytes();
    assert_eq!(inscribed_vault_commitment, vault_commitment);
}
