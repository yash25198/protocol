use bitcoin::consensus::encode::deserialize;
use bitcoin::{Transaction, TxOut};

use crate::types::DepositVault;

// Constants
const OP_RETURN_CODE: u8 = 0x6a;
const OP_PUSHBYTES_32: u8 = 0x20;

// Parses a transaction (with segwit data removed), and asserts that for every lp passed,
// there exists a UTXO in the transaction that matches the expected sats and script pub key.
pub fn validate_bitcoin_payment(
    txn_data: &[u8],
    reserved_vaults: &[DepositVault],
    aggregate_vault_commitment: &[u8; 32],
) {
    let lp_count = reserved_vaults.len() as u64;
    assert!(lp_count > 0);
    let transaction: Transaction =
        deserialize(txn_data).expect("Failed to deserialize transaction");

    let output_counter = transaction.output.len() as u64;

    // LP count must be at least less than total outputs by 1, may be redundant
    assert!(lp_count < output_counter);

    // the first index up to index `lp_count-1` outputs in the bitcoin transaction are ALWAYS the LP outputs, in the order they are reserved onchain
    for (i, lp) in reserved_vaults.iter().enumerate() {
        let tx_out: &TxOut = &transaction.output[i];
        assert_eq!(tx_out.value.to_sat(), lp.expectedSats);
        assert_eq!(tx_out.script_pubkey.as_bytes(), lp.btcPayoutScriptPubKey);
    }

    // output after the LP outputs is ALWAYS the OP_RETURN output inscribing the aggregate vault commitment, any further outputs are up to the user to spend as they please (e.g. change, other unrelated outputs, etc)
    let op_return_output = &transaction.output[lp_count as usize];
    let op_return_script_pubkey = op_return_output.script_pubkey.as_bytes();
    assert_eq!(op_return_script_pubkey[0], OP_RETURN_CODE);
    assert_eq!(op_return_script_pubkey[1], OP_PUSHBYTES_32);

    let inscribed_aggregate_vault_commitment = op_return_output.script_pubkey[2..34].as_bytes();
    assert_eq!(
        inscribed_aggregate_vault_commitment,
        aggregate_vault_commitment
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    // TODO: Generate some test data from the solidity test
}
