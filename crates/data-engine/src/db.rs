use crate::models::{
    ChainAwareDeposit, ChainAwareProposedSwap, ChainAwareRelease, ChainAwareWithdraw, OTCSwap,
};
use alloy::primitives::keccak256;
use eyre::Result;
use rift_sdk::bindings::Types::{DepositVault, ProposedSwap};
use std::str::FromStr;
use tokio_rusqlite::{params, Connection};

/// Run initial table creation / migrations on an existing `tokio_sqlite::Connection`.
pub async fn setup_database(conn: &Connection) -> Result<()> {
    let schema = r#"
        CREATE TABLE IF NOT EXISTS deposits (
            deposit_id            BLOB(32) PRIMARY KEY,
            depositor             TEXT      NOT NULL,
            recipient             TEXT      NOT NULL,
            deposit_vault         TEXT      NOT NULL,

            deposit_block_number  INTEGER   NOT NULL,
            deposit_block_hash    BLOB(32)  NOT NULL,
            deposit_txid          BLOB(32)  NOT NULL,

            withdraw_txid         BLOB(32),
            withdraw_block_number INTEGER,
            withdraw_block_hash   BLOB(32)
        );

        CREATE TABLE IF NOT EXISTS proposed_swaps (
            proposed_swap_id       BLOB(32)  PRIMARY KEY,
            deposit_id             BLOB(32)  NOT NULL,

            proposed_block_number  INTEGER   NOT NULL,
            proposed_block_hash    BLOB(32)  NOT NULL,
            proposed_txid          BLOB(32)  NOT NULL,

            swap_proof             TEXT      NOT NULL,
            proposed_release_txid  BLOB(32),
            proposed_release_block_number INTEGER,
            proposed_release_block_hash   BLOB(32),

            FOREIGN KEY (deposit_id)
                REFERENCES deposits(deposit_id)
                ON DELETE CASCADE
        );
    "#;

    conn.call(|conn| {
        conn.execute_batch(schema)?;
        Ok(())
    })
    .await?;
    Ok(())
}

pub fn get_proposed_swap_id(swap: &ProposedSwap) -> [u8; 32] {
    // This should be unique for each proposed swap
    let mut id_material = swap.depositVaultNonce.to_vec();
    id_material.extend(swap.swapIndex.to_be_bytes::<32>().to_vec());
    keccak256(id_material).into()
}

pub async fn add_proposed_swap(
    conn: &Connection,
    swap: &ProposedSwap,
    swap_block_number: u64,
    swap_block_hash: [u8; 32],
    swap_txid: [u8; 32],
) -> Result<()> {
    let proposed_swap_id = get_proposed_swap_id(swap);
    let deposit_id = swap.depositVaultNonce.to_vec();
    let swap_proof_str = serde_json::to_string(&swap)
        .map_err(|e| eyre::eyre!("Failed to serialize ProposedSwap: {:?}", e))?;

    conn.call(move |conn| {
        conn.execute(
            r#"
        INSERT INTO proposed_swaps (
            proposed_swap_id,
            deposit_id,
            proposed_block_number,
            proposed_block_hash,
            proposed_txid,
            swap_proof
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
        "#,
            params![
                proposed_swap_id.to_vec(),
                deposit_id,
                swap_block_number as i64,
                swap_block_hash.to_vec(),
                swap_txid.to_vec(),
                swap_proof_str,
            ],
        )?;
        Ok(())
    })
    .await?;
    Ok(())
}

pub async fn update_proposed_swap_to_released(
    conn: &Connection,
    proposed_swap_id: [u8; 32],
    release_txid: [u8; 32],
    release_block_number: u64,
    release_block_hash: [u8; 32],
) -> Result<()> {
    conn.call(move |conn| {
        conn.execute(
            r#"
        UPDATE proposed_swaps
        SET proposed_release_txid = ?1,
            proposed_release_block_number = ?2,
            proposed_release_block_hash = ?3
        WHERE proposed_swap_id = ?4
        "#,
            params![
                release_txid.to_vec(),
                release_block_number as i64,
                release_block_hash.to_vec(),
                proposed_swap_id.to_vec()
            ],
        )?;
        Ok(())
    })
    .await?;
    Ok(())
}

pub async fn update_deposit_to_withdrawn(
    conn: &Connection,
    deposit_id: [u8; 32],
    withdraw_txid: [u8; 32],
    withdraw_block_number: u64,
    withdraw_block_hash: [u8; 32],
) -> Result<()> {
    conn.call(move |conn| {
        conn.execute(
            r#"
        UPDATE deposits
        SET withdraw_txid = ?1,
            withdraw_block_number = ?2,
            withdraw_block_hash = ?3
        WHERE deposit_id = ?4
        "#,
            params![
                withdraw_txid.to_vec(),
                withdraw_block_number as i64,
                withdraw_block_hash.to_vec(),
                deposit_id.to_vec()
            ],
        )?;
        Ok(())
    })
    .await?;
    Ok(())
}

pub async fn add_deposit(
    conn: &Connection,
    deposit: DepositVault,
    deposit_block_number: u64,
    deposit_block_hash: [u8; 32],
    deposit_txid: [u8; 32],
) -> Result<()> {
    let deposit_id = deposit.nonce.to_vec();
    let deposit_vault_str = serde_json::to_string(&deposit)
        .map_err(|e| eyre::eyre!("Failed to serialize DepositVault: {:?}", e))?;

    conn.call(move |conn| {
        conn.execute(
            r#"
        INSERT INTO deposits (
            deposit_id,
            depositor,
            recipient,
            deposit_vault,
            deposit_block_number,
            deposit_block_hash,
            deposit_txid
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        "#,
            params![
                deposit_id,
                deposit.ownerAddress.to_string(),
                deposit.specifiedPayoutAddress.to_string(),
                deposit_vault_str,
                deposit_block_number as i64,
                deposit_block_hash.to_vec(),
                deposit_txid.to_vec(),
            ],
        )?;
        Ok(())
    })
    .await?;

    Ok(())
}

pub async fn get_virtual_swap(conn: &Connection, deposit_id: [u8; 32]) -> Result<OTCSwap> {
    let deposit_id_vec = deposit_id.to_vec();

    // 1) Load the deposit row from `deposits`
    conn.call(move |conn| {
        let mut stmt = conn.prepare(
            r#"
            SELECT
                deposit_vault,
                deposit_block_number,
                deposit_block_hash,
                deposit_txid,
                withdraw_txid,
                withdraw_block_number,
                withdraw_block_hash
            FROM deposits
            WHERE deposit_id = ?1
            "#,
        )?;

        let mut rows = stmt.query(params![deposit_id_vec.clone()])?;

        let row = match rows.next()? {
            Some(r) => r,
            None => {
                return Err(tokio_rusqlite::Error::Other(Box::new(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("No deposit found for deposit_id = {:?}", deposit_id),
                ))));
            }
        };

        let deposit_vault_str: String = row.get(0)?;
        let deposit_block_number_i64: i64 = row.get(1)?;
        let deposit_block_hash_bytes: Vec<u8> = row.get(2)?;
        let deposit_txid_bytes: Vec<u8> = row.get(3)?;
        let withdraw_txid_opt_bytes: Option<Vec<u8>> = row.get(4)?;
        let withdraw_block_number_opt: Option<i64> = row.get(5)?;
        let withdraw_block_hash_opt_bytes: Option<Vec<u8>> = row.get(6)?;

        let deposit_block_number = deposit_block_number_i64 as u64;

        let deposit_block_hash: [u8; 32] = deposit_block_hash_bytes
            .try_into()
            .expect("Invalid deposit_block_hash length");
        let deposit_txid: [u8; 32] = deposit_txid_bytes
            .try_into()
            .expect("Invalid deposit_txid length");

        // Convert deposit_vault JSON to `DepositVault`
        let deposit_vault: DepositVault =
            serde_json::from_str(&deposit_vault_str).expect("Failed to parse DepositVault JSON");

        // Convert withdraw data
        let withdraw = match (
            withdraw_txid_opt_bytes,
            withdraw_block_number_opt,
            withdraw_block_hash_opt_bytes,
        ) {
            (Some(txid_bytes), Some(block_number), Some(block_hash_bytes)) => {
                let withdraw_txid = txid_bytes.try_into().expect("Invalid withdraw_txid length");
                let withdraw_block_hash = block_hash_bytes
                    .try_into()
                    .expect("Invalid withdraw_block_hash length");

                Some(ChainAwareWithdraw {
                    withdraw_txid,
                    withdraw_block_hash,
                    withdraw_block_number: block_number as u64,
                })
            }
            _ => None,
        };

        // 2) Load the proposed swaps from `proposed_swaps`
        let mut ps_stmt = conn.prepare(
            r#"
            SELECT
                proposed_block_number,
                proposed_block_hash,
                proposed_txid,
                swap_proof,
                proposed_release_txid,
                proposed_release_block_number,
                proposed_release_block_hash
            FROM proposed_swaps
            WHERE deposit_id = ?1
            ORDER BY proposed_swap_id ASC
            "#,
        )?;

        let mut rows = ps_stmt.query(params![deposit_id_vec])?;
        let mut chain_aware_swaps: Vec<ChainAwareProposedSwap> = Vec::new();

        while let Some(row) = rows.next()? {
            let proposed_block_number_i64: i64 = row.get(0)?;
            let proposed_block_number = proposed_block_number_i64 as u64;

            let proposed_block_hash_bytes: Vec<u8> = row.get(1)?;
            let proposed_block_hash: [u8; 32] = proposed_block_hash_bytes
                .try_into()
                .expect("Invalid proposed_block_hash length");

            let proposed_txid_bytes: Vec<u8> = row.get(2)?;
            let proposed_txid: [u8; 32] = proposed_txid_bytes
                .try_into()
                .expect("Invalid proposed_txid length");

            let swap_proof_str: String = row.get(3)?;
            let swap: ProposedSwap =
                serde_json::from_str(&swap_proof_str).expect("Failed to parse ProposedSwap JSON");

            let release_txid_opt: Option<Vec<u8>> = row.get(4)?;
            let proposed_release_block_number_opt: Option<i64> = row.get(5)?;
            let proposed_release_block_hash_opt: Option<Vec<u8>> = row.get(6)?;

            let release_txid = release_txid_opt.map(|bytes| {
                bytes
                    .try_into()
                    .expect("Invalid proposed_release_txid length")
            });

            // (Optionally, you might store more release info if needed.)
            let release_block_number = proposed_release_block_number_opt.map(|x| x as u64);
            let release_block_hash = proposed_release_block_hash_opt.map(|x| {
                x.try_into()
                    .expect("Invalid proposed_release_block_hash length")
            });

            let release = match (release_txid, release_block_number, release_block_hash) {
                (Some(txid), Some(block_number), Some(block_hash)) => Some(ChainAwareRelease {
                    release_txid: txid,
                    release_block_hash: block_hash,
                    release_block_number: block_number,
                }),
                _ => None,
            };

            let cap = ChainAwareProposedSwap {
                swap,
                swap_proof_txid: proposed_txid,
                swap_proof_block_hash: proposed_block_hash,
                swap_proof_block_number: proposed_block_number,
                release,
            };
            chain_aware_swaps.push(cap);
        }

        // 3) Construct the ChainAwareDeposit
        let chain_aware_deposit = ChainAwareDeposit {
            deposit: deposit_vault,
            deposit_block_number,
            deposit_block_hash,
            deposit_txid,
        };

        // 4) Construct the OTCSwap
        let otcswap = OTCSwap {
            deposit: chain_aware_deposit,
            swap_proofs: chain_aware_swaps,
            withdraw,
        };

        Ok(otcswap)
    })
    .await
    .map_err(|e| eyre::eyre!(e))
}
