use alloy::{
    primitives::Address,
    providers::{Provider, WsConnect},
    pubsub::{ConnectionHandle, PubSubConnect, PubSubFrontend},
    rpc::types::{BlockNumberOrTag, Filter},
    sol_types::SolEvent,
    transports::{impl_future, TransportResult},
};
use bitcoin_light_client_core::{
    hasher::{Digest, Keccak256Hasher},
    leaves::{decompress_block_leaves, BlockLeaf},
};
use eyre::Result;
use futures_util::stream::StreamExt;
use rift_sdk::bindings::{
    non_artifacted_types::Types::SwapUpdateContext, non_artifacted_types::Types::VaultUpdateContext,
};
use rift_sdk::mmr::IndexedMMR;
use rift_sdk::{bindings::RiftExchange, DatabaseLocation};

use std::{path::PathBuf, str::FromStr, sync::Arc};
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::db::{
    add_deposit, add_proposed_swap, get_proposed_swap_id, get_virtual_swaps, setup_swaps_database,
    update_deposit_to_withdrawn, update_proposed_swap_to_released,
};
use crate::models::OTCSwap;

#[derive(Clone)]
pub struct DataEngine {
    pub indexed_mmr: Arc<RwLock<IndexedMMR<Keccak256Hasher>>>,
    pub swap_database_connection: Arc<tokio_rusqlite::Connection>,
}

impl DataEngine {
    pub async fn start(
        database_location: DatabaseLocation,
        provider: Arc<dyn Provider<PubSubFrontend>>,
        rift_exchange_address: String,
        deploy_block_number: u64,
    ) -> Result<Self> {
        let indexed_mmr = Arc::new(RwLock::new(
            IndexedMMR::open(database_location.clone()).await?,
        ));
        let swap_database_connection = Arc::new(match database_location.clone() {
            DatabaseLocation::InMemory => tokio_rusqlite::Connection::open_in_memory().await?,
            DatabaseLocation::Directory(path) => {
                tokio_rusqlite::Connection::open(get_qualified_swaps_database_path(path)).await?
            }
        });
        setup_swaps_database(&swap_database_connection).await?;

        let indexed_mmr_clone = indexed_mmr.clone();
        let swap_database_connection_clone = swap_database_connection.clone();
        tokio::spawn(async move {
            listen_for_events(
                provider,
                &swap_database_connection_clone,
                indexed_mmr_clone,
                &rift_exchange_address,
                deploy_block_number,
            )
            .await
            .expect("listen_for_events failed");
        });

        Ok(Self {
            indexed_mmr,
            swap_database_connection,
        })
    }

    pub async fn get_virtual_swaps(
        &self,
        address: Address,
        page: u32,
        page_size: Option<u32>,
    ) -> Result<Vec<OTCSwap>> {
        let page_size = page_size.unwrap_or(50);
        get_virtual_swaps(&self.swap_database_connection, address, page, page_size).await
    }

    // get's the tip of the MMR, and returns a proof of the tip
    pub async fn get_tip_proof(&self) -> Result<(BlockLeaf, Vec<Digest>, Vec<Digest>)> {
        let mmr = self.indexed_mmr.read().await;
        let leaves_count = mmr.client_mmr().leaves_count.get().await?;
        let leaf_index = leaves_count - 1;
        let leaf = mmr.find_leaf_by_leaf_index(leaf_index).await?;
        match leaf {
            Some(leaf) => {
                let proof = mmr.get_circuit_proof(leaf_index, None).await?;
                let siblings = proof.siblings;
                let peaks = proof.peaks;
                Ok((leaf, siblings, peaks))
            }
            None => Err(eyre::eyre!("Leaf not found")),
        }
    }

    // Delegate method that provides read access to the mmr
    pub async fn get_leaf_count(&self) -> Result<usize> {
        let mmr = self.indexed_mmr.read().await;
        mmr.get_leaf_count().await.map_err(|e| eyre::eyre!(e))
    }
}

fn get_qualified_swaps_database_path(database_location: String) -> String {
    let path = PathBuf::from(database_location);
    let swaps_db_path = path.join("swaps.db");
    swaps_db_path.to_str().expect("Invalid path").to_string()
}

// This will run infinitely
pub async fn listen_for_events(
    provider: Arc<dyn Provider<PubSubFrontend>>,
    db_conn: &Arc<tokio_rusqlite::Connection>,
    indexed_mmr: Arc<RwLock<IndexedMMR<Keccak256Hasher>>>,
    rift_exchange_address: &str,
    deploy_block_number: u64,
) -> Result<()> {
    let rift_exchange_address = Address::from_str(rift_exchange_address)?;
    let filter = Filter::new()
        .address(rift_exchange_address)
        // TODO: Grab the latest block analyzed in the db, put that here
        // TODO: Consider how the add-to-db functions will behave if sent duplicate entries
        .from_block(BlockNumberOrTag::Number(deploy_block_number));

    let sub = provider.subscribe_logs(&filter).await?;
    let mut stream = sub.into_stream();

    while let Some(log) = stream.next().await {
        match log.topic0() {
            Some(&RiftExchange::VaultUpdated::SIGNATURE_HASH) => {
                if let Ok(decoded) = RiftExchange::VaultUpdated::decode_log(&log.inner, false) {
                    info!("Received VaultUpdated event...");
                    let deposit_vault = decoded.data.vault;
                    let log_txid = log.transaction_hash.expect("txid should be present");
                    let log_block_number =
                        log.block_number.expect("block number should be present");
                    let log_block_hash = log.block_hash.expect("block hash should be present");

                    // route depending on context event
                    match VaultUpdateContext::try_from(decoded.data.context)
                        .expect("context decoding succeeds")
                    {
                        VaultUpdateContext::Created => {
                            info!("Creating deposit for nonce: {:?}", deposit_vault.nonce.0);
                            add_deposit(
                                &db_conn,
                                deposit_vault,
                                log_block_number,
                                log_block_hash.into(),
                                log_txid.into(),
                            )
                            .await
                            .expect("add_deposit failed");
                        }
                        VaultUpdateContext::Withdraw => {
                            info!("Withdrawing deposit for nonce: {:?}", deposit_vault.nonce.0);
                            update_deposit_to_withdrawn(
                                &db_conn,
                                deposit_vault.nonce.0,
                                log_txid.into(),
                                log_block_number,
                                log_block_hash.into(),
                            )
                            .await
                            .expect("update_deposit_to_withdrawn failed");
                        }
                        _ => {}
                    }
                }
            }
            Some(&RiftExchange::SwapUpdated::SIGNATURE_HASH) => {
                if let Ok(decoded) = RiftExchange::SwapUpdated::decode_log(&log.inner, false) {
                    info!("Received SwapUpdated event");
                    let log_txid = log.transaction_hash.expect("txid should be present");
                    let log_block_number =
                        log.block_number.expect("block number should be present");
                    let log_block_hash = log.block_hash.expect("block hash should be present");

                    match SwapUpdateContext::try_from(decoded.data.context)
                        .expect("context decoding succeeds")
                    {
                        SwapUpdateContext::Created => {
                            info!(
                                "Received SwapUpdated event: proposed_swap_id = {:?}",
                                get_proposed_swap_id(&decoded.data.swap)
                            );
                            add_proposed_swap(
                                &db_conn,
                                &decoded.data.swap,
                                log_block_number,
                                log_block_hash.into(),
                                log_txid.into(),
                            )
                            .await
                            .expect("add_proposed_swap failed");
                        }
                        SwapUpdateContext::Complete => {
                            update_proposed_swap_to_released(
                                &db_conn,
                                get_proposed_swap_id(&decoded.data.swap),
                                log_txid.into(),
                                log_block_number,
                                log_block_hash.into(),
                            )
                            .await
                            .expect("update_proposed_swap_to_released failed");
                        }
                        _ => {}
                    }
                }
            }
            Some(&RiftExchange::BlockTreeUpdated::SIGNATURE_HASH) => {
                info!("Received BlockTreeUpdated event");
                let block_tree_updated =
                    RiftExchange::BlockTreeUpdated::decode_log(&log.inner, false)
                        .expect("decoding succeeds");
                let block_tree_root = block_tree_updated.data.treeRoot.0;
                let compressed_block_leaves =
                    block_tree_updated.data.compressedBlockLeaves.0.to_vec();
                // decode the compressed block leaves
                let block_leaves = decompress_block_leaves(&compressed_block_leaves);
                // add the block leaves to the db
                {
                    let mut mmr = indexed_mmr.write().await;
                    mmr.append_or_reorg_based_on_parent(&block_leaves).await?;
                }
                // calculate the root as a sanity check
                let root = indexed_mmr.read().await.get_root().await?;
                assert_eq!(root, block_tree_root);
            }
            _ => warn!("Unknown event topic"),
        }
    }

    Ok(())
}
