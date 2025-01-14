use alloy::{
    primitives::Address,
    providers::{Provider, ProviderBuilder, WsConnect},
    pubsub::{ConnectionHandle, PubSubConnect},
    rpc::{
        client::ClientBuilder,
        types::{BlockNumberOrTag, Filter},
    },
    sol_types::SolEvent,
    transports::{impl_future, TransportResult},
};
use backoff::ExponentialBackoff;
use eyre::Result;
use futures_util::stream::StreamExt;
use rift_sdk::bindings::RiftExchange;
use rift_sdk::bindings::{
    non_artifacted_types::Types::SwapUpdateContext, non_artifacted_types::Types::VaultUpdateContext,
};
use std::str::FromStr;
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::db::{
    add_deposit, add_proposed_swap, get_proposed_swap_id, update_deposit_to_withdrawn,
    update_proposed_swap_to_released,
};
use crate::models::OTCSwap;

#[derive(Clone, Debug)]
pub struct RetryWsConnect(WsConnect);

impl PubSubConnect for RetryWsConnect {
    fn is_local(&self) -> bool {
        self.0.is_local()
    }

    fn connect(&self) -> impl_future!(<Output = TransportResult<ConnectionHandle>>) {
        self.0.connect()
    }

    async fn try_reconnect(&self) -> TransportResult<ConnectionHandle> {
        backoff::future::retry(ExponentialBackoff::default(), || async {
            Ok(self.0.try_reconnect().await?)
        })
        .await
    }
}

// This will run infinitely
pub async fn listen_for_events(
    evm_rpc_websocket_url: &str,
    rift_exchange_address: &str,
    db_conn: &tokio_rusqlite::Connection,
    deploy_block_number: u64,
) -> Result<()> {
    let ws = RetryWsConnect(WsConnect::new(evm_rpc_websocket_url));
    let client = ClientBuilder::default().pubsub(ws).await?;

    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .on_client(client);

    let rift_exchange_address = Address::from_str(rift_exchange_address)?;
    let filter = Filter::new()
        .address(rift_exchange_address)
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
            _ => warn!("Unknown event topic"),
        }
    }

    Ok(())
}
