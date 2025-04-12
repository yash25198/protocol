use crate::swap_watchtower::build_chain_transition_for_light_client_update;
use crate::txn_broadcast::{PreflightCheck, TransactionBroadcaster, TransactionExecutionResult};
use alloy::{
    primitives::Address, providers::Provider, pubsub::PubSubFrontend,
    rpc::types::TransactionRequest,
};
use bitcoin_light_client_core::{
    hasher::{Digest, Keccak256Hasher},
    ChainTransition,
};
use bitcoincore_rpc_async::RpcApi;
use rift_core::giga::{RiftProgramInput, RustProofType};
use rift_sdk::{
    bitcoin_utils::AsyncBitcoinClient, checkpoint_mmr::CheckpointedBlockTree,
    indexed_mmr::IndexedMMR, proof_generator::RiftProofGenerator, WebsocketWalletProvider,
};
use sol_bindings::{
    RiftExchange::{self, RiftExchangeInstance},
    Types::BlockProofParams,
};
use std::sync::Arc;
use tokio::{
    sync::{broadcast, RwLock},
    task::JoinSet,
    time::{sleep, Duration},
};
use tracing::{info, info_span, warn, Instrument};

/// Events that may be broadcast by the Fork Watchtower
#[derive(Debug, Clone)]
pub enum ReorgWatchtowerEvent {
    /// Reorg detected between Bitcoin chain and on-chain light client
    ReorgDetected {
        bitcoin_root: Digest,
        light_client_root: Digest,
    },
    /// A reorg update transaction has been successfully submitted
    ReorgUpdateSubmitted { transaction_hash: String },
    /// A reorg update has been confirmed on-chain
    ReorgUpdateConfirmed {
        transaction_hash: String,
        new_mmr_root: Digest,
    },
    /// A reorg update transaction failed
    ReorgUpdateFailed { reason: String },
}

pub struct ReorgWatchtower {
    /// Sender for broadcasting reorg events
    event_sender: broadcast::Sender<ReorgWatchtowerEvent>,
}

impl ReorgWatchtower {
    pub fn run(
        bitcoin_data_engine: Arc<BitcoinDataEngine>,
        contract_data_engine: Arc<ContractDataEngine>,
        btc_rpc: Arc<AsyncBitcoinClient>,
        evm_rpc: Arc<WebsocketWalletProvider>,
        rift_exchange_address: Address,
        transaction_broadcaster: Arc<TransactionBroadcaster>,
        bitcoin_concurrency_limit: usize,
        proof_generator: Arc<RiftProofGenerator>,
        join_set: &mut JoinSet<eyre::Result<()>>,
    ) -> Self {
        // Create broadcast channel for reorg events with buffer capacity of 100
        let (event_sender, _) = broadcast::channel(100);
        let event_sender_clone = event_sender.clone();

        // Create the RiftExchange contract instance
        let rift_exchange = RiftExchange::new(rift_exchange_address, evm_rpc.clone());

        // Spawn the reorg detection and processing task
        join_set.spawn(
            async move {
                Self::detect_and_process_reorgs(
                    bitcoin_data_engine.indexed_mmr.clone(),
                    contract_data_engine.checkpointed_block_tree.clone(),
                    btc_rpc,
                    rift_exchange,
                    transaction_broadcaster,
                    bitcoin_concurrency_limit,
                    proof_generator,
                    event_sender_clone,
                )
                .await
            }
            .instrument(info_span!("Fork Watchtower")),
        );

        Self { event_sender }
    }

    /// Returns a receiver to subscribe to Fork Watchtower events
    pub fn subscribe(&self) -> broadcast::Receiver<ReorgWatchtowerEvent> {
        self.event_sender.subscribe()
    }

    /// Main loop to detect and process reorgs
    async fn detect_and_process_reorgs(
        bitcoin_mmr: Arc<RwLock<IndexedMMR<Keccak256Hasher>>>,
        light_client_mmr: Arc<RwLock<CheckpointedBlockTree<Keccak256Hasher>>>,
        btc_rpc: Arc<AsyncBitcoinClient>,
        rift_exchange: RiftExchangeInstance<PubSubFrontend, Arc<WebsocketWalletProvider>>,
        transaction_broadcaster: Arc<TransactionBroadcaster>,
        bitcoin_concurrency_limit: usize,
        proof_generator: Arc<RiftProofGenerator>,
        event_sender: broadcast::Sender<ReorgWatchtowerEvent>,
    ) -> eyre::Result<()> {
        info!("Starting Fork Watchtower reorg detection loop");

        // Poll interval for checking reorgs
        // 30 seconds should be more than enough to detect reorgs
        const POLL_INTERVAL: Duration = Duration::from_secs(30);

        loop {
            match Self::check_and_handle_reorg(
                &bitcoin_mmr,
                &light_client_mmr,
                &btc_rpc,
                &rift_exchange,
                &transaction_broadcaster,
                bitcoin_concurrency_limit,
                &proof_generator,
                &event_sender,
            )
            .await
            {
                Ok(reorg_detected) => {
                    if reorg_detected {
                        info!("Successfully processed reorg");
                    }
                }
                Err(e) => {
                    let error_msg = format!("Error checking for reorgs: {}", e);
                    warn!("{}", error_msg);

                    // Broadcast failure event
                    let _ = event_sender
                        .send(ReorgWatchtowerEvent::ReorgUpdateFailed { reason: error_msg });
                }
            }

            // Wait before next check
            sleep(POLL_INTERVAL).await;
        }
    }

    /// Checks if a reorg has occurred and handles it if needed
    ///
    /// Returns true if a reorg was detected and handled
    async fn check_and_handle_reorg(
        bitcoin_mmr: &Arc<RwLock<IndexedMMR<Keccak256Hasher>>>,
        light_client_mmr: &Arc<RwLock<CheckpointedBlockTree<Keccak256Hasher>>>,
        btc_rpc: &Arc<AsyncBitcoinClient>,
        rift_exchange: &RiftExchangeInstance<PubSubFrontend, Arc<WebsocketWalletProvider>>,
        transaction_broadcaster: &Arc<TransactionBroadcaster>,
        bitcoin_concurrency_limit: usize,
        proof_generator: &Arc<RiftProofGenerator>,
        event_sender: &broadcast::Sender<ReorgWatchtowerEvent>,
    ) -> eyre::Result<bool> {
        let btc_mmr_guard = bitcoin_mmr.read().await;
        let light_client_guard = light_client_mmr.read().await;

        // Get the roots from both chains
        let btc_root = btc_mmr_guard.get_root().await?;
        let light_client_root = light_client_guard.get_root().await?;

        // If roots match, no reorg needed
        if btc_root == light_client_root {
            // No reorg detected
            return Ok(false);
        }

        info!(
            "Detected potential reorg - Bitcoin chain root ({}) differs from light client root ({})",
            hex::encode(&btc_root),
            hex::encode(&light_client_root)
        );

        // Broadcast reorg detection event
        let _ = event_sender.send(ReorgWatchtowerEvent::ReorgDetected {
            bitcoin_root: btc_root,
            light_client_root,
        });

        // We detected a reorg, now we need to build a chain transition
        // to update the light client
        let chain_transition = build_chain_transition_for_light_client_update(
            btc_rpc.clone(),
            &btc_mmr_guard,
            &light_client_guard,
            bitcoin_concurrency_limit,
        )
        .await?;

        info!("Generated chain transition for light client update");

        // Generate a proof for this chain transition
        let rift_program_input = RiftProgramInput::builder()
            .proof_type(RustProofType::LightClientOnly)
            .light_client_input(chain_transition)
            .build()
            .map_err(|e| eyre::eyre!("Failed to build rift program input: {}", e))?;

        info!("Generating proof for light client update");

        let (public_values_simulated, auxiliary_data) =
            rift_program_input.get_auxiliary_light_client_data();

        let proof = proof_generator
            .prove(&rift_program_input)
            .await
            .map_err(|e| eyre::eyre!("Failed to generate proof: {}", e))?;

        info!("Proof generated successfully");

        // We no longer need the read locks, drop them
        drop(btc_mmr_guard);
        drop(light_client_guard);

        // Prepare the transaction to update the light client
        let block_proof_params = BlockProofParams {
            priorMmrRoot: public_values_simulated.previousMmrRoot,
            newMmrRoot: public_values_simulated.newMmrRoot,
            tipBlockLeaf: public_values_simulated.tipBlockLeaf,
            compressedBlockLeaves: auxiliary_data.compressed_leaves.into(),
        };

        let proof_bytes = match proof.proof {
            Some(p) => p.bytes(),
            None => {
                warn!("No proof used for light client update, assuming mock proof");
                vec![]
            }
        };

        // Create the updateLightClient call using the RiftExchange contract
        let update_call = rift_exchange.updateLightClient(block_proof_params, proof_bytes.into());
        let calldata = update_call.calldata().to_owned();
        let transaction_request = update_call.into_transaction_request();

        info!("Broadcasting light client update transaction");

        let result = transaction_broadcaster
            .broadcast_transaction(calldata, transaction_request, PreflightCheck::Simulate)
            .await?;

        match result {
            TransactionExecutionResult::Success(receipt) => {
                info!(
                    "Light client update transaction confirmed: {:?}",
                    receipt.transaction_hash
                );

                // Broadcast success event
                let _ = event_sender.send(ReorgWatchtowerEvent::ReorgUpdateConfirmed {
                    transaction_hash: format!("{:?}", receipt.transaction_hash),
                    new_mmr_root: public_values_simulated.newMmrRoot.into(),
                });

                Ok(true)
            }

            TransactionExecutionResult::Revert(revert_info) => {
                let error_msg = format!(
                    "Light client update transaction reverted: {:?}",
                    revert_info
                );
                warn!("{}", error_msg);

                // Broadcast failure event
                let _ = event_sender
                    .send(ReorgWatchtowerEvent::ReorgUpdateFailed { reason: error_msg });

                Ok(false)
            }

            _ => {
                let error_msg = format!("Light client update transaction failed: {:?}", result);
                warn!("{}", error_msg);

                // Broadcast failure event
                let _ = event_sender
                    .send(ReorgWatchtowerEvent::ReorgUpdateFailed { reason: error_msg });

                Ok(false)
            }
        }
    }
}
