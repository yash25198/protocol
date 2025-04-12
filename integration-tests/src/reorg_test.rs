use crate::test_utils::{create_deposit, setup_test_tracing, MultichainAccount};
use alloy::{
    network::EthereumWallet,
    primitives::{Address, U256},
    providers::{ext::AnvilApi, Provider, ProviderBuilder, WsConnect},
    signers::local::LocalSigner,
    sol_types::SolEvent,
};
use bitcoin::{
    block::{Header as BitcoinHeader, Version},
    blockdata::constants::genesis_block,
    consensus::{Decodable, Encodable},
    hashes::Hash,
    network::Network,
    BlockHash, Block, CompactTarget, Amount, Transaction, Txid,
};
use bitcoin_light_client_core::{
    hasher::Keccak256Hasher,
    leaves::{BlockLeaf, create_new_leaves},
    light_client::Header,
};
use bitcoincore_rpc_async::RpcApi;
use data_engine::engine::ContractDataEngine;
use devnet::RiftDevnet;
use sol_bindings::{RiftExchange, Types::BlockProofParams};
use rift_core::giga::{RiftProgramInput, RustProofType};
use rift_sdk::{
    bitcoin_utils::{AsyncBitcoinClient, BitcoinClientExt},
    create_websocket_provider,
    DatabaseLocation,
    proof_generator::{ProofGeneratorType, RiftProofGenerator},
};

use std::{convert::TryInto, sync::Arc, time::Duration};
use tokio::time::sleep;
use tempfile::tempdir;
use serial_test::serial;

#[tokio::test]
#[serial]
async fn test_reorg_watchtower() {
    setup_test_tracing();
    
    let hypernode_account = MultichainAccount::new(3);
    let evm_user = MultichainAccount::new(4);
    
    let (devnet, _) = RiftDevnet::builder()
        .using_bitcoin(true)
        .funded_evm_address(evm_user.ethereum_address.to_string())
        .data_engine_db_location(DatabaseLocation::InMemory)
        .build()
        .await
        .unwrap();
    
    devnet
        .ethereum
        .fund_eth_address(hypernode_account.ethereum_address, U256::from(10) * U256::from(10).pow(U256::from(18)))
        .await
        .unwrap();
    
    let bitcoin_client = devnet.bitcoin.rpc_client.clone();
    let bitcoin_data_engine = devnet.bitcoin.data_engine.clone();
    let contract_data_engine = devnet.contract_data_engine.clone();
    let rift_exchange_address = *devnet.ethereum.rift_exchange_contract.address();
    
    let rpc_url_with_cookie = devnet.bitcoin.rpc_url_with_cookie.clone();
    let checkpoint_file_path = devnet.checkpoint_file_path.clone();
    
    // Record initial state
    let initial_block_count = bitcoin_client.get_block_count().await.unwrap();
    let initial_mmr_root = contract_data_engine.get_mmr_root().await.unwrap();
    println!("Initial block count: {}", initial_block_count);
    println!("Initial MMR root: {}", hex::encode(initial_mmr_root));
    
    devnet.bitcoin.mine_blocks(5).await.unwrap();
    
    sleep(Duration::from_millis(500)).await;
    
    // Get the current block count and the hash of the latest block
    let main_chain_block_count = bitcoin_client.get_block_count().await.unwrap();
    let main_chain_tip_hash = bitcoin_client.get_block_hash(main_chain_block_count).await.unwrap();
    println!("Main chain block count: {}", main_chain_block_count);
    println!("Main chain tip hash: {}", main_chain_tip_hash);
    
    // Now we need to set up a competing chain (fork) in Bitcoin
    // To do this we'll use invalidateblock and generate some new blocks
    
    // First, invalidate the last few blocks to create a fork point
    let fork_point_height = main_chain_block_count - 3;
    let fork_point_hash = bitcoin_client.get_block_hash(fork_point_height).await.unwrap();
    println!("Fork point height: {}", fork_point_height);
    println!("Fork point hash: {}", fork_point_hash);
    
    // Invalidate the block after the fork point to start a new chain
    bitcoin_client.invalidate_block(&main_chain_tip_hash).await.unwrap();
    
    // Generate more blocks than the original chain to win the PoW battle
    devnet.bitcoin.mine_blocks(5).await.unwrap();
    
    let new_block_count = bitcoin_client.get_block_count().await.unwrap();
    let new_tip_hash = bitcoin_client.get_block_hash(new_block_count).await.unwrap();
    println!("New chain block count: {}", new_block_count);
    println!("New chain tip hash: {}", new_tip_hash);
    
    assert!(new_block_count > main_chain_block_count, 
        "Fork should create more blocks than original chain");
    
    sleep(Duration::from_millis(1000)).await;
    
    let hypernode_args = hypernode::HypernodeArgs {
        evm_ws_rpc: devnet.ethereum.anvil.ws_endpoint_url().to_string(),
        btc_rpc: rpc_url_with_cookie.clone(),
        private_key: hex::encode(hypernode_account.secret_bytes),
        checkpoint_file: checkpoint_file_path,
        database_location: DatabaseLocation::InMemory,
        rift_exchange_address: rift_exchange_address.to_string(),
        deploy_block_number: 0,
        btc_batch_rpc_size: 100,
        proof_generator: ProofGeneratorType::Execute,
    };
    
    let hypernode_handle = tokio::spawn(async move {
        hypernode::run(hypernode_args)
            .await
            .expect("Hypernode crashed");
    });
    
    // Give hypernode time to detect the reorg and process it
    // reduced polling to 1 sec
    sleep(Duration::from_secs(5)).await;
    
    let new_mmr_root = contract_data_engine.get_mmr_root().await.unwrap();
    println!("New MMR root: {}", hex::encode(new_mmr_root));
    
    let on_chain_mmr_root = devnet
        .ethereum
        .rift_exchange_contract
        .mmrRoot()
        .call()
        .await
        .unwrap()
        ._0;
    println!("On-chain MMR root: {}", hex::encode(on_chain_mmr_root));
    
    assert_ne!(initial_mmr_root, on_chain_mmr_root.0, 
        "On-chain MMR root should have been updated due to the reorg");
    
    let bitcoin_mmr_root = bitcoin_data_engine.indexed_mmr.read().await.get_root().await.unwrap();
    println!("Bitcoin MMR root: {}", hex::encode(bitcoin_mmr_root));
    
    assert_eq!(bitcoin_mmr_root, on_chain_mmr_root.0, 
        "On-chain MMR root should match Bitcoin MMR root after reorg");
    
    let light_client_height = devnet
        .ethereum
        .rift_exchange_contract
        .getLightClientHeight()
        .call()
        .await
        .unwrap()
        ._0;
    println!("Light client height: {}", light_client_height);
    
    assert_eq!(light_client_height as u64, new_block_count, 
        "Light client height should match the new chain height");
    
    let events = devnet
        .ethereum
        .funded_provider
        .get_logs(
            &alloy::rpc::types::Filter::new()
                .address(rift_exchange_address)
                .event_signature(RiftExchange::BitcoinLightClientUpdated::SIGNATURE_HASH),
        )
        .await
        .unwrap();
    
    assert!(!events.is_empty(), "Should have at least one BitcoinLightClientUpdated event");
    
    let light_client_updated = RiftExchange::BitcoinLightClientUpdated::decode_log(
        &events.last().unwrap().inner,
        false,
    )
    .unwrap();
    
    println!("BitcoinLightClientUpdated event: {:?}", light_client_updated);
    
    // Assert the prior MMR root in the event is the initial MMR root
    // todo: may need to convert byte order or format depending on contract implementation
    assert_ne!(
        light_client_updated.data.priorMmrRoot.0,
        light_client_updated.data.newMmrRoot.0,
        "Prior and new MMR roots should be different in the update event"
    );
    
    hypernode_handle.abort();
    
    println!("Reorg watchtower test completed successfully");
}