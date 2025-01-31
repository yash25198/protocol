use crate::sp1_verifier_bytecode::{SP1_MOCK_VERIFIER_BYTECODE, SP1_VERIFIER_BYTECODE};
use alloy::network::{Ethereum, EthereumWallet};
use alloy::primitives::{ruint, Address, U256};
use alloy::providers::ext::AnvilApi;
use alloy::providers::fillers::WalletFiller;
use alloy::providers::fillers::{
    BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller,
};
use alloy::providers::{Identity, RootProvider};
use alloy::providers::{Provider, WsConnect};
use alloy::pubsub::ConnectionHandle;
use alloy::pubsub::PubSubConnect;
use alloy::sol;
use alloy::sol_types::SolCall;
use alloy::transports::http::{Client, Http};
use alloy::transports::{impl_future, TransportResult};
use alloy::{hex::FromHex, pubsub::PubSubFrontend};
use bitcoin::constants::genesis_block;
use bitcoin_light_client_core::hasher::Keccak256Hasher;
use chrono;
use data_engine_server::run_server;
use data_engine_server::ServerConfig;
use log::info;
use rift_sdk::DatabaseLocation;
use std::str::FromStr;
use std::sync::Arc;
use std::thread;
use tokio::runtime::Runtime;

use bitcoin_light_client_core::leaves::get_genesis_leaf;
use rift_sdk::bindings::{RiftExchange, Types};

// Spawn bitcoin and anvil processes, and deploy contracts to anvil.
use alloy::{
    hex,
    node_bindings::{Anvil, AnvilInstance},
    providers::ProviderBuilder,
    signers::local::PrivateKeySigner,
};
use eyre::{eyre, Result};

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    MockToken,
    "../../contracts/artifacts/MockToken.json"
);

pub type EvmWebsocketProvider = Arc<
    FillProvider<
        JoinFill<
            JoinFill<
                Identity,
                JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>,
            >,
            WalletFiller<EthereumWallet>,
        >,
        RootProvider<PubSubFrontend>,
        PubSubFrontend,
        Ethereum,
    >,
>;

pub type RiftExchangeWebsocket =
    RiftExchange::RiftExchangeInstance<PubSubFrontend, EvmWebsocketProvider>;

pub type MockTokenWebsocket = MockToken::MockTokenInstance<PubSubFrontend, EvmWebsocketProvider>;

pub struct RiftDevnet {
    pub anvil_instance: AnvilInstance,
    pub token_contract: Arc<MockTokenWebsocket>,
    pub rift_exchange_contract: Arc<RiftExchangeWebsocket>,
}

impl RiftDevnet {
    pub async fn setup(addresses: Option<Vec<String>>) -> Result<Self> {
        let anvil = spawn_anvil().await?;

        let hypernode_signer: PrivateKeySigner = anvil.keys()[1].clone().into();
        let hypernode_address = hypernode_signer.address();

        let sp1_circuit_verification_hash = rift_sdk::get_rift_program_hash();
        println!(
            "SP1 Circuit Verification Hash: {}",
            hex::encode(sp1_circuit_verification_hash)
        );

        // now setup contracts
        let (rift_exchange, token_contract, deployment_block_number) =
            deploy_contracts(&anvil, sp1_circuit_verification_hash).await?;

        let provider = rift_exchange.provider().clone();

        let data_engine_server_port = 50100;
        {
            let anvil_ws_url = anvil.ws_endpoint_url().to_string();
            let rift_exchange_address = rift_exchange.address().to_string();
            tokio::spawn(async move {
                run_server(
                    ServerConfig {
                        evm_rpc_websocket_url: anvil_ws_url,
                        rift_exchange_address,
                        database_location: DatabaseLocation::InMemory,
                        deploy_block_number: deployment_block_number,
                        port: data_engine_server_port,
                    },
                    get_genesis_leaf(),
                )
                .await
                .expect("Failed to run server");
            });
        }

        // give some eth using anvil
        provider
            .anvil_set_balance(hypernode_address, U256::from_str("10000000000000000000")?)
            .await?;

        println!("---RIFT DEVNET---");
        println!("Anvil HTTP Url:        {}", anvil.endpoint());
        println!("Anvil WS Url:          {}", anvil.ws_endpoint());
        println!("Anvil Chain ID:        {}", anvil.chain_id());
        println!(
            "Data Engine HTTP URL:  http://localhost:{}",
            data_engine_server_port
        );
        println!(
            "{:<22} {}",
            format!("{} Address:", token_contract.symbol().call().await?._0),
            token_contract.address()
        );
        println!("Rift Exchange Address: {}", rift_exchange.address());
        println!("---RIFT DEVNET---");

        if let Some(addresses) = addresses {
            for address in addresses {
                // mint some USDC and ETHER to each address
                let address = Address::from_str(&address)?;

                provider
                    .anvil_set_balance(address, U256::from_str("100000000000000000000")?) // 100 eth
                    .await?;

                token_contract
                    .mint(address, U256::from_str("1000000000000")?) // 1 mill
                    .send()
                    .await?
                    .get_receipt()
                    .await?;

                println!("Minted 1 million USDC to {}...", address);
                println!("Minted 100 ETH to {}...", address);
            }
        }

        Ok(RiftDevnet {
            anvil_instance: anvil,
            rift_exchange_contract: rift_exchange,
            token_contract,
        })
    }
}

async fn deploy_contracts(
    anvil: &AnvilInstance,
    circuit_verification_key_hash: [u8; 32],
) -> Result<(Arc<RiftExchangeWebsocket>, Arc<MockTokenWebsocket>, u64)> {
    let block_leaf = Types::BlockLeaf {
        height: get_genesis_leaf().height.into(),
        blockHash: get_genesis_leaf().hash::<Keccak256Hasher>().into(),
        cumulativeChainwork: ruint::Uint::<256, 4>::from_be_bytes(
            get_genesis_leaf().cumulative_chainwork,
        ),
    };
    // TODO: compute this based on the seeded blocks
    let genesis_mmr_root = hex!("5da557868f5475897cb308ca463cbcaa17d67ea04b0b099fe1dda086a7d1ccd8");

    let signer: PrivateKeySigner = anvil.keys()[0].clone().into();
    info!("Exchange owner address: {}", signer.address());
    let wallet = EthereumWallet::from(signer.clone());
    let provider = Arc::new(
        ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(wallet.clone())
            .on_ws(WsConnect::new(anvil.ws_endpoint_url()))
            .await
            .expect("Failed to connect to WebSocket"),
    );
    let verifier_contract =
        alloy::primitives::Address::from_str("0xaeE21CeadF7A03b3034DAE4f190bFE5F861b6ebf")?;

    provider
        .anvil_set_code(
            verifier_contract,
            Vec::from_hex(SP1_MOCK_VERIFIER_BYTECODE)?.into(),
        )
        .await?;

    let token_contract = MockToken::deploy(
        provider.clone(),
        "Coinbase Wrapped BTC".to_owned(),
        "cbBTC".to_owned(),
        8,
    )
    .await?;

    let deployment_block_number = provider.get_block_number().await?;
    let contract = RiftExchange::deploy(
        provider.clone(),
        genesis_mmr_root.into(),
        block_leaf,
        *token_contract.address(),
        circuit_verification_key_hash.into(),
        verifier_contract,
        wallet.default_signer().address(),
    )
    .await?;

    Ok((
        Arc::new(contract),
        Arc::new(token_contract),
        deployment_block_number,
    ))
}

async fn spawn_anvil() -> Result<AnvilInstance> {
    tokio::task::spawn_blocking(|| {
        let _ = Anvil::new().arg("--accounts").arg("20").spawn();
        Anvil::new()
            .block_time(1)
            .chain_id(1337)
            .port(50101_u16)
            .arg("--steps-tracing")
            .arg("--timestamp")
            .arg((chrono::Utc::now().timestamp() - 9 * 60 * 60).to_string())
            .try_spawn()
            .map_err(|e| eyre!(e))
    })
    .await?
}
