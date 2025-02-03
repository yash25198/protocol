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
use bitcoin::address::NetworkChecked;
use bitcoin::constants::genesis_block;
use bitcoin::{Address as BitcoinAddress, Amount};
use bitcoin_light_client_core::hasher::Keccak256Hasher;
use chrono;
use corepc_node::{Client as BitcoinClient, CookieValues, Node as BitcoinRegtest};
use data_engine::engine::DataEngine;
use data_engine_server::DataEngineServer;
use data_engine_server::ServerConfig;
use log::info;
use rift_sdk::{create_websocket_provider, DatabaseLocation};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tokio::runtime::Runtime;
use tokio::time::Instant;

use bitcoin_light_client_core::leaves::get_genesis_leaf;
use bitcoin_light_client_core::leaves::BlockLeaf;
use bitcoincore_rpc_async::Auth;
use bitcoincore_rpc_async::RpcApi;
use rift_sdk::bindings::{RiftExchange, Types};
use rift_sdk::bitcoin_utils::AsyncBitcoinClient;
use rift_sdk::bitcoin_utils::AuthExt;
use rift_sdk::bitcoin_utils::BitcoinClientExt;

use alloy::{
    hex,
    node_bindings::{Anvil, AnvilInstance},
    providers::ProviderBuilder,
    signers::local::PrivateKeySigner,
};
use eyre::{eyre, Result};

const MINER_TAG: &str = "alice";

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
    pub anvil: AnvilInstance,
    pub bitcoin_regtest: BitcoinRegtest,
    pub token_contract: Arc<MockTokenWebsocket>,
    pub rift_exchange_contract: Arc<RiftExchangeWebsocket>,
    pub data_engine: Arc<DataEngine>,
    miner_client: BitcoinClient,
    miner_address: BitcoinAddress,
    // just a handle to keep it from being dropped
    _data_engine_server: Option<DataEngineServer>,
}

impl RiftDevnet {
    pub async fn setup(
        // if true, run the data engine server and log various devnet info (indiciating devnet is meant to be used w/ a frontend)
        interactive: bool,
        funded_evm_address: Option<String>,
        funded_bitcoin_address: Option<String>,
    ) -> Result<(Self, u64)> {
        info!("Starting devnet...");
        info!("Spawning Anvil...");
        let t = Instant::now();
        let anvil = spawn_anvil().await?;
        info!("Spawned Anvil in {:?}", t.elapsed());
        let evm_rpc_url = anvil.ws_endpoint_url().to_string();

        info!("Creating EVM RPC provider...");
        let t = Instant::now();
        let evm_ws_rpc = create_websocket_provider(&evm_rpc_url).await?;
        info!("Created EVM RPC provider in {:?}", t.elapsed());

        info!("Setting up Bitcoin Testnet...");
        let t = Instant::now();
        let (bitcoin_regtest, miner_client, miner_address, funding_sats, cookie) =
            spawn_bitcoin_regtest(funded_bitcoin_address)?;
        info!("Setup Bitcoin Testnet in {:?}", t.elapsed());
        // create an async bitcoin rpc client
        let bitcoin_rpc_url = bitcoin_regtest.rpc_url_with_wallet(MINER_TAG);

        info!("Creating Bitcoin RPC client...");
        let bitcoin_rpc_client = AsyncBitcoinClient::new(
            bitcoin_rpc_url,
            Auth::CookieFile(cookie),
            Duration::from_millis(250),
        )
        .await?;

        info!("Downloading checkpoint leaves...");
        let t = Instant::now();
        // download the checkpoint leaves from the bitcoin regtest node
        let checkpoint_leaves = bitcoin_rpc_client
            .get_leaves_from_block_range(0, 101, None)
            .await?;
        info!("Downloaded checkpoint leaves in {:?}", t.elapsed());

        info!("Seeding data engine...");
        let t = Instant::now();
        let mut data_engine =
            DataEngine::seed(DatabaseLocation::InMemory, checkpoint_leaves).await?;
        info!("Seeded data engine in {:?}", t.elapsed());

        info!("Getting genesis MMR root...");
        let t = Instant::now();
        let genesis_mmr_root = data_engine.indexed_mmr.read().await.get_root().await?;
        info!("Got genesis MMR root in {:?}", t.elapsed());

        info!("Getting rift program verification hash...");
        let t = Instant::now();
        let rift_program_verification_hash = rift_sdk::get_rift_program_hash();
        info!("Got rift program verification hash in {:?}", t.elapsed());

        let hypernode_signer: PrivateKeySigner = anvil.keys()[1].clone().into();
        let hypernode_address = hypernode_signer.address();

        let rift_program_verification_hash = rift_sdk::get_rift_program_hash();

        info!("Deploying contracts...");
        let t = Instant::now();
        // now setup contracts
        let (rift_exchange, token_contract, deployment_block_number) =
            deploy_contracts(&anvil, rift_program_verification_hash, genesis_mmr_root).await?;
        info!("Deployed contracts in {:?}", t.elapsed());
        let provider = rift_exchange.provider().clone();

        info!("Starting data engine listener...");
        let t = Instant::now();
        // start the data engine listener now that we've deployed the contracts
        data_engine
            .start_event_listener(
                provider.clone(),
                rift_exchange.address().to_string(),
                deployment_block_number,
            )
            .await?;
        info!("Started data engine listener in {:?}", t.elapsed());
        let data_engine = Arc::new(data_engine);

        info!("Starting data engine server...");
        let t = Instant::now();
        let data_engine_server_port = 50100;
        let data_engine_server: Option<DataEngineServer> = match interactive {
            true => Some(
                DataEngineServer::from_engine(data_engine.clone(), data_engine_server_port).await?,
            ),
            false => None,
        };
        info!("Started data engine server in {:?}", t.elapsed());
        // give some eth using anvil
        provider
            .anvil_set_balance(hypernode_address, U256::from_str("10000000000000000000")?)
            .await?;

        if interactive {
            println!("---RIFT DEVNET---");
            println!("Anvil HTTP Url:        {}", anvil.endpoint());
            println!("Anvil WS Url:          {}", anvil.ws_endpoint());
            println!("Anvil Chain ID:        {}", anvil.chain_id());
            println!(
                "Data Engine HTTP URL:  http://localhost:{}",
                data_engine_server_port
            );
            println!("Bitcoin RPC URL:       {}", bitcoin_regtest.rpc_url());
            println!(
                "{:<22} {}",
                format!("{} Address:", token_contract.symbol().call().await?._0),
                token_contract.address()
            );
            println!("Rift Exchange Address: {}", rift_exchange.address());
            println!("---RIFT DEVNET---");
        }

        info!("Funding EVM address...");
        let t = Instant::now();
        if let Some(funded_evm_address) = funded_evm_address {
            // mint some USDC and ETHER to each address
            let address = Address::from_str(&funded_evm_address)?;

            provider
                .anvil_set_balance(address, U256::from_str("100000000000000000000")?) // 100 eth
                .await?;

            token_contract
                .mint(address, U256::from_str("1000000000000")?) // 1 mill
                .send()
                .await?
                .get_receipt()
                .await?;

            println!("Minted 10,000 cbBTC to {}...", funded_evm_address);
            println!("Minted 100 ETH to {}...", funded_evm_address);
        }
        info!("Funded EVM address in {:?}", t.elapsed());

        Ok((
            RiftDevnet {
                anvil,
                bitcoin_regtest,
                miner_client,
                miner_address,
                rift_exchange_contract: rift_exchange,
                token_contract,
                data_engine,
                _data_engine_server: data_engine_server,
            },
            funding_sats,
        ))
    }

    pub async fn deal_bitcoin(&self, address: BitcoinAddress, amount: Amount) -> Result<()> {
        // for every block mined, we get access to 50 BTC
        let blocks_to_mine = (amount.to_btc() / 50.0).ceil() as usize;
        self.bitcoin_regtest
            .client
            .generate_to_address(blocks_to_mine, &self.miner_address)
            .unwrap();
        self.miner_client.send_to_address(&address, amount).unwrap();
        Ok(())
    }
}

async fn deploy_contracts(
    anvil: &AnvilInstance,
    circuit_verification_key_hash: [u8; 32],
    genesis_mmr_root: [u8; 32],
) -> Result<(Arc<RiftExchangeWebsocket>, Arc<MockTokenWebsocket>, u64)> {
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

fn spawn_bitcoin_regtest(
    funded_address: Option<String>,
) -> Result<(BitcoinRegtest, BitcoinClient, BitcoinAddress, u64, PathBuf)> {
    let funding_sats: u64 = match funded_address.is_some() {
        true => Amount::from_btc(49.95).unwrap().to_sat(),
        false => 0,
    };
    info!("Instantiating Bitcoin Regtest...");
    let t = Instant::now();
    let bitcoin_regtest = BitcoinRegtest::from_downloaded().map_err(|e| eyre!(e))?;
    info!("Instantiated Bitcoin Regtest in {:?}", t.elapsed());
    let cookie = bitcoin_regtest.params.cookie_file.clone();
    let alice = bitcoin_regtest.create_wallet(MINER_TAG).unwrap();
    let alice_address = alice.new_address().unwrap();
    // 101 blocks mined = 1 block worth of mining rewards (50 BTC * n)
    // increasing this will add instantiation delay
    bitcoin_regtest
        .client
        .generate_to_address(101, &alice_address)
        .unwrap();

    if let Some(funded_address) = funded_address {
        alice
            .send_to_address(
                &BitcoinAddress::from_str(&funded_address)?.assume_checked(),
                Amount::from_sat(funding_sats),
            )
            .unwrap();
    }

    Ok((bitcoin_regtest, alice, alice_address, funding_sats, cookie))
}

mod test {
    use super::*;

    #[tokio::test]
    async fn test_devnet_starts() {
        let (rift_devnet, _) = RiftDevnet::setup(true, None, None).await.unwrap();
    }
}
