pub mod bindings;
pub mod bitcoin_utils;
mod errors;
pub mod mmr;
pub mod txn_builder;

use alloy::providers::{ProviderBuilder, WsConnect};
use alloy::pubsub::{ConnectionHandle, PubSubConnect};
use alloy::rpc::client::ClientBuilder;
use alloy::transports::{impl_future, TransportResult};
use alloy::{
    primitives::Address,
    providers::Provider,
    pubsub::PubSubFrontend,
    rpc::types::{BlockNumberOrTag, Filter},
    sol_types::SolEvent,
};
use backoff::exponential::ExponentialBackoff;
use bitcoin::hashes::hex::FromHex;
use bitcoin_light_client_core::{
    hasher::{Digest, Keccak256Hasher},
    leaves::{decompress_block_leaves, BlockLeaf},
};
use sp1_sdk::client::ProverClientBuilder;
use sp1_sdk::HashableKey;
use sp1_sdk::Prover;
use sp1_sdk::{include_elf, ProverClient};
use std::fmt::Write;
use std::str::FromStr;

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const RIFT_PROGRAM_ELF: &[u8] = include_elf!("rift-program");

pub fn get_rift_program_hash() -> [u8; 32] {
    let client = ProverClient::builder().mock().build();
    let (_, vk) = client.setup(RIFT_PROGRAM_ELF);
    vk.bytes32_raw()
}

pub fn load_hex_bytes(file: &str) -> Vec<u8> {
    let hex_string = std::fs::read_to_string(file).expect("Failed to read file");
    Vec::<u8>::from_hex(&hex_string).expect("Failed to parse hex")
}

pub fn to_hex_string(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}

pub fn get_retarget_height_from_block_height(block_height: u64) -> u64 {
    block_height - (block_height % 2016)
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Where to store the database (in-memory or on disk).
pub enum DatabaseLocation {
    InMemory,
    Directory(String),
}

impl FromStr for DatabaseLocation {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "memory" => Ok(DatabaseLocation::InMemory),
            s => Ok(DatabaseLocation::Directory(s.to_string())),
        }
    }
}

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
        backoff::future::retry(
            ExponentialBackoff::<backoff::SystemClock>::default(),
            || async { Ok(self.0.try_reconnect().await?) },
        )
        .await
    }
}

pub async fn create_websocket_provider(
    evm_rpc_websocket_url: &str,
) -> errors::Result<impl Provider<PubSubFrontend>> {
    let ws = RetryWsConnect(WsConnect::new(evm_rpc_websocket_url));
    let client = ClientBuilder::default()
        .pubsub(ws)
        .await
        .map_err(|e| errors::RiftSdkError::WebsocketProviderError(e.to_string()))?;

    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .on_client(client);

    Ok(provider)
}
