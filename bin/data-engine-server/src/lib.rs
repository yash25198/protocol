use alloy::primitives::Address;
use axum::{extract::State, routing::get, Json, Router};
use bitcoin_light_client_core::hasher::Digest;
use bitcoin_light_client_core::leaves::BlockLeaf;
use clap::{command, Parser};
use data_engine::engine::DataEngine;
use data_engine::models::OTCSwap;
use eyre::Result;
use rift_sdk::{create_websocket_provider, DatabaseLocation};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Clone, Parser)]
#[command(author, version, about, long_about = None)]
pub struct ServerConfig {
    pub evm_rpc_websocket_url: String,
    pub rift_exchange_address: String,
    pub database_location: DatabaseLocation,
    pub deploy_block_number: u64,
    pub port: u16,
}

pub async fn run_server(config: ServerConfig, initial_block_leaf: BlockLeaf) -> Result<()> {
    let provider = create_websocket_provider(&config.evm_rpc_websocket_url).await?;

    let data_engine = DataEngine::start(
        config.database_location,
        Arc::new(provider),
        config.rift_exchange_address,
        config.deploy_block_number,
    )
    .await?;

    if data_engine.get_leaf_count().await? == 0 {
        // TODO: Create a more ergonomic abstraction over "seeding" the data engine if starting fresh
        let append_result = data_engine
            .indexed_mmr
            .write()
            .await
            .append(&initial_block_leaf)
            .await?;
        println!("Seeded data engine with genesis block leaf...");
    }

    // Build the Axum router
    let app = Router::new()
        .route("/swaps", get(get_swaps_for_address))
        .route("/tip-proof", get(get_tip_proof))
        .route("/contract-bitcoin-tip", get(get_latest_contract_block))
        .route("/health", get(health))
        .with_state(Arc::new(data_engine));

    let addr = SocketAddr::from(([127, 0, 0, 1], config.port));
    tracing::info!("Listening on {}", addr);

    // Spawn the HTTP server as another tracked task
    axum::serve(tokio::net::TcpListener::bind(&addr).await?, app)
        .await
        .map_err(|e| eyre::eyre!(e))?;

    Ok(())
}

#[derive(Deserialize, Serialize)]
struct VirtualSwapQuery {
    address: Address,
    page: u32,
}

#[axum::debug_handler]
async fn get_swaps_for_address(
    State(data_engine): State<Arc<DataEngine>>,
    Json(query): Json<VirtualSwapQuery>,
) -> Result<Json<Vec<OTCSwap>>, (axum::http::StatusCode, String)> {
    let swaps = data_engine
        .get_virtual_swaps(query.address, query.page, None)
        .await
        // TODO: More useful error handling
        .map_err(|e| {
            (
                axum::http::StatusCode::BAD_REQUEST,
                format!("Failed to get swaps: {:?}", e),
            )
        })?;
    Ok(Json(swaps))
}

#[derive(Deserialize, Serialize)]
struct TipProofResponse {
    leaf: BlockLeaf,
    siblings: Vec<Digest>,
    peaks: Vec<Digest>,
}

#[axum::debug_handler]
async fn get_tip_proof(
    State(data_engine): State<Arc<DataEngine>>,
) -> Result<Json<TipProofResponse>, (axum::http::StatusCode, String)> {
    let (leaf, siblings, peaks) = data_engine.get_tip_proof().await.map_err(|e| {
        (
            axum::http::StatusCode::BAD_REQUEST,
            format!("Failed to get tip proof: {}", e),
        )
    })?;
    Ok(Json(TipProofResponse {
        leaf,
        siblings,
        peaks,
    }))
}

#[axum::debug_handler]
async fn get_latest_contract_block(
    State(data_engine): State<Arc<DataEngine>>,
) -> Result<Json<u64>, (axum::http::StatusCode, String)> {
    let block_number = data_engine
        .get_leaf_count()
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(block_number as u64))
}

#[axum::debug_handler]
async fn health() -> Result<Json<String>, (axum::http::StatusCode, String)> {
    Ok(Json("OK".to_string()))
}
