use alloy::primitives::Address;
use axum::{extract::State, routing::get, Json, Router};
use bitcoin_light_client_core::hasher::Digest;
use bitcoin_light_client_core::leaves::BlockLeaf;
use clap::Parser;
use data_engine::engine::DataEngine;
use data_engine::models::OTCSwap;
use eyre::Result;
use rift_sdk::{create_websocket_provider, DatabaseLocation};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Websocket URL of the EVM network to subscribe to events on  
    #[arg(long)]
    evm_rpc_websocket_url: String,

    /// Rift Exchange contract address
    #[arg(long)]
    rift_exchange_address: String,

    /// The location of the database
    #[arg(long, value_parser)]
    database_location: DatabaseLocation,

    /// The block number when the contract was deployed
    #[arg(long)]
    deploy_block_number: u64,

    /// The port to listen on
    #[arg(long, default_value = "8201")]
    port: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Set up tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    // Parse CLI args
    let args = Args::parse();
    let provider = create_websocket_provider(&args.evm_rpc_websocket_url).await?;

    let data_engine = DataEngine::start(
        args.database_location,
        Arc::new(provider),
        args.rift_exchange_address,
        args.deploy_block_number,
    )
    .await?;

    // Build the Axum router
    let app = Router::new()
        .route("/swaps", get(get_swaps_for_address))
        .route("/tip-proof", get(get_tip_proof))
        .with_state(Arc::new(data_engine));

    let addr = SocketAddr::from(([127, 0, 0, 1], args.port));
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
