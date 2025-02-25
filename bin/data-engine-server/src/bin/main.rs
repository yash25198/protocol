use bitcoin_light_client_core::leaves::get_genesis_leaf;
use clap::Parser;
use eyre::Result;

use data_engine::engine::DataEngine;
use data_engine_server::DataEngineServer;
use data_engine_server::ServerConfig;
use rift_sdk::DatabaseLocation;

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
    let config = ServerConfig::parse();
    let checkpoint_leaves =
        checkpoint_downloader::decompress_checkpoint_file(&config.checkpoint_file).unwrap();

    let data_engine_server = DataEngineServer::start(config, checkpoint_leaves).await?;
    data_engine_server.server_handle.await?;
    Ok(())
}
