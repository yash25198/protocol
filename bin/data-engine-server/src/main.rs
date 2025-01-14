use axum::{extract::State, routing::get, Json, Router};
use clap::Parser;
use data_engine::db::setup_database;
use data_engine::db::DatabaseLocation;
use data_engine::engine::listen_for_events;
use data_engine::models::OTCSwap;
use eyre::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio_rusqlite::Connection;
use tokio_util::task::TaskTracker;

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

    // Create an async connection
    let conn = match &args.database_location {
        DatabaseLocation::InMemory => Arc::new(Connection::open_in_memory().await?),
        DatabaseLocation::File(path) => Arc::new(Connection::open(path).await?),
    };

    // Run your schema setup / migrations
    setup_database(&conn.clone()).await?;

    // Set up a TaskTracker to manage tasks
    let tracker = TaskTracker::new();

    {
        let conn = conn.clone();
        tracker.spawn(async move {
            listen_for_events(
                &args.evm_rpc_websocket_url,
                &args.rift_exchange_address,
                &conn,
                args.deploy_block_number,
            )
            .await
            .expect("Event listener failed"); //TODO: Propagate error
        });
    }

    // Build the Axum router
    let app = Router::new()
        .route("/swaps", get(get_user_swaps))
        .with_state(conn.clone());

    let addr = SocketAddr::from(([127, 0, 0, 1], args.port));
    tracing::info!("Listening on {}", addr);

    // Spawn the HTTP server as another tracked task
    tracker.spawn(async move {
        axum::serve(tokio::net::TcpListener::bind(&addr).await?, app)
            .await
            .map_err(|e| eyre::eyre!(e))?;
        Ok::<_, eyre::Report>(())
    });

    // Close the tracker to prevent new tasks from being spawned
    tracker.close();

    // Wait for all tasks and propagate any errors
    tracker.wait().await;

    Ok(())
}

async fn get_user_swaps(State(conn): State<Arc<Connection>>) -> Json<Vec<OTCSwap>> {
    // TODO: Implement your logic to fetch OTCSwaps from the DB.
    // For now, just returning an empty Vec:
    Json(vec![])
}
