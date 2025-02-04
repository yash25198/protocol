use clap::Parser;
use devnet::RiftDevnet;
use eyre::Result;
use log::info;
use tokio::signal;

#[derive(Parser)]
#[command(author, version, about)]
struct Args {
    /// Address to fund with cbBTC and Ether
    #[arg(short, long)]
    evm_address: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    info!("Running devnet...");
    let args = Args::parse();

    let (devnet, _funding_sats) = RiftDevnet::setup(
        true,             // interactive
        args.evm_address, // an optional EVM address to fund
        None,
    )
    .await?;

    // Wait for Ctrl+C
    signal::ctrl_c().await?;
    drop(devnet);
    Ok(())
}
