use clap::Parser;
use devnet::core::RiftDevnet;
use eyre::Result;
use tokio::signal;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Address to fund with cbBTC and Ether
    #[arg(short, long)]
    evm_address: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();
    let (devnet, _) = RiftDevnet::setup(true, args.evm_address, None).await?;
    signal::ctrl_c().await?;
    drop(devnet);
    Ok(())
}
