use clap::Parser;
use devnet::core::RiftDevnet;
use eyre::Result;
use tokio::signal;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// List of addresses to use
    #[arg(short, long, value_delimiter = ',')]
    addresses: Option<Vec<String>>,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();
    let devnet = RiftDevnet::setup(args.addresses).await?;
    signal::ctrl_c().await?;
    drop(devnet);
    Ok(())
}
