use thiserror::Error;

#[derive(Error, Debug)]
pub enum RiftSdkError {
    #[error("Bitcoin RPC failed to download data: {0}")]
    BitcoinRpcError(String),

    #[error("Store failed to be utilized: {0}")]
    StoreError(String),

    #[error("Failed to initialize client MMR: {0}")]
    ClientMMRError(String),

    #[error("Failed to append leaf to MMR: {0}")]
    AppendLeafError(String),

    #[error("MMR error: {0}")]
    MMRError(String),
}

pub type Result<T> = std::result::Result<T, RiftSdkError>;
