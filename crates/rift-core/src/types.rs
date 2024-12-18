use alloy_sol_types::sol;
pub type Sha256Digest = [u8; 32];

sol!(
    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    Types,
    "../../contracts/artifacts/RiftExchange.json"
);

pub type DepositVault = Types::DepositVault;
