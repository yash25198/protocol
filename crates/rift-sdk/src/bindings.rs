use alloy::sol;

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    RiftExchange,
    "../../contracts/artifacts/RiftExchange.json"
);
