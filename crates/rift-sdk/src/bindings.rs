use alloy::sol;

// TODO: This scheme is horrendous, but needed b/c alloy/solidity doesn't automatically include ABI definitions
// for structs that aren't used as public arguments? investigate...
sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    RiftExchange,
    "../../contracts/artifacts/RiftExchange.json"
);

pub mod non_artifacted_types {
    use super::*;
    sol!("../../contracts/src/libraries/Types.sol",);
}
