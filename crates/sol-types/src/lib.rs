use alloy_sol_types::sol;
sol!(
    #[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq, Default)]
    TypeExposer,
    "../../contracts/artifacts/TypeExposer.json"
);
