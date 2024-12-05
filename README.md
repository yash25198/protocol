# Rift Protocol Monorepo
All the components that secure Rift
- [`bitcoin-light-client-program`](./crates/bitcoin-light-client-program/): Circuit validating Bitcoin Proof of Work and longest chain
- [`rift-settlement-program`](./crates/rift-settlement-program/): Circuit validating Bitcoin<>Ethereum order settlement
- [`contracts`](./contracts): Solidity smart contracts for the Rift Settlement Layer 
- [`hypernode`](./bin/hypernode): Bitcoin and Ethereum indexer with hooks to trigger proof generation
- [`e2e-tests`](./bin/hypernode): End-to-end testing suite for the entire system 
- [`data-aggregation-contracts`](./data-aggregation-contracts): Contracts for aggregating and processing on-chain data in client code
