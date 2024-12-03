# Rift Protocol Monorepo
All the components that secure Rift

- [`btc-light-client/`](./btc-light-client/): Circuits validating Bitcoin Proof of Work and longest chain
- [`circuits/`](./circuits): Circuits validating Bitcoin<>Ethereum order settlement
- [`contracts/`](./contracts): Solidity smart contracts for the Rift Exchange
- [`hypernode/`](./hypernode): Bitcoin and Ethereum indexer with hooks to trigger proof generation 
- [`e2e-tests/`](./e2e-tests): End-to-end testing suite for the entire system 
- [`data-aggregation-contracts/`](./data-aggregation-contracts): Contracts for aggregating and processing on-chain data in client code
