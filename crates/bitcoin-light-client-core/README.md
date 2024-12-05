# Bitcoin Light Client Core

Bitcoin light client that utilizes [Bitcoin Core](https://github.com/bitcoin/bitcoin) for all consensus validation and a [Merkle Mountain Range](https://github.com/opentimestamps/opentimestamps-server/blob/master/doc/merkle-mountain-range.md) to efficiently commit to an arbitrary amount headers with a single hash, with all state transitions validated in zero knowledge.

## Requirements
- [Rust](https://rustup.rs/)

## Tests
- If you didn't clone the repo with `git-lfs`, you'll need to download the headers [here](../../test-data/README.md)<br>

#### Run Tests
```
cargo test --release -- --include-ignored
```