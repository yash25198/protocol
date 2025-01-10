test-contracts:
	cargo build --release --bin test-utils
	cd contracts && forge test

test-crates:
	cargo test --release --workspace --exclude rift-program
