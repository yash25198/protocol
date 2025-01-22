sync:
	cd contracts && forge build  && ./sync-artifacts.sh
	cargo build --release

test-contracts: | sync
	cd contracts && forge test

test-crates: | sync
	cargo test --release --workspace --exclude rift-program

test: | sync test-contracts test-crates