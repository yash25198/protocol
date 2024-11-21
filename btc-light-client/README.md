# Bitcoin Light Client 

Bitcoin light client that utilizes [Bitcoin Core](https://github.com/bitcoin/bitcoin) for all consensus validation and a [Merkle Mountain Range](https://github.com/opentimestamps/opentimestamps-server/blob/master/doc/merkle-mountain-range.md) to efficiently commit to an arbitrary amount headers with a single hash, with all state transitions validated in SP1.

## Requirements
- [Rust](https://rustup.rs/)
- [SP1](https://docs.succinct.xyz/getting-started/install.html)

## Tests
- If you didn't clone the repo with `git-lfs`, you'll need to download the headers [here](../test-data/README.md)<br>

#### Run Core Tests
```
cargo test -p btc-light-client-core --release -- --include-ignored
```

## SP1 Utilities 

### Build the Program

To build the program, run the following command:

```sh
cd program
cargo prove build
```

### Execute the Program

To run the program without generating a proof:

```sh
cd script
cargo run --release -- --execute
```

This will execute the program and display the output.

### Retrieve the Verification Key

```sh
cargo prove vkey --elf elf/riscv32im-succinct-zkvm-elf
```

