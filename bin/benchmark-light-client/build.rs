use sp1_helper::build_program_with_args;

fn main() {
    build_program_with_args(
        "../../crates/bitcoin-light-client-program",
        Default::default(),
    )
}
