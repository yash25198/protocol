use sp1_helper::build_program_with_args;
use sp1_helper::BuildArgs;

fn main() {
    let args = BuildArgs {
        docker: false,
        ..Default::default()
    };
    build_program_with_args("../../crates/rift-program", args);
}
