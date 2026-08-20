use std::process::ExitCode;

fn main() -> ExitCode {
    xtask::quality::cli::run(std::env::args().skip(1).collect())
}
