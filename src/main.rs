//! The `rusp` binary.

#![forbid(unsafe_code)]

use std::process::ExitCode;

use clap::Parser;

use rusp::cli::Cli;

fn main() -> ExitCode {
    let cli = Cli::parse();
    match rusp::app::run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            rusp::ui::report_error(&err);
            if err.is_cancelled() {
                // Conventional exit status for "terminated by SIGINT".
                ExitCode::from(130)
            } else {
                ExitCode::FAILURE
            }
        }
    }
}
