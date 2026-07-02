//! RenpyEx CLI entry point.

use clap::Parser;
use renpyex::cli::Cli;

fn main() {
    let cli = Cli::parse();
    let result = cli.command.run();
    if let Err(err) = result {
        eprintln!("renpyex: {err}");
        std::process::exit(1);
    }
}
