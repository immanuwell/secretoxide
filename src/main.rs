mod cli;

use clap::Parser;
use cli::{Cli, Commands};

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Init { uninstall: _ } => {
            println!("secox init — not yet implemented");
        }
        Commands::Scan { path: _, staged: _, no_fail: _ } => {
            println!("secox scan — not yet implemented");
        }
        Commands::Rules => {
            println!("secox rules — not yet implemented");
        }
    }
}
