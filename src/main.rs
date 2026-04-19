mod cli;
mod output;
mod rules;
mod scanner;
mod types;

use std::path::PathBuf;
use std::process;

use clap::Parser;
use colored::Colorize;

use cli::{Cli, Commands};
use output::{print_banner, print_findings_text, print_summary};
use types::Confidence;

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Init { uninstall: _ } => {
            println!("secox init — not yet implemented");
        }
        Commands::Scan { path, staged: _, no_fail } => cmd_scan(path, no_fail),
        Commands::Rules => cmd_rules(),
    }
}

fn cmd_scan(path: PathBuf, no_fail: bool) {
    print_banner("scanning directory");

    let mut findings = match scanner::scan_directory(&path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("{} {e}", "error:".red().bold());
            process::exit(2);
        }
    };

    findings.retain(|f| f.confidence != Confidence::Low);
    findings.sort_by(|a, b| {
        a.confidence.cmp(&b.confidence)
            .then(a.file.cmp(&b.file))
            .then(a.line_number.cmp(&b.line_number))
    });
    findings.dedup_by(|a, b| {
        a.rule_id == b.rule_id && a.file == b.file && a.line_number == b.line_number
    });

    print_findings_text(&findings);
    print_summary(&findings);

    if !findings.is_empty() && !no_fail {
        process::exit(1);
    }
}

fn cmd_rules() {
    use rules::RULES;
    println!("\n  {} Built-in detection rules:\n", "secox".cyan().bold());
    for r in RULES.iter() {
        println!(
            "  {} {}  {}",
            r.meta.confidence.label().bold(),
            r.meta.id.cyan(),
            r.meta.name.dimmed(),
        );
    }
    println!("\n  {} rules total.\n", RULES.len().to_string().bold());
}
