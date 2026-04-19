mod cli;
mod git;
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
        Commands::Init { uninstall } => cmd_init(uninstall),
        Commands::Scan { path, staged, git_history, no_fail, include_low } => {
            cmd_scan(path, staged, git_history, no_fail, include_low)
        }
        Commands::Rules => cmd_rules(),
    }
}

fn cmd_init(uninstall: bool) {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let root = match git::find_git_root(&cwd) {
        Some(r) => r,
        None => {
            eprintln!("{} Not a git repository.", "error:".red().bold());
            process::exit(1);
        }
    };

    if uninstall {
        match git::uninstall_hook(&root) {
            Ok(_) => println!("{} Hook removed.", "secox:".cyan().bold()),
            Err(e) => { eprintln!("{} {e}", "error:".red().bold()); process::exit(1); }
        }
        return;
    }

    if git::uses_precommit_framework(&root) {
        println!("{}", "  Detected pre-commit framework (.pre-commit-config.yaml).".yellow());
        println!("  Add secox to your config:\n");
        println!("  {}", "  repos:\n    - repo: https://github.com/yourusername/secretoxide\n      rev: v0.1.0\n      hooks:\n        - id: secox".cyan());
        return;
    }

    match git::install_hook(&root) {
        Ok(_) => {
            println!(
                "\n  {} Pre-commit hook installed at {}",
                "✓".green().bold(),
                root.join(".git/hooks/pre-commit").display().to_string().cyan()
            );
            println!("    secox will now scan staged files before every commit.\n");
        }
        Err(e) => { eprintln!("{} Failed to install hook: {e}", "error:".red().bold()); process::exit(1); }
    }
}

fn cmd_scan(path: PathBuf, staged: bool, git_history: bool, no_fail: bool, include_low: bool) {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let repo_root = git::find_git_root(&cwd).unwrap_or_else(|| cwd.clone());

    let mode = if staged { "scanning staged files" }
               else if git_history { "scanning git history" }
               else { "scanning directory" };
    print_banner(mode);

    let mut findings = match if staged {
        scanner::scan_staged(&repo_root)
    } else if git_history {
        git::scan_history(&repo_root)
    } else {
        scanner::scan_directory(&path)
    } {
        Ok(f) => f,
        Err(e) => {
            eprintln!("{} {e}", "error:".red().bold());
            process::exit(2);
        }
    };

    if !include_low {
        findings.retain(|f| f.confidence != Confidence::Low);
    }
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
