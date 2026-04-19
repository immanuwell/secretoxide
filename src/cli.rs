use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::types::OutputFormat;

#[derive(Parser)]
#[command(
    name = "secox",
    version,
    about = "Zero-setup secret scanner for your codebase",
    long_about = "secox detects API keys, tokens, passwords, and other credentials\nin source code, git diffs, and git history.\n\nQuick start:\n  secox init          # install pre-commit hook\n  secox scan          # scan current directory\n  secox scan --staged # scan only staged files"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Install the secox pre-commit hook in the current git repository.
    Init {
        /// Remove the secox hook instead of installing it.
        #[arg(long)]
        uninstall: bool,
    },

    /// Scan for secrets in files or git history.
    Scan {
        /// Directory to scan (defaults to current directory).
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Scan only files currently staged for commit.
        #[arg(long)]
        staged: bool,

        /// Scan the entire git commit history (can be slow on large repos).
        #[arg(long, conflicts_with = "staged")]
        git_history: bool,

        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        format: OutputFormat,

        /// Exit 0 even when secrets are found (useful in advisory CI mode).
        #[arg(long)]
        no_fail: bool,

        /// Include low-confidence findings (more noise, fewer missed secrets).
        #[arg(long)]
        include_low: bool,
    },

    /// List all built-in detection rules.
    Rules {
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        format: OutputFormat,
    },
}
