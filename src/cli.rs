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
    /// Install the secox pre-commit hook.
    ///
    /// By default installs into the current repository's .git/hooks/pre-commit.
    /// Use --global to install once for all repositories via core.hooksPath.
    Init {
        /// Remove the secox hook instead of installing it.
        #[arg(long)]
        uninstall: bool,

        /// Install (or uninstall) the hook globally for all git repositories
        /// via `git config --global core.hooksPath`.
        ///
        /// Note: incompatible with the pre-commit framework — if your project
        /// uses .pre-commit-config.yaml, add secox there instead.
        #[arg(long)]
        global: bool,
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

        /// Extra paths or glob patterns to ignore, in addition to .secoxignore.
        /// Accepts the same syntax as .secoxignore: plain names ("tests"),
        /// rooted paths ("/vendor"), wildcards ("*.snap"), or "**/" prefixes.
        #[arg(long, value_name = "PATTERN")]
        ignore: Vec<String>,
    },

    /// Interactively review each finding and mark false positives as allowed.
    ///
    /// For each finding secox asks "Allow? [y/N]". Pressing y injects a
    /// language-appropriate  secox:allow  comment onto that line so future
    /// scans skip it. Pressing n (or Enter) leaves the finding in place.
    Resolve {
        /// Resolve findings in staged files only (default: scan staged files).
        #[arg(long, default_value_t = true)]
        staged: bool,
    },

    /// List all built-in detection rules.
    Rules {
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        format: OutputFormat,
    },
}
