use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::types::OutputFormat;

#[derive(Parser)]
#[command(
    name = "secox",
    version,
    about = "Zero-setup secret scanner for your codebase",
    long_about = "secox detects API keys, tokens, passwords, and other credentials\n\
                  in source code, git diffs, and git history.\n\
                  \n\
                  Quick start:\n  \
                    secox init          # install pre-commit hook\n  \
                    secox scan          # scan current directory\n  \
                    secox scan --staged # scan only staged files",
    after_long_help = "Examples:\n  \
      secox init                              install pre-commit hook for this repo\n  \
      secox init --global                     install once for all repos (core.hooksPath)\n  \
      secox scan                              scan the current directory\n  \
      secox scan --staged                     scan only what is staged right now\n  \
      secox scan --git-history                audit the full commit history\n  \
      secox scan --include-low                widen the net (more noise, fewer misses)\n  \
      secox scan --format json | jq .         pipe findings to jq\n  \
      secox scan --ignore \"*.snap\"            skip snapshot files\n  \
      secox scan --ignore vendor/             skip vendored dependencies\n  \
      secox resolve                           triage blocked-commit findings interactively\n  \
      secox rules                             list all built-in detection rules\n\
      \n\
      Suppress a single finding inline:\n  \
      api_key = \"sk-live-...\"  # secox:allow\n  \
      \n\
      Suppress all findings in a file — add to the top:\n  \
      # secox:allow-file"
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
    #[command(
        after_help = "Examples:\n  \
          secox init                    install hook in this repo\n  \
          secox init --global           install once for all repos via core.hooksPath\n  \
          secox init --uninstall        remove the hook from this repo\n  \
          secox init --global --uninstall  remove the global hook\n\
          \n\
          pre-commit framework users: add secox to .pre-commit-config.yaml instead."
    )]
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
    #[command(
        after_help = "Examples:\n  \
          secox scan                        scan everything in the current directory\n  \
          secox scan src/                   scan a specific subdirectory\n  \
          secox scan --staged               scan only files staged for the next commit\n  \
          secox scan --git-history          audit every commit ever (slow on large repos)\n  \
          secox scan --include-low          also show low-confidence env-file findings\n  \
          secox scan --no-fail              advisory mode: report but exit 0 (for CI)\n  \
          secox scan --format json          machine-readable output\n  \
          secox scan --format sarif         SARIF for GitHub Code Scanning / VS Code\n  \
          secox scan --ignore \"tests/\"      skip the tests directory\n  \
          secox scan --ignore \"*.fixture.ts\" skip fixture files by glob\n  \
          secox scan --ignore vendor/ --ignore \"*.snap\"\n\
          \n\
          Suppress inline (add to the end of the line with the secret):\n  \
          API_KEY = \"sk-...\"  # secox:allow\n\
          \n\
          Suppress entire file (add to the top of the file):\n  \
          # secox:allow-file\n\
          \n\
          Ignore patterns can also be committed to .secoxignore (one per line,\n  \
          same syntax as .gitignore)."
    )]
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

        /// Verify each finding against its provider's API (makes live network requests).
        /// Adds a ✓ verified / ✗ invalid status to each finding.
        /// Unsupported providers (AWS, Twilio, …) are left unverified.
        #[arg(long)]
        verify: bool,
    },

    /// Interactively triage findings: rotate real secrets, allow false positives.
    #[command(
        long_about = "Interactively triage findings: rotate real secrets, allow false positives.\n\
                      \n\
                      For each finding secox asks [r]otate / [a]llow / [s]kip:\n  \
                        r  shows provider-specific revocation URL + steps, offers to replace\n  \
                           the hardcoded value with an env var reference in the file, then\n  \
                           checks whether the secret appears in git history and emits the\n  \
                           exact git filter-repo command if it does.\n  \
                        a  injects a language-appropriate secox:allow pragma onto that line\n  \
                           so future scans skip it without affecting other findings.\n  \
                        s  leaves the finding in place (still blocking).",
        after_help = concat!(
            "Examples:\n",
            "  secox resolve              triage staged-file findings (run after a blocked commit)\n",
            "  secox resolve --no-staged  triage the whole working tree, not just staged files\n",
            "\n",
            "Typical workflow when a commit is blocked:\n",
            "  1. git commit     →  secox blocks it and prints the findings\n",
            "  2. secox resolve  →  for each finding choose r / a / s:\n",
            "       r  rotation guide, optional in-file env var swap, history check\n",
            "       a  secox:allow pragma added; that line is skipped on next scan\n",
            "       s  still blocking — revisit before retrying the commit\n",
            "  3. git commit     →  succeeds once all findings are rotated or allowed",
        )
    )]
    Resolve {
        /// Scan staged files only. Use --no-staged to scan the whole working tree.
        #[arg(long, default_value_t = true, action = clap::ArgAction::SetTrue, overrides_with = "no_staged")]
        staged: bool,

        /// Scan the whole working tree instead of only staged files.
        #[arg(long, action = clap::ArgAction::SetTrue, overrides_with = "staged")]
        no_staged: bool,
    },

    /// List all built-in detection rules.
    #[command(
        after_help = "Examples:\n  \
          secox rules                  pretty-print all rules with confidence levels\n  \
          secox rules --format json    machine-readable rule list for tooling / audits"
    )]
    Rules {
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        format: OutputFormat,
    },

    /// Manage the .secox-baseline.json file for legacy repos.
    ///
    /// The baseline lets you onboard an existing codebase without being overwhelmed
    /// by pre-existing findings. Once baselined, only NEW secrets block commits.
    #[command(
        after_help = concat!(
            "Examples:\n",
            "  secox baseline            snapshot all current findings into .secox-baseline.json\n",
            "  secox baseline --update   refresh the baseline after rotating old secrets\n",
            "\n",
            "Workflow for onboarding an existing repo:\n",
            "  1. secox baseline          create the initial baseline\n",
            "  2. git add .secox-baseline.json && git commit\n",
            "  3. secox scan              now only findings NOT in the baseline are shown\n",
            "  4. Work through old findings over time with `secox resolve`\n",
            "  5. secox baseline --update after each batch you clean up",
        )
    )]
    Baseline {
        /// Overwrite an existing baseline (default: refuse if one already exists).
        #[arg(long)]
        update: bool,
    },
}
