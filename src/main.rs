mod baseline;
mod cli;
mod git;
mod output;
mod resolve;
mod rotation;

use secox_lib::{ignore::SecoxIgnore, rules, scanner, types};

use std::path::PathBuf;
use std::process;

use clap::Parser;
use colored::Colorize;

use cli::{Cli, Commands};
use output::{print_banner, print_findings, print_summary};
use types::{Confidence, OutputFormat};

fn main() {
    // Reset SIGPIPE to default so we exit cleanly when output is piped to `head` etc.
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }

    let cli = Cli::parse();
    match cli.command {
        Commands::Init { uninstall, global } => cmd_init(uninstall, global),
        Commands::Scan { path, staged, git_history, format, no_fail, include_low, ignore } => {
            cmd_scan(path, staged, git_history, format, no_fail, include_low, ignore)
        }
        Commands::Resolve { staged, no_staged } => cmd_resolve(staged && !no_staged),
        Commands::Rules { format } => cmd_rules(format),
        Commands::Baseline { update } => cmd_baseline(update),
    }
}

fn cmd_init(uninstall: bool, global: bool) {
    if global {
        cmd_init_global(uninstall);
    } else {
        cmd_init_local(uninstall);
    }
}

fn cmd_init_local(uninstall: bool) {
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
            Ok(true)  => println!("{} Hook removed.", "secox:".cyan().bold()),
            Ok(false) => println!("{} No secox hook found — nothing to remove.", "secox:".cyan().bold()),
            Err(e)    => { eprintln!("{} {e}", "error:".red().bold()); process::exit(1); }
        }
        return;
    }

    if git::uses_precommit_framework(&root) {
        println!("{}", "  Detected pre-commit framework (.pre-commit-config.yaml).".yellow());
        println!("  Add secox to your config:\n");
        println!("  {}", "  repos:\n    - repo: https://github.com/yourusername/secretoxide\n      rev: v0.1.0\n      hooks:\n        - id: secox".cyan());
        return;
    }

    if git::global_core_hooks_path().is_some() {
        println!(
            "  {} global core.hooksPath is already set — the global hook will run for this repo.",
            "note:".yellow().bold()
        );
        println!("  Installing a per-repo hook as well (both will run).\n");
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

fn cmd_init_global(uninstall: bool) {
    if uninstall {
        match git::uninstall_global_hook() {
            Ok(true)  => println!("{} Global hook removed.", "secox:".cyan().bold()),
            Ok(false) => println!("{} No secox global hook found — nothing to remove.", "secox:".cyan().bold()),
            Err(e)    => { eprintln!("{} {e}", "error:".red().bold()); process::exit(1); }
        }
        return;
    }

    match git::install_global_hook() {
        Ok(dir) => {
            println!(
                "\n  {} Global pre-commit hook installed in {}",
                "✓".green().bold(),
                dir.display().to_string().cyan()
            );
            println!("    secox will now scan staged files before every commit in any repository.");
            println!("    git config --global core.hooksPath is set to {}\n", dir.display().to_string().cyan());
        }
        Err(e) => { eprintln!("{} Failed to install global hook: {e}", "error:".red().bold()); process::exit(1); }
    }
}

fn cmd_scan(
    path: PathBuf,
    staged: bool,
    git_history: bool,
    format: OutputFormat,
    no_fail: bool,
    include_low: bool,
    ignore_cli: Vec<String>,
) {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let repo_root = git::find_git_root(&cwd).unwrap_or_else(|| cwd.clone());
    let ignore = SecoxIgnore::load(&repo_root, &ignore_cli);

    if format == OutputFormat::Text {
        let mode = if staged { "scanning staged files" }
                   else if git_history { "scanning git history" }
                   else { "scanning directory" };
        print_banner(mode);
    }

    let mut findings = match if staged {
        scanner::scan_staged(&repo_root, &ignore)
    } else if git_history {
        git::scan_history(&repo_root, &ignore)
    } else {
        scanner::scan_directory(&path, &ignore, &repo_root)
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

    // Suppress findings that are already in the baseline.
    let suppressed_count = if let Some(bl) = baseline::Baseline::load(&repo_root) {
        let (kept, n) = bl.suppress(findings, &repo_root);
        findings = kept;
        n
    } else {
        0
    };

    print_findings(&findings, format);
    print_summary(&findings, format);

    if suppressed_count > 0 && format == OutputFormat::Text {
        println!(
            "  {} {} known finding(s) suppressed by baseline — run {} to refresh.\n",
            "ℹ".cyan(),
            suppressed_count,
            "secox baseline --update".cyan(),
        );
    }

    if !findings.is_empty() && !no_fail {
        process::exit(1);
    }
}

fn cmd_resolve(staged: bool) {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let repo_root = git::find_git_root(&cwd).unwrap_or_else(|| cwd.clone());
    let ignore = SecoxIgnore::load(&repo_root, &[]);

    if let Err(e) = resolve::run(&repo_root, &ignore, staged) {
        eprintln!("{} {e}", "error:".red().bold());
        process::exit(2);
    }
}

fn cmd_baseline(update: bool) {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let repo_root = git::find_git_root(&cwd).unwrap_or_else(|| cwd.clone());
    let ignore = SecoxIgnore::load(&repo_root, &[]);

    let baseline_path = baseline::baseline_path(&repo_root);

    if baseline_path.exists() && !update {
        eprintln!(
            "{} {} already exists. Use {} to overwrite it.",
            "error:".red().bold(),
            baseline_path.display().to_string().cyan(),
            "secox baseline --update".cyan(),
        );
        process::exit(1);
    }

    println!("\n  {} Scanning for current findings to baseline…\n", "secox:".cyan().bold());

    let findings = match scanner::scan_directory(&repo_root, &ignore, &repo_root) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("{} {e}", "error:".red().bold());
            process::exit(2);
        }
    };

    // Only baseline Medium and High — Low findings are too noisy to track.
    let findings: Vec<_> = findings
        .into_iter()
        .filter(|f| f.confidence != Confidence::Low)
        .collect();

    let count = findings.len();
    let entries = baseline::findings_to_entries(&findings, &repo_root);
    let bl = baseline::Baseline::new(entries);

    if let Err(e) = bl.save(&repo_root) {
        eprintln!("{} Failed to write baseline: {e}", "error:".red().bold());
        process::exit(2);
    }

    println!(
        "  {} Baselined {} finding(s) → {}\n",
        "✓".green().bold(),
        count.to_string().yellow().bold(),
        baseline_path.display().to_string().cyan(),
    );

    if count > 0 {
        println!(
            "  Commit {} to share the baseline with your team.\n  \
             Future {} runs will only show findings NOT in this baseline.\n",
            ".secox-baseline.json".cyan(),
            "secox scan".cyan(),
        );
    } else {
        println!("  Clean repo — baseline is empty. Nothing will be suppressed.\n");
    }
}

fn cmd_rules(format: OutputFormat) {
    use rules::RULES;
    use serde_json::json;

    match format {
        OutputFormat::Json => {
            let arr: Vec<_> = RULES
                .iter()
                .map(|r| json!({
                    "id": r.meta.id,
                    "name": r.meta.name,
                    "description": r.meta.description,
                    "confidence": match r.meta.confidence {
                        Confidence::High => "HIGH",
                        Confidence::Medium => "MEDIUM",
                        Confidence::Low => "LOW",
                    },
                }))
                .collect();
            println!("{}", serde_json::to_string_pretty(&arr).unwrap());
        }
        _ => {
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
    }
}
