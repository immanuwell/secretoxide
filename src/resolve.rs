use std::io::{self, Write};
use std::path::Path;

use anyhow::Result;
use colored::Colorize;

use secox_lib::{ignore::SecoxIgnore, scanner, types::Finding};

use crate::rotation;

pub fn run(repo_root: &Path, ignore: &SecoxIgnore, staged: bool) -> Result<()> {
    let mut findings = if staged {
        scanner::scan_staged(repo_root, ignore)?
    } else {
        scanner::scan_directory(repo_root, ignore, repo_root)?
    };

    // Deduplicate: if the same line triggered multiple rules, prompt once.
    findings.sort_by(|a, b| a.file.cmp(&b.file).then(a.line_number.cmp(&b.line_number)));
    findings.dedup_by(|a, b| a.file == b.file && a.line_number == b.line_number);

    if findings.is_empty() {
        println!("\n  {} No findings to resolve.\n", "✓".green().bold());
        return Ok(());
    }

    println!(
        "\n  {} {} finding(s) to review.\n",
        "secox:".cyan().bold(),
        findings.len().to_string().yellow().bold(),
    );

    let mut rotated = 0usize;
    let mut allowed = 0usize;
    let mut blocking = 0usize;

    for finding in &findings {
        print_finding(finding);

        match prompt_action()? {
            Action::Rotate => {
                show_rotation_guide(finding);
                rotated += 1;
            }
            Action::Allow => {
                inject_allow(&finding.file, finding.line_number)?;
                println!(
                    "  {} Marked as allowed — secox:allow added to line {}.\n",
                    "✓".green(),
                    finding.line_number
                );
                allowed += 1;
            }
            Action::Skip => {
                println!("  {} Skipped — still blocking.\n", "–".dimmed());
                blocking += 1;
            }
        }
    }

    println!("{}", "─".repeat(60).dimmed());
    if rotated > 0 {
        println!("  Rotating: {}", rotated.to_string().cyan().bold());
    }
    if allowed > 0 {
        println!("  Allowed:  {}", allowed.to_string().green().bold());
    }
    if blocking > 0 {
        println!("  Blocking: {}", blocking.to_string().yellow().bold());
        println!(
            "\n  Rotate or allow the remaining finding(s), then run {}.\n",
            "git commit".cyan()
        );
    } else {
        println!("\n  All findings resolved — your commit should go through.\n");
    }

    Ok(())
}

// ── actions ───────────────────────────────────────────────────────────────────

enum Action {
    Rotate,
    Allow,
    Skip,
}

fn show_rotation_guide(finding: &Finding) {
    match rotation::guide_for(finding.rule_id) {
        Some(guide) => rotation::print_guide(guide),
        None => {
            println!(
                "\n  {} No specific rotation guide for '{}' — check your provider's security settings.\n",
                "!".yellow(),
                finding.rule_id
            );
        }
    }
}

// ── prompt helpers ────────────────────────────────────────────────────────────

fn print_finding(f: &Finding) {
    let conf = match f.confidence {
        secox_lib::types::Confidence::High => " HIGH ".on_red().white().bold(),
        secox_lib::types::Confidence::Medium => " MED  ".on_yellow().black().bold(),
        secox_lib::types::Confidence::Low => " LOW  ".on_bright_black().white(),
    };
    println!("  {} {} {}", conf, f.rule_name.bold(), format!("({})", f.rule_id).dimmed());
    println!(
        "     {} {}",
        "File:".dimmed(),
        format!("{}:{}", f.file.display(), f.line_number).cyan()
    );
    println!("     {} {}", "Secret:".dimmed(), f.secret_preview.yellow());
    let line_display = if f.line.len() > 100 {
        format!("{}…", &f.line[..100])
    } else {
        f.line.clone()
    };
    println!("     {} {}", "Line:".dimmed(), line_display.dimmed());
}

fn prompt_action() -> Result<Action> {
    loop {
        print!(
            "\n  [{}]otate  [{}]llow false positive  [{}]kip  ",
            "r".cyan().bold(),
            "a".green().bold(),
            "s".dimmed(),
        );
        io::stdout().flush()?;

        let mut buf = String::new();
        io::stdin().read_line(&mut buf)?;
        match buf.trim().to_lowercase().as_str() {
            "r" | "rotate" => return Ok(Action::Rotate),
            "a" | "allow" => return Ok(Action::Allow),
            "s" | "skip" | "" => return Ok(Action::Skip),
            _ => println!("  Please enter r, a, or s."),
        }
    }
}

fn inject_allow(path: &Path, line_number: usize) -> Result<()> {
    let content = std::fs::read_to_string(path)?;
    let mut lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();

    if line_number == 0 || line_number > lines.len() {
        return Ok(());
    }

    let marker = allow_comment(path);
    let idx = line_number - 1;

    if lines[idx].contains("secox:allow") {
        return Ok(());
    }
    lines[idx] = format!("{}  {}", lines[idx], marker);

    let trailing_newline = content.ends_with('\n');
    let mut out = lines.join("\n");
    if trailing_newline {
        out.push('\n');
    }
    std::fs::write(path, out)?;
    Ok(())
}

fn allow_comment(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some(
            "js" | "ts" | "jsx" | "tsx" | "java" | "go" | "rs" | "c" | "cpp" | "cc" | "h"
            | "hpp" | "cs" | "swift" | "kt" | "dart" | "scala" | "php" | "groovy" | "gradle",
        ) => "// secox:allow",
        Some("lua") | Some("sql") | Some("hs") => "-- secox:allow",
        Some("html") | Some("xml") | Some("vue") | Some("svelte") | Some("htm") => {
            "<!-- secox:allow -->"
        }
        _ => "# secox:allow",
    }
}
