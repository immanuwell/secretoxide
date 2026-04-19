use std::io::{self, Write};
use std::path::Path;

use anyhow::Result;
use colored::Colorize;

use secox_lib::{ignore::SecoxIgnore, scanner, types::Finding};

pub fn run(repo_root: &Path, ignore: &SecoxIgnore, staged: bool) -> Result<()> {
    let findings = if staged {
        scanner::scan_staged(repo_root, ignore)?
    } else {
        scanner::scan_directory(repo_root, ignore, repo_root)?
    };

    if findings.is_empty() {
        println!("\n  {} No findings to resolve.\n", "✓".green().bold());
        return Ok(());
    }

    println!(
        "\n  {} {} finding(s) to review — {} to allow, {} or Enter to keep blocking.\n",
        "secox:".cyan().bold(),
        findings.len().to_string().yellow().bold(),
        "y".green().bold(),
        "n".red(),
    );

    let mut allowed = 0usize;
    let mut blocking = 0usize;

    for finding in &findings {
        print_finding(finding);
        if prompt_yes_no()? {
            inject_allow(&finding.file, finding.line_number)?;
            println!("  {} Allowed — secox:allow appended to line {}.\n", "✓".green(), finding.line_number);
            allowed += 1;
        } else {
            println!("  {} Skipped.\n", "–".dimmed());
            blocking += 1;
        }
    }

    println!("{}", "─".repeat(60).dimmed());
    println!(
        "  Allowed: {}   Still blocking: {}",
        allowed.to_string().green().bold(),
        blocking.to_string().yellow().bold(),
    );
    if blocking > 0 {
        println!(
            "\n  Fix or rotate the remaining secret(s), then run {}.\n",
            "git commit".cyan()
        );
    } else {
        println!("\n  All findings resolved — your commit should go through.\n");
    }

    Ok(())
}

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
    print!("  Allow this finding? [y/N] ");
    let _ = io::stdout().flush();
}

fn prompt_yes_no() -> Result<bool> {
    let mut buf = String::new();
    io::stdin().read_line(&mut buf)?;
    Ok(matches!(buf.trim().to_lowercase().as_str(), "y" | "yes"))
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
