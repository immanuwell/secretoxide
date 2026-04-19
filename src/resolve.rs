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
                offer_env_var_replacement(finding)?;
                check_git_history(finding, repo_root)?;
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

// ── env var replacement ───────────────────────────────────────────────────────

fn offer_env_var_replacement(finding: &Finding) -> Result<()> {
    if finding.secret_raw.is_empty() {
        return Ok(());
    }

    // Inside an env file the right fix is to stop tracking the file, not to
    // replace the value with a reference to itself.
    let file_name = finding
        .file
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    if file_name.starts_with(".env") {
        println!(
            "  {} This secret is in {}. Stop tracking it and add it to .gitignore:\n\
             \n  {}\n  {}\n",
            "hint:".yellow().bold(),
            file_name.cyan(),
            format!("echo '{}' >> .gitignore", file_name).cyan(),
            format!("git rm --cached {}", file_name).cyan(),
        );
        return Ok(());
    }

    let hint = rotation::guide_for(finding.rule_id)
        .map(|g| g.env_var_hint)
        .unwrap_or("SECRET");

    print!(
        "  Replace hardcoded value with env var? [y/N] (suggested: {}) ",
        hint.cyan()
    );
    io::stdout().flush()?;

    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    if !matches!(answer.trim().to_lowercase().as_str(), "y" | "yes") {
        return Ok(());
    }

    print!("  Env var name [{}]: ", hint.cyan());
    io::stdout().flush()?;
    let mut var_name_input = String::new();
    io::stdin().read_line(&mut var_name_input)?;
    let var_name = var_name_input.trim();
    let var_name = if var_name.is_empty() { hint } else { var_name };

    let reference = env_var_reference(&finding.file, var_name);

    match replace_in_file(&finding.file, &finding.secret_raw, &reference) {
        Ok(true) => {
            println!(
                "  {} Replaced with {}\n  {} Add to your secrets manager or .env file:\n  {}\n",
                "✓".green(),
                reference.cyan(),
                "hint:".dimmed(),
                format!("{}=<your-value>", var_name).dimmed(),
            );
        }
        Ok(false) => {
            println!(
                "  {} Could not find the exact secret value in the file — edit manually.\n",
                "!".yellow()
            );
        }
        Err(e) => {
            println!("  {} Failed to modify file: {}\n", "!".red(), e);
        }
    }

    Ok(())
}

fn env_var_reference(path: &Path, var_name: &str) -> String {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    match ext {
        "py" => format!(r#"os.environ["{}"]"#, var_name),
        "js" | "ts" | "jsx" | "tsx" | "mjs" | "cjs" => {
            format!("process.env.{}", var_name)
        }
        "go" => format!(r#"os.Getenv("{}")"#, var_name),
        "rb" => format!(r#"ENV["{}"]"#, var_name),
        "java" | "kt" | "scala" | "groovy" => {
            format!(r#"System.getenv("{}")"#, var_name)
        }
        "rs" => format!(
            r#"std::env::var("{}").expect("{} not set")"#,
            var_name, var_name
        ),
        "php" => format!(r#"$_ENV["{}"]"#, var_name),
        "cs" => format!(r#"Environment.GetEnvironmentVariable("{}")"#, var_name),
        _ => format!("${{{}}}", var_name),
    }
}

fn replace_in_file(path: &Path, secret: &str, replacement: &str) -> Result<bool> {
    let content = std::fs::read_to_string(path)?;
    if !content.contains(secret) {
        return Ok(false);
    }
    let new_content = content.replacen(secret, replacement, 1);
    std::fs::write(path, new_content)?;
    Ok(true)
}

// ── git history check ─────────────────────────────────────────────────────────

fn check_git_history(finding: &Finding, repo_root: &Path) -> Result<()> {
    use std::process::Command;

    if finding.secret_raw.is_empty() {
        return Ok(());
    }

    // git log -S searches for commits that introduced or removed this exact string
    let output = Command::new("git")
        .args(["log", "--all", "--oneline", "-S", &finding.secret_raw])
        .current_dir(repo_root)
        .output();

    let output = match output {
        Ok(o) if o.status.success() => o,
        _ => return Ok(()), // git not available, not a repo, or no history
    };

    let commits: Vec<&str> = std::str::from_utf8(&output.stdout)
        .unwrap_or("")
        .lines()
        .filter(|l| !l.is_empty())
        .collect();

    if commits.is_empty() {
        println!(
            "  {} Secret not found in git history — only present in working tree.\n",
            "✓".green()
        );
        return Ok(());
    }

    println!(
        "  {} Secret found in {} commit(s) in git history:\n",
        "!".red().bold(),
        commits.len().to_string().red().bold(),
    );
    for c in &commits {
        println!("      {}", c.dimmed());
    }

    // Escape the secret for use in a shell heredoc / printf
    let escaped = finding.secret_raw.replace('\'', "'\\''");

    println!("\n  Rewrite history to remove the secret (requires git-filter-repo):\n");
    println!(
        "  {}",
        format!("printf '{}==><REVOKED>\\n' > /tmp/replacements.txt", escaped).cyan()
    );
    println!(
        "  {}",
        "git filter-repo --replace-text /tmp/replacements.txt --force".cyan()
    );
    println!(
        "  {}  {}",
        "git push --force-with-lease".cyan(),
        "# coordinate with your team first".dimmed(),
    );
    println!(
        "\n  Install git-filter-repo: {}  or  {}\n",
        "pip install git-filter-repo".dimmed(),
        "brew install git-filter-repo".dimmed(),
    );

    Ok(())
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
