use std::path::{Path, PathBuf};

use anyhow::Result;

use secox_lib::{ignore::SecoxIgnore, types::Finding};

pub fn find_git_root(start: &Path) -> Option<PathBuf> {
    let mut dir = start.to_path_buf();
    loop {
        if dir.join(".git").is_dir() {
            return Some(dir);
        }
        if !dir.pop() {
            return None;
        }
    }
}

pub fn uses_precommit_framework(repo_root: &Path) -> bool {
    repo_root.join(".pre-commit-config.yaml").exists()
        || repo_root.join(".pre-commit-config.yml").exists()
}

pub fn hook_path(repo_root: &Path) -> PathBuf {
    repo_root.join(".git").join("hooks").join("pre-commit")
}

const HOOK_MARKER: &str = "# secox-managed";

const HOOK_SCRIPT: &str = r#"# secox-managed — secret scanner pre-commit hook
# To bypass (not recommended): git commit --no-verify

if command -v secox >/dev/null 2>&1; then
    secox scan --staged
    status=$?
    if [ $status -ne 0 ]; then
        echo ""
        echo "secox: commit blocked. Fix the above findings before committing."
        echo "       To suppress a false positive, add  # secox:ignore  to that line."
        echo "       To skip this check (NOT recommended): git commit --no-verify"
        exit 1
    fi
else
    echo "secox: not found in PATH — skipping secret scan."
    echo "       Install: cargo install secox"
fi
"#;

pub fn install_hook(repo_root: &Path) -> Result<()> {
    let hook = hook_path(repo_root);

    if hook.exists() {
        let existing = std::fs::read_to_string(&hook)?;
        if existing.contains(HOOK_MARKER) {
            println!("secox: pre-commit hook already installed.");
            return Ok(());
        }
        let appended = format!("{existing}\n{HOOK_SCRIPT}");
        std::fs::write(&hook, appended)?;
    } else {
        std::fs::create_dir_all(hook.parent().unwrap())?;
        std::fs::write(&hook, format!("#!/bin/sh\n{HOOK_SCRIPT}"))?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&hook)?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&hook, perms)?;
    }

    Ok(())
}

pub fn uninstall_hook(repo_root: &Path) -> Result<()> {
    let hook = hook_path(repo_root);
    if !hook.exists() {
        println!("secox: no hook found.");
        return Ok(());
    }

    let content = std::fs::read_to_string(&hook)?;
    if !content.contains(HOOK_MARKER) {
        println!("secox: hook was not installed by secox, leaving untouched.");
        return Ok(());
    }

    let stripped = if let Some(idx) = content.find(&format!("# {HOOK_MARKER}")) {
        content[..idx].to_string()
    } else {
        content
    };

    if stripped.trim().is_empty() || stripped.trim() == "#!/bin/sh" {
        std::fs::remove_file(&hook)?;
    } else {
        std::fs::write(&hook, stripped)?;
    }

    Ok(())
}

pub fn scan_history(repo_root: &Path, ignore: &SecoxIgnore) -> Result<Vec<Finding>> {
    use std::process::Command;

    use anyhow::Context;

    use crate::scanner::scan_content;

    let log = Command::new("git")
        .args(["log", "--all", "--format=%H%x09%s", "--reverse"])
        .current_dir(repo_root)
        .output()
        .context("failed to run git log")?;

    if !log.status.success() {
        anyhow::bail!("git log failed: {}", String::from_utf8_lossy(&log.stderr));
    }

    let commits: Vec<(String, String)> = String::from_utf8_lossy(&log.stdout)
        .lines()
        .filter(|l| !l.is_empty())
        .filter_map(|line| {
            let mut parts = line.splitn(2, '\t');
            let hash = parts.next()?.trim().to_string();
            let msg = parts.next().unwrap_or("").trim().to_string();
            Some((hash, msg))
        })
        .collect();

    let total = commits.len();
    let mut findings = Vec::new();

    for (i, (hash, msg)) in commits.iter().enumerate() {
        eprint!("\r  Scanning commit {}/{total} {}...", i + 1, &hash[..8]);

        let diff = match Command::new("git")
            .args(["diff-tree", "--no-commit-id", "-r", "-p", hash])
            .current_dir(repo_root)
            .output()
        {
            Ok(d) => d,
            Err(_) => continue,
        };

        let patch = String::from_utf8_lossy(&diff.stdout);
        let mut current_file: Option<PathBuf> = None;
        let mut added_lines: Vec<(usize, String)> = Vec::new();
        let mut hunk_line: usize = 1;

        for line in patch.lines() {
            if line.starts_with("+++ b/") {
                if let Some(file) = &current_file {
                    if !ignore.is_ignored(file, repo_root) {
                        let content = added_lines.iter().map(|(_, l)| l.as_str()).collect::<Vec<_>>().join("\n");
                        let mut ff = scan_content(&content, file, Some(hash), Some(msg));
                        for f in &mut ff {
                            if let Some((orig, _)) = added_lines.get(f.line_number.saturating_sub(1)) {
                                f.line_number = *orig;
                            }
                        }
                        findings.append(&mut ff);
                    }
                }
                current_file = Some(repo_root.join(&line[6..]));
                added_lines = Vec::new();
                hunk_line = 1;
            } else if line.starts_with("@@ ") {
                if let Some(s) = line.split('+').nth(1) {
                    hunk_line = s.split(&[',', ' ']).next().and_then(|n| n.parse().ok()).unwrap_or(1);
                }
            } else if line.starts_with('+') && !line.starts_with("+++") {
                added_lines.push((hunk_line, line[1..].to_string()));
                hunk_line += 1;
            } else if !line.starts_with('-') {
                hunk_line += 1;
            }
        }

        if let Some(file) = &current_file {
            if !ignore.is_ignored(file, repo_root) {
                let content = added_lines.iter().map(|(_, l)| l.as_str()).collect::<Vec<_>>().join("\n");
                let mut ff = scan_content(&content, file, Some(hash), Some(msg));
                for f in &mut ff {
                    if let Some((orig, _)) = added_lines.get(f.line_number.saturating_sub(1)) {
                        f.line_number = *orig;
                    }
                }
                findings.append(&mut ff);
            }
        }
    }

    eprintln!();
    Ok(findings)
}
