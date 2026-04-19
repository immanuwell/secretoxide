use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};

use secox_lib::{ignore::SecoxIgnore, types::Finding};

// ── git repo helpers ──────────────────────────────────────────────────────────

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

/// Returns the globally configured core.hooksPath, if any.
pub fn global_core_hooks_path() -> Option<PathBuf> {
    let out = Command::new("git")
        .args(["config", "--global", "core.hooksPath"])
        .output()
        .ok()?;
    if out.status.success() {
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !s.is_empty() {
            return Some(expand_tilde(&s));
        }
    }
    None
}

fn home_dir() -> Option<PathBuf> {
    std::env::var("HOME").ok().map(PathBuf::from)
}

fn expand_tilde(s: &str) -> PathBuf {
    if s == "~" || s.starts_with("~/") {
        let home = std::env::var("HOME").unwrap_or_default();
        PathBuf::from(s.replacen('~', &home, 1))
    } else {
        PathBuf::from(s)
    }
}

// ── shared hook script ────────────────────────────────────────────────────────

const HOOK_MARKER: &str = "# secox-managed";

const HOOK_SCRIPT: &str = r#"# secox-managed — secret scanner pre-commit hook
# To bypass (not recommended): git commit --no-verify

if command -v secox >/dev/null 2>&1; then
    secox scan --staged
    status=$?
    if [ $status -ne 0 ]; then
        echo ""
        echo "secox: commit blocked — secret(s) detected in staged files."
        echo ""
        echo "  To triage interactively (allow false positives with one keypress):"
        echo "    secox resolve"
        echo ""
        echo "  To suppress a single line, append a comment:"
        echo "    # secox:allow   (Python / YAML / shell)"
        echo "    // secox:allow  (JS / Go / Java / Rust ...)"
        echo ""
        echo "  To skip this check entirely (NOT recommended):"
        echo "    git commit --no-verify"
        exit 1
    fi
else
    echo "secox: not found in PATH — skipping secret scan."
    echo "       Install: cargo install secox"
fi
"#;

// ── low-level hook file helpers ───────────────────────────────────────────────

fn write_hook(hook: &Path) -> Result<()> {
    std::fs::create_dir_all(hook.parent().unwrap())?;

    let content = if hook.exists() {
        let existing = std::fs::read_to_string(hook)?;
        if existing.contains(HOOK_MARKER) {
            return Ok(()); // already installed, nothing to do
        }
        format!("{existing}\n{HOOK_SCRIPT}")
    } else {
        format!("#!/bin/sh\n{HOOK_SCRIPT}")
    };

    std::fs::write(hook, content)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(hook)?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(hook, perms)?;
    }

    Ok(())
}

/// Returns `true` if the secox block was present and removed, `false` if it
/// was not installed by secox (file is left untouched in that case).
fn remove_hook(hook: &Path) -> Result<bool> {
    if !hook.exists() {
        return Ok(false);
    }

    let content = std::fs::read_to_string(hook)?;
    if !content.contains(HOOK_MARKER) {
        return Ok(false);
    }

    // Cut everything from the marker to the end of the secox block.
    let stripped = match content.find(HOOK_MARKER) {
        Some(idx) => content[..idx].to_string(),
        None => return Ok(false),
    };

    if stripped.trim().is_empty() || stripped.trim() == "#!/bin/sh" {
        std::fs::remove_file(hook)?;
    } else {
        std::fs::write(hook, stripped.trim_end().to_string() + "\n")?;
    }

    Ok(true)
}

// ── per-repo installation ─────────────────────────────────────────────────────

pub fn install_hook(repo_root: &Path) -> Result<()> {
    let hook = repo_root.join(".git").join("hooks").join("pre-commit");
    write_hook(&hook)
}

pub fn uninstall_hook(repo_root: &Path) -> Result<bool> {
    let hook = repo_root.join(".git").join("hooks").join("pre-commit");
    remove_hook(&hook)
}

// ── global installation ───────────────────────────────────────────────────────

/// Default directory used when no core.hooksPath is already configured.
pub fn default_global_hooks_dir() -> Option<PathBuf> {
    home_dir().map(|h| h.join(".git-hooks"))
}

pub fn install_global_hook() -> Result<PathBuf> {
    // Reuse existing core.hooksPath if already configured; otherwise set it.
    let hooks_dir = if let Some(existing) = global_core_hooks_path() {
        existing
    } else {
        let dir = default_global_hooks_dir()
            .context("cannot determine home directory")?;
        Command::new("git")
            .args(["config", "--global", "core.hooksPath", &dir.to_string_lossy()])
            .output()
            .context("failed to run git config")?;
        dir
    };

    std::fs::create_dir_all(&hooks_dir)?;
    let hook = hooks_dir.join("pre-commit");
    write_hook(&hook)?;
    Ok(hooks_dir)
}

pub fn uninstall_global_hook() -> Result<bool> {
    let hooks_dir = global_core_hooks_path().ok_or_else(|| {
        anyhow::anyhow!(
            "git config --global core.hooksPath is not set; no global hook to remove.\n\
             To remove a per-repo hook run: secox init --uninstall --local"
        )
    })?;

    let hook = hooks_dir.join("pre-commit");
    let removed = remove_hook(&hook)?;

    // If the hooks dir is now empty and was the one secox created, unset the
    // global config so we leave the system in a clean state.
    if removed {
        let is_default = default_global_hooks_dir()
            .map(|d| d == hooks_dir)
            .unwrap_or(false);
        if is_default {
            let empty = std::fs::read_dir(&hooks_dir)
                .map(|mut d| d.next().is_none())
                .unwrap_or(false);
            if empty {
                let _ = Command::new("git")
                    .args(["config", "--global", "--unset", "core.hooksPath"])
                    .output();
                let _ = std::fs::remove_dir(&hooks_dir);
            }
        }
    }

    Ok(removed)
}

// ── git history scanning ──────────────────────────────────────────────────────

pub fn scan_history(repo_root: &Path, ignore: &SecoxIgnore) -> Result<Vec<Finding>> {
    use anyhow::Context as _;

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
            .args(["diff-tree", "--root", "--no-commit-id", "-r", "-p", hash])
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
                    flush_diff_block(file, repo_root, &added_lines, hash, msg, ignore, &mut findings);
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
            flush_diff_block(file, repo_root, &added_lines, hash, msg, ignore, &mut findings);
        }
    }

    eprintln!();
    Ok(findings)
}

fn flush_diff_block(
    file: &Path,
    repo_root: &Path,
    added_lines: &[(usize, String)],
    hash: &str,
    msg: &str,
    ignore: &SecoxIgnore,
    findings: &mut Vec<secox_lib::types::Finding>,
) {
    use secox_lib::scanner::scan_content;

    if ignore.is_ignored(file, repo_root) {
        return;
    }
    let content = added_lines.iter().map(|(_, l)| l.as_str()).collect::<Vec<_>>().join("\n");
    let mut ff = scan_content(&content, file, Some(hash), Some(msg));
    for f in &mut ff {
        if let Some((orig, _)) = added_lines.get(f.line_number.saturating_sub(1)) {
            f.line_number = *orig;
        }
    }
    findings.append(&mut ff);
}
