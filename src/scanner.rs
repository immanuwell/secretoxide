use std::path::{Path, PathBuf};

use anyhow::Result;
use walkdir::WalkDir;

use crate::{
    rules::{redact, RULES},
    types::Finding,
};

const MAX_FILE_SIZE: u64 = 10 * 1024 * 1024;

const INLINE_IGNORE: &str = "secox:ignore";
const FILE_IGNORE: &str = "secox:ignore-file";

const SKIP_EXTENSIONS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "bmp", "ico", "svg", "webp",
    "mp3", "mp4", "wav", "ogg", "mov", "avi",
    "zip", "tar", "gz", "bz2", "xz", "7z", "rar",
    "pdf", "doc", "docx", "xls", "xlsx",
    "woff", "woff2", "ttf", "eot",
    "exe", "dll", "so", "dylib", "a",
    "pyc", "pyo", "class",
];

fn skip_by_extension(path: &Path) -> bool {
    let name = path.to_string_lossy().to_lowercase();
    SKIP_EXTENSIONS.iter().any(|ext| name.ends_with(&format!(".{ext}")))
}

fn is_binary(buf: &[u8]) -> bool {
    buf.iter().take(8192).any(|&b| b == 0)
}

pub fn scan_content(
    content: &str,
    path: &Path,
    commit: Option<&str>,
    commit_message: Option<&str>,
) -> Vec<Finding> {
    if content.contains(FILE_IGNORE) {
        return vec![];
    }

    let mut findings = Vec::new();

    for (line_idx, line) in content.lines().enumerate() {
        if line.contains(INLINE_IGNORE) {
            continue;
        }

        for rule in RULES.iter() {
            for caps in rule.regex.captures_iter(line) {
                let secret = if rule.meta.secret_group == 0 {
                    caps.get(0).map(|m| m.as_str()).unwrap_or("")
                } else {
                    caps.get(rule.meta.secret_group)
                        .or_else(|| caps.get(0))
                        .map(|m| m.as_str())
                        .unwrap_or("")
                };

                if secret.is_empty() {
                    continue;
                }

                findings.push(Finding {
                    rule_id: rule.meta.id,
                    rule_name: rule.meta.name,
                    confidence: rule.meta.confidence.clone(),
                    file: path.to_path_buf(),
                    line_number: line_idx + 1,
                    line: line.trim().to_string(),
                    secret_preview: redact(secret),
                    commit: commit.map(|s| s.to_string()),
                    commit_message: commit_message.map(|s| s.to_string()),
                });
            }
        }
    }

    findings
}

pub fn scan_file(path: &Path) -> Result<Vec<Finding>> {
    if skip_by_extension(path) {
        return Ok(vec![]);
    }

    let metadata = std::fs::metadata(path)?;
    if metadata.len() > MAX_FILE_SIZE {
        return Ok(vec![]);
    }

    let bytes = std::fs::read(path)?;
    if is_binary(&bytes) {
        return Ok(vec![]);
    }

    let content = String::from_utf8_lossy(&bytes);
    Ok(scan_content(&content, path, None, None))
}

pub fn scan_staged(repo_root: &Path) -> Result<Vec<Finding>> {
    use std::process::Command;

    let output = Command::new("git")
        .args(["diff", "--cached", "--name-only", "--diff-filter=ACM"])
        .current_dir(repo_root)
        .output()?;

    if !output.status.success() {
        anyhow::bail!("git diff failed: {}", String::from_utf8_lossy(&output.stderr));
    }

    let files: Vec<PathBuf> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| repo_root.join(l))
        .collect();

    let mut findings = Vec::new();
    for path in &files {
        if path.exists() {
            match scan_file(path) {
                Ok(mut f) => findings.append(&mut f),
                Err(_) => {}
            }
        }
    }

    Ok(findings)
}

fn is_lock_file(path: &Path) -> bool {
    let name = path.file_name().map(|n| n.to_string_lossy()).unwrap_or_default();
    matches!(
        name.as_ref(),
        "package-lock.json" | "yarn.lock" | "pnpm-lock.yaml"
            | "Cargo.lock" | "Gemfile.lock" | "poetry.lock"
            | "composer.lock" | "go.sum" | "Pipfile.lock"
    )
}

pub fn scan_directory(path: &Path) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    for entry in WalkDir::new(path)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let p = entry.path();

        if p.components().any(|c| c.as_os_str() == ".git") {
            continue;
        }

        if !p.is_file() {
            continue;
        }

        if is_lock_file(p) {
            continue;
        }

        match scan_file(p) {
            Ok(mut f) => findings.append(&mut f),
            Err(_) => {}
        }
    }

    Ok(findings)
}
