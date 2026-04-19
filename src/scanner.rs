use std::path::{Path, PathBuf};

use anyhow::Result;
use walkdir::WalkDir;

use crate::{
    ignore::SecoxIgnore,
    rules::{bigram_humanness, char_class_diversity, entropy, is_env_reference, is_placeholder, is_test_path, looks_like_code_identifier, redact, RULES},
    types::{Confidence, Finding},
    validator::{aws_key_entropy_ok, validate_github_token, validate_jwt},
};

const MAX_FILE_SIZE: u64 = 10 * 1024 * 1024;

const INLINE_IGNORE: &str = "secox:ignore";
const INLINE_ALLOW: &str = "secox:allow";
const FILE_IGNORE: &str = "secox:ignore-file";
const FILE_ALLOW: &str = "secox:allow-file";

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

// ── Sensitive-filename detection ──────────────────────────────────────────────
//
// Some files are dangerous to commit regardless of their content — private keys,
// env files, credential configs, etc. We flag them by name so that even an empty
// or partially-filled file raises a warning before it reaches remote.

struct SensitiveFileRule {
    rule_id:   &'static str,
    rule_name: &'static str,
}

fn sensitive_file_rule(name: &str) -> Option<SensitiveFileRule> {
    // Exact names (lowercased comparison)
    const ENV_NAMES: &[&str] = &[
        ".env", ".env.local", ".env.development", ".env.staging",
        ".env.production", ".env.test", ".env.backup", ".env.example",
        ".envrc",
    ];
    const KEY_NAMES: &[&str] = &[
        "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
        "id_rsa.pub", "id_dsa.pub", "id_ecdsa.pub", "id_ed25519.pub",
    ];
    const CRED_NAMES: &[&str] = &[
        "credentials.json", "credentials.csv",
        "secrets.json", "secrets.yml", "secrets.yaml",
        "serviceaccountkey.json", "service_account.json", "service-account.json",
        ".netrc", ".htpasswd", "htpasswd",
        "terraform.tfvars", "terraform.tfvars.json",
        "wp-config.php",
    ];

    let lower = name.to_lowercase();

    if ENV_NAMES.contains(&lower.as_str()) || lower.starts_with(".env.") {
        return Some(SensitiveFileRule {
            rule_id:   "sensitive-file-env",
            rule_name: "Environment Secrets File",
        });
    }
    if KEY_NAMES.contains(&lower.as_str()) {
        return Some(SensitiveFileRule {
            rule_id:   "sensitive-file-key",
            rule_name: "SSH Private Key File",
        });
    }
    if CRED_NAMES.contains(&lower.as_str())
        || lower.ends_with("serviceaccountkey.json")
        || lower.ends_with("service_account.json")
    {
        return Some(SensitiveFileRule {
            rule_id:   "sensitive-file-credentials",
            rule_name: "Credential / Secrets Config File",
        });
    }

    // Extension-based rules
    match std::path::Path::new(name)
        .extension()
        .and_then(|e| e.to_str())
    {
        Some("pem") => return Some(SensitiveFileRule {
            rule_id:   "sensitive-file-key",
            rule_name: "PEM Certificate / Key File",
        }),
        Some("p12") | Some("pfx") => return Some(SensitiveFileRule {
            rule_id:   "sensitive-file-key",
            rule_name: "PKCS#12 Certificate File",
        }),
        Some("jks") | Some("keystore") => return Some(SensitiveFileRule {
            rule_id:   "sensitive-file-key",
            rule_name: "Java KeyStore File",
        }),
        Some("tfvars") => return Some(SensitiveFileRule {
            rule_id:   "sensitive-file-credentials",
            rule_name: "Terraform Variables File",
        }),
        _ => {}
    }

    None
}

fn check_sensitive_filename(
    path: &Path,
    commit: Option<&str>,
    commit_message: Option<&str>,
) -> Option<Finding> {
    let file_name = path.file_name()?.to_str()?;
    let rule = sensitive_file_rule(file_name)?;

    let display = file_name.to_string();
    Some(Finding {
        rule_id:        rule.rule_id,
        rule_name:      rule.rule_name,
        confidence:     Confidence::High,
        file:           path.to_path_buf(),
        line_number:    0,
        line:           display.clone(),
        secret_preview: display.clone(),
        secret_raw:     String::new(),
        commit:         commit.map(|s| s.to_string()),
        commit_message: commit_message.map(|s| s.to_string()),
    })
}

pub fn scan_content(
    content: &str,
    path: &Path,
    commit: Option<&str>,
    commit_message: Option<&str>,
) -> Vec<Finding> {
    if content.contains(FILE_IGNORE) || content.contains(FILE_ALLOW) {
        return vec![];
    }

    let in_test_file = is_test_path(path);
    let mut findings = Vec::new();

    // Filename-level check runs before content — flagged regardless of what's inside.
    if let Some(f) = check_sensitive_filename(path, commit, commit_message) {
        findings.push(f);
    }

    for (line_idx, line) in content.lines().enumerate() {
        if line.contains(INLINE_IGNORE) || line.contains(INLINE_ALLOW) {
            continue;
        }

        let line_has_env_ref = is_env_reference(line);

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

                if secret.is_empty() || is_placeholder(secret) {
                    continue;
                }

                // Skip lines where the value is read from the environment at runtime.
                if line_has_env_ref && rule.meta.secret_group > 0 {
                    continue;
                }

                // Generic (non-structured) rules get extra semantic checks:
                // identifier patterns, character diversity, entropy, and bigram humanness.
                if rule.meta.secret_group > 0 && rule.meta.confidence != Confidence::High {
                    if looks_like_code_identifier(secret)
                        || char_class_diversity(secret) < 2
                        || entropy(secret) < 3.2
                        || bigram_humanness(secret) > 0.38
                    {
                        continue;
                    }
                }

                // Provider-level structural validation
                // ─────────────────────────────────────
                // URL basic-auth: check that the password component (after the first `:`)
                // is not itself a placeholder word — catches `user:password@host` and
                // `user:secret@host` that the whole-string placeholder check would miss.
                if rule.meta.id == "url-basic-auth" {
                    let pass = secret.splitn(2, ':').nth(1).unwrap_or("");
                    if pass.is_empty() || is_placeholder(pass) {
                        continue;
                    }
                }

                // AWS key IDs: the 16-char suffix must have realistic entropy.
                // Suspiciously low entropy → docs/example key → skip.
                if rule.meta.id == "aws-access-key-id" && !aws_key_entropy_ok(secret) {
                    continue;
                }

                // JWTs: decode the base64url header and verify it contains an `alg`
                // field.  A string that starts with `eyJ` but decodes to non-JSON is
                // an opaque token or encoding artifact — not a JWT → skip.
                if rule.meta.id == "jwt" {
                    match validate_jwt(secret) {
                        Some(false) | None => continue,
                        Some(true) => {}
                    }
                }

                // GitHub tokens carry a CRC-32 checksum in the last 6 chars.
                // A mismatch means the token is fabricated or truncated — downgrade
                // to Medium so it's still visible but doesn't block CI at HIGH.
                let provider_confidence_override: Option<Confidence> =
                    if matches!(
                        rule.meta.id,
                        "github-pat-classic"
                            | "github-pat-fine-grained"
                            | "github-oauth-token"
                            | "github-app-token"
                    ) {
                        match validate_github_token(secret) {
                            Some(true) => None,                    // checksum valid — keep rule confidence
                            Some(false) => Some(Confidence::Medium), // fabricated/old → downgrade
                            None => None,
                        }
                    } else {
                        None
                    };

                // In test/fixture files, generic rules are downgraded to Medium.
                // Structured rules keep full confidence (rotated even if fake-looking).
                let effective_confidence = if let Some(ov) = provider_confidence_override {
                    ov
                } else if in_test_file
                    && rule.meta.secret_group > 0
                    && rule.meta.confidence == Confidence::High
                {
                    Confidence::Medium
                } else {
                    rule.meta.confidence.clone()
                };

                findings.push(Finding {
                    rule_id: rule.meta.id,
                    rule_name: rule.meta.name,
                    confidence: effective_confidence,
                    file: path.to_path_buf(),
                    line_number: line_idx + 1,
                    line: line.trim().to_string(),
                    secret_preview: redact(secret),
                    secret_raw: secret.to_string(),
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

pub fn scan_staged(repo_root: &Path, ignore: &SecoxIgnore) -> Result<Vec<Finding>> {
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
        if !path.exists() || ignore.is_ignored(path, repo_root) {
            continue;
        }
        match scan_file(path) {
            Ok(mut f) => findings.append(&mut f),
            Err(_) => {}
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

pub fn scan_directory(path: &Path, ignore: &SecoxIgnore, repo_root: &Path) -> Result<Vec<Finding>> {
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

        if ignore.is_ignored(p, repo_root) {
            continue;
        }

        if !p.is_file() || is_lock_file(p) {
            continue;
        }

        match scan_file(p) {
            Ok(mut f) => findings.append(&mut f),
            Err(_) => {}
        }
    }

    Ok(findings)
}
