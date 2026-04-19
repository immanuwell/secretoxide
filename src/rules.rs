use once_cell::sync::Lazy;
use regex::Regex;

use crate::types::Confidence;

pub struct Rule {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub confidence: Confidence,
    pub secret_group: usize,
}

pub struct CompiledRule {
    pub meta: Rule,
    pub regex: Regex,
}

pub fn redact(secret: &str) -> String {
    let n = secret.len();
    if n <= 8 {
        return "••••••••".to_string();
    }
    let visible = 4.min(n / 4);
    let prefix = &secret[..visible];
    let suffix = &secret[n - visible..];
    let dots = "•".repeat(n - visible * 2);
    format!("{prefix}{dots}{suffix}")
}

fn build_rules() -> Vec<CompiledRule> {
    let specs: &[(&str, &str, &str, Confidence, usize, &str)] = &[
        (
            "aws-access-key-id",
            "AWS Access Key ID",
            "Amazon Web Services access key identifier.",
            Confidence::High,
            1,
            r"\b(AKIA[0-9A-Z]{16})\b",
        ),
        (
            "aws-secret-access-key",
            "AWS Secret Access Key",
            "Amazon Web Services secret access key.",
            Confidence::High,
            1,
            r#"(?i)aws[_\-\.]?secret[_\-\.]?(?:access[_\-\.]?)?key\s*(?:['"]?\s*[:=]\s*['"]?|[:=])\s*([A-Za-z0-9/+=]{40})\b"#,
        ),
        (
            "github-pat-classic",
            "GitHub Personal Access Token",
            "GitHub classic personal access token.",
            Confidence::High,
            1,
            r"\b(ghp_[a-zA-Z0-9]{36,})\b",
        ),
        (
            "github-pat-fine-grained",
            "GitHub Fine-Grained PAT",
            "GitHub fine-grained personal access token.",
            Confidence::High,
            1,
            r"\b(github_pat_[a-zA-Z0-9_]{82,})\b",
        ),
        (
            "github-oauth-token",
            "GitHub OAuth Token",
            "GitHub OAuth access token.",
            Confidence::High,
            1,
            r"\b(gho_[a-zA-Z0-9]{36,})\b",
        ),
        (
            "github-app-token",
            "GitHub App Token",
            "GitHub App installation or user access token.",
            Confidence::High,
            1,
            r"\b(gh[su]_[a-zA-Z0-9]{36,})\b",
        ),
    ];

    specs
        .iter()
        .filter_map(|(id, name, desc, conf, grp, pat)| {
            match Regex::new(pat) {
                Ok(re) => Some(CompiledRule {
                    meta: Rule {
                        id,
                        name,
                        description: desc,
                        confidence: conf.clone(),
                        secret_group: *grp,
                    },
                    regex: re,
                }),
                Err(e) => {
                    eprintln!("secox: failed to compile rule {id}: {e}");
                    None
                }
            }
        })
        .collect()
}

pub static RULES: Lazy<Vec<CompiledRule>> = Lazy::new(build_rules);
