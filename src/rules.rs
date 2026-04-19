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
        (
            "openai-api-key",
            "OpenAI API Key",
            "OpenAI API key (legacy format).",
            Confidence::High,
            1,
            r"\b(sk-[a-zA-Z0-9]{48})\b",
        ),
        (
            "openai-api-key-project",
            "OpenAI Project API Key",
            "OpenAI API key (project/org format).",
            Confidence::High,
            1,
            r"\b(sk-proj-[a-zA-Z0-9_\-]{40,})\b",
        ),
        (
            "anthropic-api-key",
            "Anthropic API Key",
            "Anthropic Claude API key.",
            Confidence::High,
            1,
            r"\b(sk-ant-(?:api\d+-)?[a-zA-Z0-9_\-]{40,})\b",
        ),
        (
            "stripe-live-secret-key",
            "Stripe Live Secret Key",
            "Stripe live-mode secret API key.",
            Confidence::High,
            1,
            r"\b(sk_live_[0-9a-zA-Z]{24,})\b",
        ),
        (
            "stripe-live-pk",
            "Stripe Live Publishable Key",
            "Stripe live-mode publishable key.",
            Confidence::Medium,
            1,
            r"\b(pk_live_[0-9a-zA-Z]{24,})\b",
        ),
        (
            "stripe-test-secret-key",
            "Stripe Test Secret Key",
            "Stripe test-mode secret key (should not be in version control).",
            Confidence::Medium,
            1,
            r"\b(sk_test_[0-9a-zA-Z]{24,})\b",
        ),
        (
            "slack-bot-token",
            "Slack Bot Token",
            "Slack bot OAuth access token.",
            Confidence::High,
            1,
            r"\b(xoxb-[0-9]{8,13}-[0-9]{8,13}-[a-zA-Z0-9]{24})\b",
        ),
        (
            "slack-user-token",
            "Slack User Token",
            "Slack user OAuth access token.",
            Confidence::High,
            1,
            r"\b(xoxp-[0-9]{8,13}-[0-9]{8,13}-[0-9]{8,13}-[a-zA-Z0-9]{32})\b",
        ),
        (
            "slack-app-token",
            "Slack App-Level Token",
            "Slack app-level token (Socket Mode / Events API).",
            Confidence::High,
            1,
            r"\b(xapp-\d-[A-Z0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{64})\b",
        ),
        (
            "slack-webhook",
            "Slack Incoming Webhook",
            "Slack incoming webhook URL.",
            Confidence::High,
            0,
            r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[a-zA-Z0-9]{24,}",
        ),
        (
            "google-api-key",
            "Google API Key",
            "Google Cloud / Firebase API key.",
            Confidence::High,
            1,
            r"\b(AIza[0-9A-Za-z_\-]{35})\b",
        ),
        (
            "sendgrid-api-key",
            "SendGrid API Key",
            "Twilio SendGrid mail API key.",
            Confidence::High,
            1,
            r"\b(SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43})\b",
        ),
        (
            "mailgun-api-key",
            "Mailgun API Key",
            "Mailgun private API key.",
            Confidence::High,
            1,
            r"\b(key-[0-9a-zA-Z]{32})\b",
        ),
        (
            "npm-access-token",
            "npm Access Token",
            "npm registry access token.",
            Confidence::High,
            1,
            r"\b(npm_[a-zA-Z0-9]{36})\b",
        ),
        (
            "pypi-api-token",
            "PyPI API Token",
            "Python Package Index API token.",
            Confidence::High,
            1,
            r"\b(pypi-[a-zA-Z0-9_\-]{200,})\b",
        ),
        (
            "vault-token",
            "HashiCorp Vault Token",
            "HashiCorp Vault service token.",
            Confidence::High,
            1,
            r"\b(hvs\.[a-zA-Z0-9_\-]{90,})\b",
        ),
        (
            "telegram-bot-token",
            "Telegram Bot Token",
            "Telegram Bot API token.",
            Confidence::High,
            1,
            r"\b(\d{8,10}:[a-zA-Z0-9_\-]{35})\b",
        ),
        (
            "private-key-pem",
            "PEM Private Key",
            "PEM-encoded private key block (RSA, EC, DSA, OPENSSH, PGP).",
            Confidence::High,
            0,
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?:[^-]*)-----",
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
