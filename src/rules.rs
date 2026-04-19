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

/// Strings that indicate a value is a placeholder, not a real secret.
static PLACEHOLDER_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)^(example|sample|test|dummy|placeholder|fake|mock|demo|default|your[_\-]?|insert[_\-]?|replace[_\-]?|enter[_\-]?|provide[_\-]?|use[_\-]?|set[_\-]?|my[_\-]?|xxx+|aaa+|bbb+|000+|111+|changeme|fixme|todo|<[^>]+>|\$\{[^}]*\}|\{\{[^}]*\}\}|<%[^%]*%>|\*+|\.\.\.+|n/?a|undefined|null|none|empty|blank)",
    ).unwrap()
});

fn is_all_caps_identifier(value: &str) -> bool {
    // Env-var names used as values look like MY_API_KEY — they always have underscores.
    // Real secrets like AKIA... have no underscores, so we exclude them here.
    value.len() >= 6
        && value.contains('_')
        && value.chars().all(|c| c.is_ascii_uppercase() || c == '_' || c.is_ascii_digit())
        && value.chars().any(|c| c.is_ascii_uppercase())
}

pub fn is_placeholder(value: &str) -> bool {
    PLACEHOLDER_PATTERN.is_match(value)
        || value.starts_with("${")
        || value.starts_with("{{")
        || value.starts_with("<%")
        || is_all_caps_identifier(value)
        || value.chars().collect::<std::collections::HashSet<_>>().len() <= 2
}

/// Shannon entropy in bits per character — genuine secrets tend to score > 3.5.
pub fn entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for b in s.bytes() {
        freq[b as usize] += 1;
    }
    let len = s.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
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
        (
            "jwt",
            "JSON Web Token",
            "JSON Web Token — may contain sensitive claims.",
            Confidence::Medium,
            0,
            r"\beyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\b",
        ),
        (
            "generic-password",
            "Generic Password Assignment",
            "Hard-coded password in source code.",
            Confidence::Medium,
            1,
            r#"(?i)(?:password|passwd|pwd)\s*[:=]\s*['"]([^'"]{8,})['"]"#,
        ),
        (
            "generic-secret",
            "Generic Secret Assignment",
            "Hard-coded secret in source code.",
            Confidence::Medium,
            1,
            r#"(?i)(?:^|[^a-z])(?:secret|client_secret|app_secret)\s*[:=]\s*['"]([^'"]{8,})['"]"#,
        ),
        (
            "generic-api-key",
            "Generic API Key Assignment",
            "Hard-coded API key in source code.",
            Confidence::Medium,
            1,
            r#"(?i)(?:api[_\-]?key|apikey)\s*[:=]\s*['"]([^'"]{16,})['"]"#,
        ),
        (
            "generic-token",
            "Generic Auth Token Assignment",
            "Hard-coded auth/access token in source code.",
            Confidence::Medium,
            1,
            r#"(?i)(?:auth[_\-]?token|access[_\-]?token|bearer[_\-]?token)\s*[:=]\s*['"]([^'"]{16,})['"]"#,
        ),
        (
            "env-secret",
            "Environment Variable Secret",
            "Secret-looking value in an environment file.",
            Confidence::Low,
            1,
            r#"(?m)^(?i)(?:PASSWORD|PASSWD|SECRET|API_KEY|APIKEY|AUTH_TOKEN|ACCESS_TOKEN|PRIVATE_KEY)\s*=\s*([^\s#'"]{12,})"#,
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
