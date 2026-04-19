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
        r"(?i)^(example|sample|test|dummy|placeholder|fake|mock|demo|default|your[_\-]?|insert[_\-]?|replace[_\-]?|enter[_\-]?|provide[_\-]?|use[_\-]?|set[_\-]?|my[_\-]?|xxx+|aaa+|bbb+|000+|111+|changeme|fixme|todo|password|passwd|pass|<[^>]+>|\$\{[^}]*\}|\{\{[^}]*\}\}|<%[^%]*%>|\*+|\.\.\.+|n/?a|undefined|null|none|empty|blank)",
    ).unwrap()
});

/// Composite phrases like "TestPassword", "FakeApiKey", "SampleSecret" appear in
/// documentation and test files — they are not real credentials.
static PLACEHOLDER_PHRASE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)(test|fake|mock|sample|example|demo|dummy|stub)(pass(word)?|secret|key|token|cred|auth|api)",
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
        || PLACEHOLDER_PHRASE.is_match(value)
        || value.chars().collect::<std::collections::HashSet<_>>().len() <= 2
}

/// Heuristic check for generic (non-structured) rules only: a value that looks like
/// a camelCase or snake_case identifier is a variable name, not a hardcoded secret.
/// Do NOT call this for HIGH confidence rules with strict prefixes (sk_live_, ghp_, …).
pub fn looks_like_code_identifier(value: &str) -> bool {
    if value.len() < 6 || value.len() > 40 {
        return false;
    }
    let bytes = value.as_bytes();
    let is_snake = bytes.iter().all(|&b| b.is_ascii_lowercase() || b == b'_' || b.is_ascii_digit())
        && bytes.contains(&b'_');
    let is_camel = bytes.iter().all(|&b| b.is_ascii_alphanumeric())
        && bytes[0].is_ascii_lowercase()
        && bytes.iter().any(|&b| b.is_ascii_uppercase())
        && !bytes.iter().any(|&b| b.is_ascii_digit());
    is_snake || is_camel
}

/// Measures how "English-like" a value is by counting common English bigrams
/// found within consecutive alphabetic runs.  Natural language / prose scores
/// above ~0.38; random-looking credentials score much lower.
///
/// Used as an additional filter for generic rules: if the "secret" is natural
/// language masquerading as a value (e.g. `secret = "These-Are-Just-Words"`)
/// we suppress the finding to avoid false positives.
pub fn bigram_humanness(s: &str) -> f64 {
    // Top-30 English letter bigrams (frequency-ordered)
    const COMMON: &[[u8; 2]] = &[
        *b"th", *b"he", *b"in", *b"er", *b"an", *b"re", *b"on", *b"en", *b"at", *b"es",
        *b"ed", *b"te", *b"ti", *b"or", *b"st", *b"ar", *b"nd", *b"to", *b"nt", *b"is",
        *b"of", *b"it", *b"al", *b"as", *b"ha", *b"ng", *b"io", *b"le", *b"se", *b"ou",
    ];

    // Only analyse consecutive alphabetic runs so digits / symbols don't dilute the score
    let mut total = 0usize;
    let mut hits = 0usize;
    let lower = s.to_lowercase();
    let bytes = lower.as_bytes();
    let mut run_start = 0;
    let mut in_run = false;

    for (i, &b) in bytes.iter().enumerate() {
        if b.is_ascii_alphabetic() {
            if !in_run { run_start = i; in_run = true; }
        } else if in_run {
            let run = &bytes[run_start..i];
            for w in run.windows(2) {
                total += 1;
                if COMMON.iter().any(|bg| bg == w) { hits += 1; }
            }
            in_run = false;
        }
    }
    if in_run {
        let run = &bytes[run_start..];
        for w in run.windows(2) {
            total += 1;
            if COMMON.iter().any(|bg| bg == w) { hits += 1; }
        }
    }

    if total == 0 { return 0.0; }
    hits as f64 / total as f64
}

/// Number of distinct character classes present in `s` (uppercase / lowercase /
/// digit / non-alphanumeric).  Real credentials almost always use at least two.
pub fn char_class_diversity(s: &str) -> u8 {
    let (mut upper, mut lower, mut digit, mut special) = (false, false, false, false);
    for c in s.chars() {
        if c.is_ascii_uppercase() { upper = true; }
        else if c.is_ascii_lowercase() { lower = true; }
        else if c.is_ascii_digit() { digit = true; }
        else { special = true; }
    }
    upper as u8 + lower as u8 + digit as u8 + special as u8
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

static ENV_REF_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)\b(os\.getenv|os\.environ|process\.env\.|System\.getenv|getenv\s*\(|secrets\.get\s*\(|config\.get\s*\(|settings\.[A-Z_])",
    ).unwrap()
});

/// Returns true when the line fetches a value from the environment rather than
/// hard-coding it — e.g. `os.getenv(...)` or `process.env.SECRET`.
pub fn is_env_reference(line: &str) -> bool {
    ENV_REF_PATTERN.is_match(line)
}

/// Returns true when the path is clearly a test, fixture, or documentation file.
/// Used to downgrade confidence for generic rules — specific-format rules (AWS, GitHub, …)
/// are still flagged at full confidence because even test-file leaks should be rotated.
pub fn is_test_path(path: &std::path::Path) -> bool {
    let s = path.to_string_lossy().to_lowercase();
    // Directory components
    let test_dirs = [
        "/test/", "/tests/", "/spec/", "/specs/", "/__tests__/",
        "/fixtures/", "/fixture/", "/mocks/", "/mock/",
        "/examples/", "/example/", "/docs/", "/doc/",
        "/testdata/", "/test_data/",
    ];
    if test_dirs.iter().any(|d| s.contains(d)) {
        return true;
    }
    // File name patterns
    if let Some(name) = path.file_name().map(|n| n.to_string_lossy().to_lowercase()) {
        let test_names = ["_test.", "_spec.", ".test.", ".spec.", "test_", "spec_"];
        if test_names.iter().any(|p| name.contains(p)) {
            return true;
        }
        // Common test file names
        if matches!(
            name.as_ref(),
            "test.py" | "test.js" | "test.ts" | "test.go" | "test.rb"
                | "conftest.py" | "setup_test.go"
        ) {
            return true;
        }
    }
    false
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
            // Exclude template syntax (${ {{ <%) and function calls (parens/brackets).
            r#"(?m)^(?i)(?:PASSWORD|PASSWD|SECRET|API_KEY|APIKEY|AUTH_TOKEN|ACCESS_TOKEN|PRIVATE_KEY)\s*=\s*([^\s#'"()\[\]{}<>$]{12,})"#,
        ),
        // ── Additional provider-specific rules ────────────────────────────────
        (
            "gitlab-pat",
            "GitLab Personal Access Token",
            "GitLab personal access token.",
            Confidence::High,
            1,
            r"\b(glpat-[a-zA-Z0-9_\-]{20})\b",
        ),
        (
            "digitalocean-pat",
            "DigitalOcean Personal Access Token",
            "DigitalOcean personal access token (v1).",
            Confidence::High,
            1,
            r"\b(dop_v1_[a-f0-9]{64})\b",
        ),
        (
            "docker-hub-token",
            "Docker Hub Access Token",
            "Docker Hub personal access token.",
            Confidence::High,
            1,
            r"\b(dckr_pat_[a-zA-Z0-9_\-]{27})\b",
        ),
        (
            "shopify-access-token",
            "Shopify Access Token",
            "Shopify private app access token.",
            Confidence::High,
            1,
            r"\b(shpat_[a-f0-9]{32})\b",
        ),
        (
            "linear-api-key",
            "Linear API Key",
            "Linear project management API key.",
            Confidence::High,
            1,
            r"\b(lin_api_[a-zA-Z0-9]{40})\b",
        ),
        (
            "planetscale-token",
            "PlanetScale Service Token",
            "PlanetScale database service token.",
            Confidence::High,
            1,
            r"\b(pscale_tkn_[a-zA-Z0-9_\-]{43})\b",
        ),
        (
            "doppler-token",
            "Doppler Service Token",
            "Doppler secrets manager service token.",
            Confidence::High,
            1,
            r"(dp\.st\.[a-zA-Z0-9._\-]{20,})",
        ),
        (
            "huggingface-token",
            "Hugging Face API Token",
            "Hugging Face user or write access token.",
            Confidence::High,
            1,
            r"\b(hf_[a-zA-Z0-9]{34})\b",
        ),
        (
            "databricks-token",
            "Databricks Personal Access Token",
            "Databricks workspace personal access token.",
            Confidence::High,
            1,
            r"\b(dapi[a-f0-9]{32})\b",
        ),
        (
            "twilio-account-sid",
            "Twilio Account SID",
            "Twilio account SID — always accompanies an auth token.",
            Confidence::High,
            1,
            r"\b(AC[a-f0-9]{32})\b",
        ),
        (
            "mailchimp-api-key",
            "Mailchimp API Key",
            "Mailchimp marketing API key.",
            Confidence::High,
            1,
            r"\b([a-f0-9]{32}-us\d{1,2})\b",
        ),
        (
            "stripe-restricted-key",
            "Stripe Restricted Key",
            "Stripe restricted API key (live mode).",
            Confidence::High,
            1,
            r"\b(rk_live_[0-9a-zA-Z]{24,})\b",
        ),
        (
            "azure-storage-account-key",
            "Azure Storage Account Key",
            "Azure storage account access key (base64-encoded 512-bit key).",
            Confidence::High,
            1,
            r"AccountKey=([A-Za-z0-9+/]{86}==)",
        ),
        (
            "url-basic-auth",
            "Credentials in URL",
            "Username and password embedded directly in a URL (basic auth).",
            Confidence::High,
            1,
            r"[a-zA-Z][a-zA-Z0-9+.\-]*://([^:@\s<>{}]{1,100}:[^@\s<>{}]{1,100})@[a-zA-Z0-9]",
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
