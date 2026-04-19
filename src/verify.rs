use std::time::Duration;

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(8))
        .build()
}

/// Some(true) = 2xx (active), Some(false) = 401/403 (invalid), None = inconclusive
fn http_get(url: &str, headers: &[(&str, &str)]) -> Option<bool> {
    let mut req = agent().get(url);
    for (k, v) in headers {
        req = req.set(k, v);
    }
    match req.call() {
        Ok(_) => Some(true),
        Err(ureq::Error::Status(401 | 403, _)) => Some(false),
        _ => None,
    }
}

fn bearer(url: &str, token: &str, extra: &[(&str, &str)]) -> Option<bool> {
    let auth = format!("Bearer {}", token);
    let mut headers = vec![("Authorization", auth.as_str())];
    headers.extend_from_slice(extra);
    http_get(url, &headers)
}

// ── Provider implementations ──────────────────────────────────────────────────

fn verify_github(token: &str) -> Option<bool> {
    bearer(
        "https://api.github.com/user",
        token,
        &[("User-Agent", "secox")],
    )
}

fn verify_openai(key: &str) -> Option<bool> {
    bearer("https://api.openai.com/v1/models", key, &[])
}

fn verify_anthropic(key: &str) -> Option<bool> {
    http_get(
        "https://api.anthropic.com/v1/models",
        &[
            ("x-api-key", key),
            ("anthropic-version", "2023-06-01"),
        ],
    )
}

fn verify_huggingface(token: &str) -> Option<bool> {
    bearer("https://huggingface.co/api/whoami", token, &[])
}

fn verify_gitlab(token: &str) -> Option<bool> {
    http_get(
        "https://gitlab.com/api/v4/user",
        &[("PRIVATE-TOKEN", token)],
    )
}

fn verify_slack(token: &str) -> Option<bool> {
    let res = agent()
        .post("https://slack.com/api/auth.test")
        .set("Authorization", &format!("Bearer {}", token))
        .set("Content-Type", "application/x-www-form-urlencoded")
        .send_string("")
        .ok()?;
    let json = res.into_json::<serde_json::Value>().ok()?;
    Some(json["ok"].as_bool().unwrap_or(false))
}

fn verify_stripe(key: &str) -> Option<bool> {
    bearer("https://api.stripe.com/v1/balance", key, &[])
}

fn verify_sendgrid(key: &str) -> Option<bool> {
    bearer("https://api.sendgrid.com/v3/scopes", key, &[])
}

fn verify_mailchimp(key: &str) -> Option<bool> {
    // Key format: <hash>-<datacenter>
    let dc = key.split('-').last()?;
    if dc.len() > 6 {
        return None; // doesn't look like a datacenter suffix
    }
    let url = format!("https://{}.api.mailchimp.com/3.0/ping", dc);
    bearer(&url, key, &[])
}

fn verify_digitalocean(token: &str) -> Option<bool> {
    bearer("https://api.digitalocean.com/v2/account", token, &[])
}

fn verify_linear(key: &str) -> Option<bool> {
    let res = agent()
        .post("https://api.linear.app/graphql")
        .set("Authorization", key)
        .set("Content-Type", "application/json")
        .send_string(r#"{"query":"{ viewer { id } }"}"#)
        .ok()?;
    let json = res.into_json::<serde_json::Value>().ok()?;
    // Valid token → data.viewer exists; invalid → errors array, no viewer
    Some(json.get("data").and_then(|d| d.get("viewer")).is_some())
}

fn verify_doppler(token: &str) -> Option<bool> {
    bearer("https://api.doppler.com/v3/me", token, &[])
}

fn verify_databricks(token: &str) -> Option<bool> {
    // Token is provider-prefixed (dapi...) but we don't know the workspace host.
    // Try the common Databricks community edition host as a best-effort check.
    let _ = token;
    None
}

// ── Dispatch ─────────────────────────────────────────────────────────────────

/// Returns true when secox knows how to verify a given rule against its provider.
pub fn supported(rule_id: &str) -> bool {
    matches!(
        rule_id,
        "github-pat-classic"
            | "github-pat-fine-grained"
            | "github-oauth-token"
            | "github-app-token"
            | "openai-api-key"
            | "openai-api-key-project"
            | "anthropic-api-key"
            | "huggingface-token"
            | "gitlab-pat"
            | "slack-bot-token"
            | "slack-user-token"
            | "slack-app-token"
            | "stripe-live-secret-key"
            | "stripe-restricted-key"
            | "sendgrid-api-key"
            | "mailchimp-api-key"
            | "digitalocean-pat"
            | "linear-api-key"
            | "doppler-token"
    )
}

/// Check whether a found secret is still active against its provider's API.
///
/// Returns `Some(true)` if the credential is confirmed active, `Some(false)` if
/// it is definitively invalid or revoked, and `None` if the provider is not
/// supported or the check is inconclusive (network error, timeout, etc.).
pub fn verify(rule_id: &str, secret: &str) -> Option<bool> {
    match rule_id {
        "github-pat-classic"
        | "github-pat-fine-grained"
        | "github-oauth-token"
        | "github-app-token" => verify_github(secret),

        "openai-api-key" | "openai-api-key-project" => verify_openai(secret),

        "anthropic-api-key" => verify_anthropic(secret),

        "huggingface-token" => verify_huggingface(secret),

        "gitlab-pat" => verify_gitlab(secret),

        "slack-bot-token" | "slack-user-token" | "slack-app-token" => verify_slack(secret),

        "stripe-live-secret-key" | "stripe-restricted-key" => verify_stripe(secret),

        "sendgrid-api-key" => verify_sendgrid(secret),

        "mailchimp-api-key" => verify_mailchimp(secret),

        "digitalocean-pat" => verify_digitalocean(secret),

        "linear-api-key" => verify_linear(secret),

        "doppler-token" => verify_doppler(secret),

        "databricks-token" => verify_databricks(secret),

        _ => None,
    }
}
