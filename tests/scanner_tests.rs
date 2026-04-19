use std::path::Path;

// We test the public scanner::scan_content function directly.
// Each test checks that a known secret pattern fires AND that a
// safe / placeholder equivalent does NOT produce a finding.
//
// Secret-shaped test fixtures are assembled from parts at runtime so that
// secret-scanning tools do not flag this repository itself.

fn findings_for(content: &str) -> Vec<String> {
    secox_lib::scan_content_pub(content, Path::new("test.txt"), None, None)
        .into_iter()
        .map(|f| f.rule_id.to_string())
        .collect()
}

/// Joins parts at runtime so no complete secret literal exists in source.
fn t(parts: &[&str]) -> String {
    parts.concat()
}

#[test]
fn aws_access_key_detected() {
    let src = r#"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"#;
    let ids = findings_for(src);
    assert!(ids.contains(&"aws-access-key-id".to_string()), "expected aws-access-key-id in {ids:?}");
}

#[test]
fn aws_access_key_placeholder_ignored() {
    // "AKIATESTEXAMPLE00" — only 18 chars, won't match 20-char requirement
    let src = r#"key = "AKIATESTEXAMPLE00""#;
    let ids = findings_for(src);
    assert!(!ids.contains(&"aws-access-key-id".to_string()), "false positive: {ids:?}");
}

#[test]
fn github_pat_detected() {
    // ghp_ + exactly 36 alphanumeric chars
    let key = t(&["ghp_aBcDeFgHiJk", "LmNoPqRsTuVwXyZ1234567890"]);
    let src = format!("token = {key}");
    let ids = findings_for(&src);
    assert!(ids.contains(&"github-pat-classic".to_string()), "{ids:?}");
}

#[test]
fn openai_key_detected() {
    // sk- + exactly 48 alphanumeric chars
    let key = t(&["sk-aBcDeFgHiJk", "LmNoPqRsTuVwXyZ1234567890123456789012"]);
    let src = format!("OPENAI_API_KEY={key}");
    let ids = findings_for(&src);
    assert!(ids.contains(&"openai-api-key".to_string()), "{ids:?}");
}

#[test]
fn anthropic_key_detected() {
    let key = t(&["sk-ant-api03-", "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH"]);
    let src = format!("key = {key}");
    let ids = findings_for(&src);
    assert!(ids.contains(&"anthropic-api-key".to_string()), "{ids:?}");
}

#[test]
fn stripe_live_key_detected() {
    let key = t(&["sk_live_", "abcdefghijklmnopqrstuvwx"]);
    let src = format!(r#"stripe_key = "{key}""#);
    let ids = findings_for(&src);
    assert!(ids.contains(&"stripe-live-secret-key".to_string()), "{ids:?}");
}

#[test]
fn google_api_key_detected() {
    // AIza + exactly 35 alphanumeric chars
    let key = t(&["AIzaSyD", "abcdefghijklmnopqrstuvwxyz012345"]);
    let src = format!("GOOGLE_API_KEY={key}");
    let ids = findings_for(&src);
    assert!(ids.contains(&"google-api-key".to_string()), "{ids:?}");
}

#[test]
fn sendgrid_key_detected() {
    // SG. + 22 chars + . + 43 chars
    let key = t(&["SG.", "abcdefghijklmnopqrstuv.", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"]);
    let src = format!("key = {key}");
    let ids = findings_for(&src);
    assert!(ids.contains(&"sendgrid-api-key".to_string()), "{ids:?}");
}

#[test]
fn pem_private_key_detected() {
    let src = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----";
    let ids = findings_for(src);
    assert!(ids.contains(&"private-key-pem".to_string()), "{ids:?}");
}

#[test]
fn generic_password_detected() {
    let src = r#"password = "SuperSecret123!""#;
    let ids = findings_for(src);
    assert!(ids.contains(&"generic-password".to_string()), "{ids:?}");
}

#[test]
fn generic_password_placeholder_ignored() {
    let src = r#"password = "your_password_here""#;
    let ids = findings_for(src);
    assert!(!ids.contains(&"generic-password".to_string()), "false positive: {ids:?}");
}

#[test]
fn inline_ignore_suppresses_finding() {
    let key = t(&["sk-aBcDeFgHiJk", "LmNoPqRsTuVwXyZ123456789012345678901"]);
    let src = format!("OPENAI_API_KEY={key}  # secox:ignore");
    let ids = findings_for(&src);
    assert!(ids.is_empty(), "expected no findings but got {ids:?}");
}

#[test]
fn file_ignore_suppresses_all() {
    let key = t(&["sk-aBcDeFgHiJk", "LmNoPqRsTuVwXyZ123456789012345678901"]);
    let src = format!("# secox:ignore-file\nOPENAI_API_KEY={key}");
    let ids = findings_for(&src);
    assert!(ids.is_empty(), "expected no findings but got {ids:?}");
}

#[test]
fn env_reference_line_not_flagged() {
    // os.getenv call should not be treated as a hardcoded secret
    let src = r#"api_key = os.getenv("OPENAI_API_KEY", "")"#;
    let ids = findings_for(src);
    assert!(!ids.contains(&"generic-api-key".to_string()), "false positive: {ids:?}");
}

#[test]
fn env_secret_template_value_ignored() {
    // .env file with a template placeholder
    let src = "API_KEY=${MY_REAL_API_KEY_FROM_CI}";
    let ids = findings_for(src);
    assert!(!ids.contains(&"env-secret".to_string()), "false positive: {ids:?}");
}

#[test]
fn all_caps_identifier_as_value_ignored() {
    // e.g. generic-api-key: api_key = "MY_PROD_API_KEY_VALUE" — all-caps env ref, not a secret
    let src = r#"api_key = "MY_PROD_API_KEY_VALUE""#;
    let ids = findings_for(src);
    assert!(!ids.contains(&"generic-api-key".to_string()), "false positive: {ids:?}");
}

#[test]
fn template_var_as_value_ignored() {
    let src = r#"secret = "${SECRET_KEY_ENV_VAR}""#;
    let ids = findings_for(src);
    assert!(!ids.contains(&"generic-secret".to_string()), "false positive: {ids:?}");
}

#[test]
fn inline_allow_suppresses_finding() {
    let key = t(&["sk-aBcDeFgHiJk", "LmNoPqRsTuVwXyZ123456789012345678901"]);
    let src = format!("OPENAI_API_KEY={key}  // secox:allow");
    let ids = findings_for(&src);
    assert!(ids.is_empty(), "expected no findings but got {ids:?}");
}

#[test]
fn file_allow_suppresses_all() {
    let key = t(&["sk-aBcDeFgHiJk", "LmNoPqRsTuVwXyZ123456789012345678901"]);
    let src = format!("# secox:allow-file\nOPENAI_API_KEY={key}");
    let ids = findings_for(&src);
    assert!(ids.is_empty(), "expected no findings but got {ids:?}");
}

#[test]
fn jwt_detected() {
    // A syntactically valid JWT-shaped string.
    let src = "token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    let ids = findings_for(src);
    assert!(ids.contains(&"jwt".to_string()), "{ids:?}");
}

#[test]
fn npm_token_detected() {
    // npm_ + exactly 36 alphanumeric chars
    let key = t(&["npm_aBcDeFgHiJk", "LmNoPqRsTuVwXyZ1234567890"]);
    let src = format!("NPM_TOKEN={key}");
    let ids = findings_for(&src);
    assert!(ids.contains(&"npm-access-token".to_string()), "{ids:?}");
}

#[test]
fn slack_bot_token_detected() {
    // xoxb- + 11 digits + - + 11 digits + - + exactly 24 alphanumeric chars
    let key = t(&["xoxb-12345678901-", "12345678901-aBcDeFgHiJkLmNoPqRsTuVwX"]);
    let src = format!("SLACK_TOKEN={key}");
    let ids = findings_for(&src);
    assert!(ids.contains(&"slack-bot-token".to_string()), "{ids:?}");
}
