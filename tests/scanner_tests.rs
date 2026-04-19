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
fn snake_case_identifier_as_value_ignored() {
    let src = r#"password = "my_db_password_here""#;
    let ids = findings_for(src);
    assert!(!ids.contains(&"generic-password".to_string()), "false positive: {ids:?}");
}

#[test]
fn camel_case_identifier_as_value_ignored() {
    let src = r#"secret = "myApplicationSecret""#;
    let ids = findings_for(src);
    assert!(!ids.contains(&"generic-secret".to_string()), "false positive: {ids:?}");
}

#[test]
fn composite_placeholder_phrase_ignored() {
    let src = r#"password = "TestPassword123!""#;
    let ids = findings_for(src);
    assert!(!ids.contains(&"generic-password".to_string()), "false positive: {ids:?}");
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

// ── New provider rule tests ───────────────────────────────────────────────────

#[test]
fn gitlab_pat_detected() {
    // glpat- + exactly 20 alphanumeric/hyphen/underscore chars
    let key = t(&["glpat-", "abcdefghijklmnopqrst"]);
    let src = format!("GITLAB_TOKEN={key}");
    let ids = findings_for(&src);
    assert!(ids.contains(&"gitlab-pat".to_string()), "{ids:?}");
}

#[test]
fn digitalocean_pat_detected() {
    // dop_v1_ + exactly 64 lowercase hex chars
    let key = t(&["dop_v1_", "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4", "e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"]);
    let src = format!("DO_TOKEN={key}");
    let ids = findings_for(&src);
    assert!(ids.contains(&"digitalocean-pat".to_string()), "{ids:?}");
}

#[test]
fn docker_hub_token_detected() {
    // dckr_pat_ + exactly 27 alphanumeric/hyphen/underscore chars
    let key = t(&["dckr_pat_", "abcdefghijklmnopqrstuvwxyz0"]);
    let src = format!("DOCKER_TOKEN={key}");
    let ids = findings_for(&src);
    assert!(ids.contains(&"docker-hub-token".to_string()), "{ids:?}");
}

#[test]
fn shopify_access_token_detected() {
    // shpat_ + exactly 32 lowercase hex chars
    let key = t(&["shpat_", "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"]);
    let src = format!("SHOPIFY_TOKEN={key}");
    let ids = findings_for(&src);
    assert!(ids.contains(&"shopify-access-token".to_string()), "{ids:?}");
}

#[test]
fn linear_api_key_detected() {
    // lin_api_ + exactly 40 alphanumeric chars
    let key = t(&["lin_api_", "abcdefghijklmnopqrstuvwxyzABCD1234567890"]);
    let src = format!("LINEAR_KEY={key}");
    let ids = findings_for(&src);
    assert!(ids.contains(&"linear-api-key".to_string()), "{ids:?}");
}

#[test]
fn huggingface_token_detected() {
    // hf_ + exactly 34 alphanumeric chars
    let key = t(&["hf_", "abcdefghijklmnopqrstuvwxyzABCDEFGH"]);
    let src = format!("HF_TOKEN={key}");
    let ids = findings_for(&src);
    assert!(ids.contains(&"huggingface-token".to_string()), "{ids:?}");
}

#[test]
fn databricks_token_detected() {
    // dapi + exactly 32 lowercase hex chars
    let key = t(&["dapi", "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"]);
    let src = format!("DATABRICKS_TOKEN={key}");
    let ids = findings_for(&src);
    assert!(ids.contains(&"databricks-token".to_string()), "{ids:?}");
}

#[test]
fn mailchimp_api_key_detected() {
    // 32 lowercase hex chars + -us + 1-2 digits
    let key = t(&["a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4", "-us12"]);
    let src = format!("MC_API_KEY={key}");
    let ids = findings_for(&src);
    assert!(ids.contains(&"mailchimp-api-key".to_string()), "{ids:?}");
}

#[test]
fn stripe_restricted_key_detected() {
    // rk_live_ + 24+ alphanumeric chars
    let key = t(&["rk_live_", "abcdefghijklmnopqrstuvwx"]);
    let src = format!("STRIPE_KEY={key}");
    let ids = findings_for(&src);
    assert!(ids.contains(&"stripe-restricted-key".to_string()), "{ids:?}");
}

#[test]
fn azure_storage_key_detected() {
    // AccountKey= + exactly 86 base64 chars + == (64-byte key encoded)
    // 26+26+10+2+22 = 86 chars: a-z, A-Z, 0-9, +/, then fill to 86
    let key = t(&["AccountKey=", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/abcdefghijklmnopqrstuv"]);
    let src = format!("DefaultEndpointsProtocol=https;{key}==;EndpointSuffix=core.windows.net");
    let ids = findings_for(&src);
    assert!(ids.contains(&"azure-storage-account-key".to_string()), "{ids:?}");
}

#[test]
fn jwt_invalid_header_not_detected() {
    // A string matching the JWT shape but with a non-JSON base64url header.
    // eyJub3Rqc29u decodes to "{notjson" which is not valid JSON.
    let src = "token: eyJub3Rqc29u.eyJzdWIiOiIxMjM0NTY3ODkwIn0.fakesignaturehere12345";
    let ids = findings_for(src);
    assert!(!ids.contains(&"jwt".to_string()), "false positive: {ids:?}");
}

#[test]
fn natural_language_generic_secret_ignored() {
    // A generic-secret match whose value is clearly English prose — should be suppressed
    // by the bigram humanness filter.
    let src = r#"secret = "TheseAreJustEnglishWordsHere""#;
    let ids = findings_for(src);
    assert!(!ids.contains(&"generic-secret".to_string()), "false positive: {ids:?}");
}
