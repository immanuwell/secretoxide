use colored::Colorize;

pub struct RotationGuide {
    pub rule_ids: &'static [&'static str],
    pub provider: &'static str,
    pub revoke_url: &'static str,
    pub steps: &'static [&'static str],
    pub env_var_hint: &'static str,
}

static GUIDES: &[RotationGuide] = &[
    RotationGuide {
        rule_ids: &["aws-access-key-id", "aws-secret-access-key"],
        provider: "Amazon Web Services (IAM)",
        revoke_url: "https://console.aws.amazon.com/iam/home#/security_credentials",
        steps: &[
            "Open IAM → Security credentials → Access keys",
            "Click 'Deactivate' next to the exposed key, then 'Delete'",
            "Create a new access key and store it in your password manager / secrets vault",
            "Update all deployments and CI/CD variables with the new key",
            "Verify CloudTrail for any unauthorized use of the old key",
        ],
        env_var_hint: "AWS_ACCESS_KEY_ID",
    },
    RotationGuide {
        rule_ids: &[
            "github-pat-classic",
            "github-pat-fine-grained",
            "github-oauth-token",
            "github-app-token",
        ],
        provider: "GitHub",
        revoke_url: "https://github.com/settings/tokens",
        steps: &[
            "Go to GitHub → Settings → Developer settings → Personal access tokens",
            "Delete the exposed token immediately",
            "Generate a new token with the minimum required scopes",
            "Update any CI/CD secrets (GitHub Actions, CircleCI, etc.) that used the old token",
        ],
        env_var_hint: "GITHUB_TOKEN",
    },
    RotationGuide {
        rule_ids: &[
            "stripe-live-secret-key",
            "stripe-restricted-key",
            "stripe-test-secret-key",
            "stripe-live-pk",
        ],
        provider: "Stripe",
        revoke_url: "https://dashboard.stripe.com/apikeys",
        steps: &[
            "Open Stripe Dashboard → Developers → API keys",
            "Click 'Roll key' next to the exposed key (Stripe rotates without downtime)",
            "Copy the new secret key and update all deployments immediately",
            "Check your Stripe logs for any suspicious API calls",
        ],
        env_var_hint: "STRIPE_SECRET_KEY",
    },
    RotationGuide {
        rule_ids: &["openai-api-key", "openai-api-key-project"],
        provider: "OpenAI",
        revoke_url: "https://platform.openai.com/api-keys",
        steps: &[
            "Open OpenAI Platform → API keys",
            "Click the trash icon to delete the exposed key",
            "Create a new key and restrict it to specific projects if possible",
            "Update all deployments and check usage logs for unexpected charges",
        ],
        env_var_hint: "OPENAI_API_KEY",
    },
    RotationGuide {
        rule_ids: &["anthropic-api-key"],
        provider: "Anthropic",
        revoke_url: "https://console.anthropic.com/account/keys",
        steps: &[
            "Open Anthropic Console → API Keys",
            "Delete the exposed key",
            "Create a new key with an appropriate name",
            "Update all deployments with the new key",
        ],
        env_var_hint: "ANTHROPIC_API_KEY",
    },
    RotationGuide {
        rule_ids: &["slack-bot-token", "slack-user-token", "slack-app-token", "slack-webhook"],
        provider: "Slack",
        revoke_url: "https://api.slack.com/apps",
        steps: &[
            "Open api.slack.com → Your Apps → select the app",
            "Go to OAuth & Permissions and click 'Revoke all OAuth tokens'",
            "For webhooks: go to Incoming Webhooks and delete the exposed URL",
            "Reinstall the app to your workspace to generate new tokens",
            "Update all services using the old token",
        ],
        env_var_hint: "SLACK_BOT_TOKEN",
    },
    RotationGuide {
        rule_ids: &["google-api-key"],
        provider: "Google Cloud",
        revoke_url: "https://console.cloud.google.com/apis/credentials",
        steps: &[
            "Open Google Cloud Console → APIs & Services → Credentials",
            "Click the key name → Delete (trash icon)",
            "Create a new API key and restrict it to specific APIs and IP ranges",
            "Update all deployments with the new key",
        ],
        env_var_hint: "GOOGLE_API_KEY",
    },
    RotationGuide {
        rule_ids: &["sendgrid-api-key"],
        provider: "SendGrid (Twilio)",
        revoke_url: "https://app.sendgrid.com/settings/api_keys",
        steps: &[
            "Open SendGrid → Settings → API Keys",
            "Click the gear icon next to the exposed key → Delete",
            "Create a new API key with the minimum required permissions",
            "Update all email-sending deployments with the new key",
        ],
        env_var_hint: "SENDGRID_API_KEY",
    },
    RotationGuide {
        rule_ids: &["gitlab-pat"],
        provider: "GitLab",
        revoke_url: "https://gitlab.com/-/profile/personal_access_tokens",
        steps: &[
            "Open GitLab → User Settings → Access Tokens",
            "Click 'Revoke' next to the exposed token",
            "Create a new token with only the scopes you need",
            "Update any CI/CD variables and integrations using the old token",
        ],
        env_var_hint: "GITLAB_TOKEN",
    },
    RotationGuide {
        rule_ids: &["digitalocean-pat"],
        provider: "DigitalOcean",
        revoke_url: "https://cloud.digitalocean.com/account/api/tokens",
        steps: &[
            "Open DigitalOcean → API → Tokens",
            "Delete the exposed token",
            "Generate a new token with the minimum required scopes (read vs read+write)",
            "Update all deployment configs and CI secrets",
        ],
        env_var_hint: "DIGITALOCEAN_ACCESS_TOKEN",
    },
    RotationGuide {
        rule_ids: &["npm-access-token"],
        provider: "npm (Node Package Manager)",
        revoke_url: "https://www.npmjs.com/settings/~/tokens",
        steps: &[
            "Open npmjs.com → Account → Access Tokens",
            "Delete the exposed token",
            "Create a new granular access token with only the required package permissions",
            "Update .npmrc or CI/CD secrets with the new token",
        ],
        env_var_hint: "NPM_TOKEN",
    },
    RotationGuide {
        rule_ids: &["huggingface-token"],
        provider: "Hugging Face",
        revoke_url: "https://huggingface.co/settings/tokens",
        steps: &[
            "Open Hugging Face → Settings → Access Tokens",
            "Delete the exposed token",
            "Create a new token with the minimum required role (read vs write)",
            "Update your scripts or CI/CD with the new token",
        ],
        env_var_hint: "HF_TOKEN",
    },
    RotationGuide {
        rule_ids: &["mailchimp-api-key"],
        provider: "Mailchimp",
        revoke_url: "https://us1.admin.mailchimp.com/account/api/",
        steps: &[
            "Open Mailchimp → Account → Extras → API keys",
            "Click 'Invalidate' next to the exposed key",
            "Create a new API key",
            "Update all email marketing integrations with the new key",
        ],
        env_var_hint: "MAILCHIMP_API_KEY",
    },
    RotationGuide {
        rule_ids: &["databricks-token"],
        provider: "Databricks",
        revoke_url: "https://accounts.cloud.databricks.com/",
        steps: &[
            "Open Databricks workspace → User Settings → Developer → Access Tokens",
            "Revoke the exposed token",
            "Generate a new personal access token with a short expiry",
            "Update all notebooks, jobs, and CI pipelines with the new token",
        ],
        env_var_hint: "DATABRICKS_TOKEN",
    },
    RotationGuide {
        rule_ids: &["vault-token"],
        provider: "HashiCorp Vault",
        revoke_url: "https://developer.hashicorp.com/vault/docs/commands/token/revoke",
        steps: &[
            "Run: vault token revoke <exposed-token>",
            "If you don't have the token value, revoke by accessor: vault token revoke -accessor <accessor>",
            "Review audit logs for any access made with the token",
            "Generate a new token with appropriate policies and TTL",
        ],
        env_var_hint: "VAULT_TOKEN",
    },
    RotationGuide {
        rule_ids: &["shopify-access-token"],
        provider: "Shopify",
        revoke_url: "https://www.shopify.com/admin/apps",
        steps: &[
            "Open your Shopify Admin → Apps → App you use",
            "Uninstall and reinstall the app to rotate the token, or",
            "If using a Custom App: Admin → Settings → Apps and sales channels → Develop apps → select app → rotate API credentials",
            "Update your integration with the new access token",
        ],
        env_var_hint: "SHOPIFY_ACCESS_TOKEN",
    },
    RotationGuide {
        rule_ids: &["azure-storage-account-key"],
        provider: "Azure Storage",
        revoke_url: "https://portal.azure.com/#view/HubsExtension/BrowseResource/resourceType/Microsoft.Storage%2FStorageAccounts",
        steps: &[
            "Open Azure Portal → Storage accounts → select account → Security + networking → Access keys",
            "Click 'Rotate key' for the exposed key (key1 or key2)",
            "Update all connection strings in your apps and CI/CD",
            "Consider switching to Azure AD / managed identity authentication to avoid key management",
        ],
        env_var_hint: "AZURE_STORAGE_CONNECTION_STRING",
    },
    RotationGuide {
        rule_ids: &["private-key-pem"],
        provider: "TLS / SSH Private Key",
        revoke_url: "https://developer.mozilla.org/en-US/docs/Web/Security/Certificate_Transparency",
        steps: &[
            "Generate a new key pair: openssl genrsa -out new_key.pem 4096",
            "If it is a TLS certificate key: reissue the certificate from your CA, then revoke the old cert",
            "If it is an SSH key: remove the old public key from all authorized_keys files and known hosts",
            "Update all services, load balancers, and CI/CD systems with the new key",
            "Report the compromise to your CA if it is a TLS cert (most CAs require this)",
        ],
        env_var_hint: "PRIVATE_KEY",
    },
    RotationGuide {
        rule_ids: &["twilio-account-sid"],
        provider: "Twilio",
        revoke_url: "https://console.twilio.com/us1/account/keys-credentials/api-keys",
        steps: &[
            "Open Twilio Console → Account → API keys & tokens",
            "Revoke the exposed API key (the Account SID itself cannot be rotated, but you can revoke API keys)",
            "Create a new API Key/Secret pair for programmatic access",
            "Update all integrations with the new credentials",
        ],
        env_var_hint: "TWILIO_AUTH_TOKEN",
    },
    RotationGuide {
        rule_ids: &["sensitive-file-env"],
        provider: "Environment file accidentally committed",
        revoke_url: "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository",
        steps: &[
            "Stop tracking the file: git rm --cached <file>",
            "Add it to .gitignore so it never sneaks back in",
            "Rotate any credentials the file contained (assume they are compromised)",
            "If the file was ever pushed: rewrite history with git filter-repo or BFG",
        ],
        env_var_hint: "SECRET",
    },
    RotationGuide {
        rule_ids: &["sensitive-file-key", "sensitive-file-credentials"],
        provider: "Private key / credential file accidentally committed",
        revoke_url: "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository",
        steps: &[
            "Stop tracking the file: git rm --cached <file>",
            "Add it to .gitignore",
            "Generate a new key pair — the exposed one must be considered compromised",
            "Replace the old public key in every authorized_keys / service that trusted it",
            "If the file was ever pushed: rewrite history with git filter-repo or BFG",
        ],
        env_var_hint: "PRIVATE_KEY",
    },
];

pub fn guide_for(rule_id: &str) -> Option<&'static RotationGuide> {
    GUIDES.iter().find(|g| g.rule_ids.contains(&rule_id))
}

pub fn print_guide(guide: &RotationGuide) {
    println!(
        "\n  {} {} — {}",
        "Rotate:".bold().cyan(),
        guide.provider.bold(),
        guide.revoke_url.underline().blue(),
    );
    for (i, step) in guide.steps.iter().enumerate() {
        println!("    {}. {}", i + 1, step);
    }
    println!();
}
