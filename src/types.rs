use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    High,
    Medium,
    Low,
}

impl Confidence {
    pub fn label(&self) -> &'static str {
        match self {
            Confidence::High => "HIGH",
            Confidence::Medium => "MED ",
            Confidence::Low => "LOW ",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub rule_id: &'static str,
    pub rule_name: &'static str,
    pub confidence: Confidence,
    pub file: PathBuf,
    pub line_number: usize,
    pub line: String,
    pub secret_preview: String,
    /// Raw secret value — used for env-var replacement and history checks.
    /// Not included in any serialised output (JSON/SARIF).
    pub secret_raw: String,
    pub commit: Option<String>,
    pub commit_message: Option<String>,
    /// Set by --verify: Some(true) = active, Some(false) = revoked/invalid, None = not checked.
    pub verified: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
    Sarif,
}
