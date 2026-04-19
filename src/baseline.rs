use std::path::Path;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use secox_lib::types::Finding;

const BASELINE_FILE: &str = ".secox-baseline.json";

#[derive(Debug, Serialize, Deserialize)]
pub struct BaselineEntry {
    pub rule_id: String,
    pub file: String,
    pub secret_preview: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Baseline {
    pub version: u32,
    pub entries: Vec<BaselineEntry>,
}

impl Baseline {
    pub fn new(entries: Vec<BaselineEntry>) -> Self {
        Baseline { version: 1, entries }
    }

    pub fn load(repo_root: &Path) -> Option<Self> {
        let path = repo_root.join(BASELINE_FILE);
        let content = std::fs::read_to_string(path).ok()?;
        serde_json::from_str(&content).ok()
    }

    pub fn save(&self, repo_root: &Path) -> Result<()> {
        let path = repo_root.join(BASELINE_FILE);
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json + "\n")?;
        Ok(())
    }

    /// Returns (kept, suppressed): findings not in the baseline, and the count suppressed.
    pub fn suppress(&self, findings: Vec<Finding>, repo_root: &Path) -> (Vec<Finding>, usize) {
        let mut kept = Vec::new();
        let mut suppressed = 0;

        for f in findings {
            let rel = f
                .file
                .strip_prefix(repo_root)
                .unwrap_or(&f.file)
                .to_string_lossy()
                .to_string();

            let in_baseline = self.entries.iter().any(|e| {
                e.rule_id == f.rule_id
                    && e.file == rel
                    && e.secret_preview == f.secret_preview
            });

            if in_baseline {
                suppressed += 1;
            } else {
                kept.push(f);
            }
        }

        (kept, suppressed)
    }
}

pub fn findings_to_entries(findings: &[Finding], repo_root: &Path) -> Vec<BaselineEntry> {
    findings
        .iter()
        .map(|f| {
            let rel = f
                .file
                .strip_prefix(repo_root)
                .unwrap_or(&f.file)
                .to_string_lossy()
                .to_string();
            BaselineEntry {
                rule_id: f.rule_id.to_string(),
                file: rel,
                secret_preview: f.secret_preview.clone(),
            }
        })
        .collect()
}

pub fn baseline_path(repo_root: &Path) -> std::path::PathBuf {
    repo_root.join(BASELINE_FILE)
}
