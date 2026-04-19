pub mod rules;
pub mod scanner;
pub mod types;
// git and output are CLI-only; not re-exported.

use std::path::Path;

/// Public wrapper around scan_content for use in tests and external crates.
pub fn scan_content_pub(
    content: &str,
    path: &Path,
    commit: Option<&str>,
    commit_message: Option<&str>,
) -> Vec<types::Finding> {
    scanner::scan_content(content, path, commit, commit_message)
}
