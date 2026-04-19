use std::path::Path;

/// Loaded from `.secoxignore` in the repo root, optionally merged with
/// patterns supplied on the command line via `--ignore`.
pub struct SecoxIgnore {
    entries: Vec<(bool, String)>, // (negated, pattern)
}

impl SecoxIgnore {
    pub fn empty() -> Self {
        Self { entries: vec![] }
    }

    /// Load `.secoxignore` from `root`, then append any extra CLI patterns.
    pub fn load(root: &Path, extra: &[String]) -> Self {
        let mut entries: Vec<(bool, String)> = Vec::new();

        let path = root.join(".secoxignore");
        if let Ok(content) = std::fs::read_to_string(&path) {
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                if let Some(rest) = line.strip_prefix('!') {
                    entries.push((true, rest.to_string()));
                } else {
                    entries.push((false, line.to_string()));
                }
            }
        }

        for p in extra {
            entries.push((false, p.clone()));
        }

        Self { entries }
    }

    pub fn is_ignored(&self, path: &Path, root: &Path) -> bool {
        if self.entries.is_empty() {
            return false;
        }
        let rel = path.strip_prefix(root).unwrap_or(path);
        let rel_str = rel.to_string_lossy().replace('\\', "/");

        let mut ignored = false;
        for (negated, pattern) in &self.entries {
            if pattern_matches(&rel_str, rel, pattern) {
                ignored = !negated;
            }
        }
        ignored
    }
}

fn pattern_matches(rel_str: &str, rel: &Path, pattern: &str) -> bool {
    let pattern = pattern.trim_end_matches('/');
    if pattern.is_empty() {
        return false;
    }

    // Rooted: "/tests" or "/src/fixtures" — match only from repo root.
    if let Some(rooted) = pattern.strip_prefix('/') {
        let rooted = rooted.trim_end_matches('/');
        return rel_str == rooted || rel_str.starts_with(&format!("{rooted}/"));
    }

    // Contains slash but not rooted: "src/testdata" — match anywhere the
    // sub-path appears.
    if pattern.contains('/') {
        // "**/<name>" — ignore by directory name at any depth.
        if let Some(tail) = pattern.strip_prefix("**/") {
            let tail = tail.trim_end_matches('/');
            return rel_str == tail
                || rel_str.ends_with(&format!("/{tail}"))
                || rel_str.starts_with(&format!("{tail}/"))
                || rel_str.contains(&format!("/{tail}/"));
        }
        // Plain sub-path: match from root.
        return rel_str == pattern || rel_str.starts_with(&format!("{pattern}/"));
    }

    // Wildcard filename: "*.snap", "*.golden" — match against the file name only.
    if let Some(suffix) = pattern.strip_prefix('*') {
        return rel
            .file_name()
            .map(|f| f.to_string_lossy().ends_with(suffix))
            .unwrap_or(false);
    }

    // Plain name (no slashes, no wildcards): match any path component so that
    // "tests", "fixtures", "vendor" etc. work regardless of nesting depth.
    rel.components()
        .any(|c| c.as_os_str().to_string_lossy() == pattern)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn check(path: &str, pattern: &str) -> bool {
        let rel = PathBuf::from(path);
        pattern_matches(path, &rel, pattern)
    }

    #[test]
    fn plain_name_matches_nested_dir() {
        assert!(check("tests/secrets.env", "tests"));
        assert!(check("src/tests/data.key", "tests"));
        assert!(!check("src/bestests/data.key", "tests"));
    }

    #[test]
    fn rooted_pattern_only_at_root() {
        assert!(check("tests/foo.key", "/tests"));
        assert!(!check("src/tests/foo.key", "/tests"));
    }

    #[test]
    fn wildcard_extension() {
        assert!(check("src/foo.snap", "*.snap"));
        assert!(check("tests/bar.golden", "*.golden"));
        assert!(!check("src/foo.snap.bak", "*.snap"));
    }

    #[test]
    fn double_star_prefix() {
        assert!(check("a/b/fixtures/secret.json", "**/fixtures"));
        assert!(check("fixtures/secret.json", "**/fixtures"));
    }

    #[test]
    fn negation_unignores() {
        let ignore = SecoxIgnore {
            entries: vec![
                (false, "tests".to_string()),
                (true, "tests/integration".to_string()),
            ],
        };
        let root = PathBuf::from("/repo");
        assert!(ignore.is_ignored(&PathBuf::from("/repo/tests/unit/key.env"), &root));
        assert!(!ignore.is_ignored(&PathBuf::from("/repo/tests/integration/key.env"), &root));
    }
}
