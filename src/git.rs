use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::types::Finding;

pub fn find_git_root(start: &Path) -> Option<PathBuf> {
    let mut dir = start.to_path_buf();
    loop {
        if dir.join(".git").is_dir() {
            return Some(dir);
        }
        if !dir.pop() {
            return None;
        }
    }
}

pub fn uses_precommit_framework(repo_root: &Path) -> bool {
    repo_root.join(".pre-commit-config.yaml").exists()
        || repo_root.join(".pre-commit-config.yml").exists()
}

pub fn hook_path(repo_root: &Path) -> PathBuf {
    repo_root.join(".git").join("hooks").join("pre-commit")
}

const HOOK_MARKER: &str = "# secox-managed";

const HOOK_SCRIPT: &str = r#"# secox-managed — secret scanner pre-commit hook
# To bypass (not recommended): git commit --no-verify

if command -v secox >/dev/null 2>&1; then
    secox scan --staged
    status=$?
    if [ $status -ne 0 ]; then
        echo ""
        echo "secox: commit blocked. Fix the above findings before committing."
        echo "       To suppress a false positive, add  # secox:ignore  to that line."
        echo "       To skip this check (NOT recommended): git commit --no-verify"
        exit 1
    fi
else
    echo "secox: not found in PATH — skipping secret scan."
    echo "       Install: cargo install secox"
fi
"#;

pub fn install_hook(repo_root: &Path) -> Result<()> {
    let hook = hook_path(repo_root);

    if hook.exists() {
        let existing = std::fs::read_to_string(&hook)?;
        if existing.contains(HOOK_MARKER) {
            println!("secox: pre-commit hook already installed.");
            return Ok(());
        }
        let appended = format!("{existing}\n{HOOK_SCRIPT}");
        std::fs::write(&hook, appended)?;
    } else {
        std::fs::create_dir_all(hook.parent().unwrap())?;
        std::fs::write(&hook, format!("#!/bin/sh\n{HOOK_SCRIPT}"))?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&hook)?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&hook, perms)?;
    }

    Ok(())
}

pub fn uninstall_hook(repo_root: &Path) -> Result<()> {
    let hook = hook_path(repo_root);
    if !hook.exists() {
        println!("secox: no hook found.");
        return Ok(());
    }

    let content = std::fs::read_to_string(&hook)?;
    if !content.contains(HOOK_MARKER) {
        println!("secox: hook was not installed by secox, leaving untouched.");
        return Ok(());
    }

    let stripped = if let Some(idx) = content.find(&format!("# {HOOK_MARKER}")) {
        content[..idx].to_string()
    } else {
        content
    };

    if stripped.trim().is_empty() || stripped.trim() == "#!/bin/sh" {
        std::fs::remove_file(&hook)?;
    } else {
        std::fs::write(&hook, stripped)?;
    }

    Ok(())
}

pub fn scan_history(_repo_root: &Path) -> Result<Vec<Finding>> {
    Ok(vec![]) // TODO: implement in upcoming commit
}
