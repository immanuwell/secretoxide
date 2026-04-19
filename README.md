![](media/secretoxide.png)

# secox

Finds secrets in your code. Then actually helps you fix them.

Every other scanner prints a list and walks away. secox stays — shows revocation steps, rewrites the file for you, checks if the damage is already in git history. That last part is where most incidents go sideways, so.

```bash
cargo install secox
```

---

## Basics

```bash
secox init            # drop a pre-commit hook in .git/hooks
secox scan            # scan everything
secox scan --staged   # only what you're about to commit (fast)
```

Install the hook once and forget about it. Runs on every `git commit` automatically.

---

## When a commit gets blocked — this is the good part

```bash
secox resolve
```

For each finding you pick **r**, **a**, or **s**.

**r — rotate.** Pulls up the exact revocation URL for that provider (AWS, GitHub, Stripe, OpenAI, Anthropic, Slack, GitLab, and 12 more). Walks you through the steps. Then asks if you want the hardcoded value swapped for a proper env var reference right in the file — `os.environ["KEY"]` for Python, `process.env.KEY` for JS/TS, `os.Getenv("KEY")` for Go, etc. Then it checks git history with `git log -S`, and if the secret is already baked into past commits, hands you the ready-to-copy `git filter-repo` command.

**a — allow.** False positive. Injects `# secox:allow` on that line. Never asks again.

**s — skip.** Come back later (it'll keep blocking until you do).

---

## Fewer false positives than gitleaks / ripsecrets

Three layers before anything actually fires:

**1. Context-aware** — `os.getenv("SECRET")` is a lookup, not a leak. `<YOUR_KEY_HERE>` is a placeholder. Values inside test fixtures get downgraded. All of these are skipped.

**2. Semantic checks** — entropy, character diversity, and a bigram filter that catches natural-language prose sneaking through. `password = "These Are Just Words"` doesn't fire.

**3. Provider-level validation** — GitHub tokens carry a CRC-32 checksum in the last 6 chars; secox validates it (fabricated tokens get downgraded to Medium). AWS key suffixes get entropy-checked (the famous `AKIAIOSFODNN7EXAMPLE` from AWS docs? too repetitive, skipped). JWTs get their base64url header decoded — no `alg` field means it's not a JWT, skip.

43 rules total. Provider-specific ones only fire on their exact format. Generic ones (password, api_key, secret assignments) go through all three layers first.

---

## Suppress findings

One line — add to the end of it:
```python
api_key = "sk-live-..."  # secox:allow
```

Whole file — add to the top:
```
# secox:allow-file
```

Whole directories / patterns — commit a `.secoxignore` (gitignore syntax):
```
vendor/
*.snap
tests/fixtures/
```

Or pass `--ignore` at the CLI for one-offs:
```bash
secox scan --ignore "*.snap" --ignore vendor/
```

---

## Audit git history

```bash
secox scan --git-history
```

Slow on big repos. Worth running once before open-sourcing something.

---

## CI / CD

```bash
secox scan --format sarif    # GitHub Code Scanning
secox scan --format json     # pipe to jq, ship to your SIEM, whatever
secox scan --no-fail         # advisory — logs findings but exits 0
```

---

## Global hook (install once, covers every repo)

```bash
secox init --global
```

Sets `core.hooksPath`. Every repo on the machine is covered from that point, no per-project setup.

---

## All commands

```
secox init [--global] [--uninstall]
secox scan [PATH] [--staged] [--git-history] [--format text|json|sarif]
           [--include-low] [--no-fail] [--ignore PATTERN]
secox resolve [--no-staged]
secox rules [--format text|json]
```

`secox <command> --help` has examples for everything.
