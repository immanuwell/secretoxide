![](media/secretoxide.png)

# secox

Finds secrets in your code. Then actually helps you fix them.

Every other scanner prints a list and walks away. secox stays — shows you the revocation steps, rewrites the file, checks git history, and if the damage is already in old commits, hands you the exact command to fix that too.

```bash
cargo install secox
secox init   # drop a pre-commit hook, done
```

---

## When a commit gets blocked

Run this:

```bash
secox resolve
```

For each finding you pick **r**, **a**, or **s**:

**r — rotate.** Shows the revocation URL + step-by-step for that provider (AWS, GitHub, Stripe, OpenAI, Anthropic, Slack, GitLab, and 15 more). Asks if you want the hardcoded value swapped for a proper env var reference in-file (`os.environ["KEY"]` for Python, `process.env.KEY` for JS/TS, `os.Getenv("KEY")` for Go, etc.). Then runs `git log -S` against your history — if the secret is already in old commits, you get the exact `git filter-repo` command to paste.

**a — allow.** False positive. Injects `# secox:allow` on that line. Never bothers you again.

**s — skip.** Deal with it later.

---

## Catches dangerous files before you even open them

secox flags sensitive filenames the moment they hit the staging area — no regex needed, no content to scan:

- `.env`, `.env.local`, `.env.production`, `.env.*`
- `id_rsa`, `id_ed25519`, `*.pem`, `*.p12`, `*.jks`
- `credentials.json`, `serviceAccountKey.json`, `terraform.tfvars`, `.netrc`, `.htpasswd`

Committing `id_rsa` is almost never intentional. Now it's blocked at `git commit` instead of discovered six months later in a security audit.

---

## Onboarding an existing repo without losing your mind

The first scan on a legacy codebase usually explodes with hundreds of stale findings. That's why people disable hooks. secox has a baseline:

```bash
secox baseline                           # snapshot everything that exists right now
git add .secox-baseline.json && git commit
```

From that point on, `secox scan` only shows **new** secrets — the ones you're about to add. Work through the old ones at your own pace with `secox resolve`, then refresh:

```bash
secox baseline --update                  # after rotating a batch
```

Commit the baseline file and the whole team shares the same suppression list.

---

## Fewer false positives than gitleaks / ripsecrets

Three layers before anything fires:

**1. Context-aware** — `os.getenv("SECRET")` is a lookup. `<YOUR_KEY_HERE>` is a placeholder. Values in test fixtures get downgraded. All skipped.

**2. Semantic checks** — entropy, character diversity, and a bigram filter that catches English prose sneaking through. `password = "These Are Just Words"` doesn't fire.

**3. Provider-level validation** — GitHub tokens have a CRC-32 checksum in the last 6 chars; secox validates it (fabricated tokens → Medium). AWS key suffixes get entropy-checked (`AKIAIOSFODNN7EXAMPLE` from the AWS docs is too repetitive, skipped). JWTs get their base64url header decoded — no `alg` field, not a JWT.

43 rules. Provider-specific ones fire only on their exact prefix+format. Generic ones (password, api_key, secret assignments) go through all three layers first.

---

## Suppress findings

One line:
```python
api_key = "sk-live-..."  # secox:allow
```

Whole file (add to the top):
```
# secox:allow-file
```

Whole directories — commit a `.secoxignore` (gitignore syntax):
```
vendor/
*.snap
tests/fixtures/
```

---

## Everything else

```bash
secox scan --git-history        # audit every past commit (slow, worth it once)
secox scan --format sarif       # GitHub Code Scanning
secox scan --format json        # pipe to jq / ship to SIEM
secox scan --no-fail            # advisory mode, exits 0
secox init --global             # one hook for every repo on the machine
```

`secox <command> --help` has examples for everything.
