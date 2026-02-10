# envguard

![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)

A secret scanner for codebases. Detect leaked API keys, tokens, passwords, and credentials before they reach production.

## Why This Matters

Secret leaks are one of the most common and costly security failures in software development. A single committed API key can lead to unauthorized access, data breaches, and thousands of dollars in fraudulent charges -- often within minutes of being pushed to a public repository.

`envguard` catches these mistakes at the source: in your local codebase and CI/CD pipeline, before secrets ever reach version control.

## Installation

```bash
# Clone the repository
git clone https://github.com/orianna1510-code/envguard.git
cd envguard

# Install in development mode
pip install -e ".[dev]"
```

## Usage

### Scan a directory

```bash
# Scan the current directory
envguard scan .

# Scan a specific project
envguard scan ./my-project
```

### Filter by severity

```bash
# Only show high and critical findings
envguard scan . --severity high

# Only show critical findings
envguard scan . --severity critical
```

### Machine-readable output

```bash
# JSON output (for scripting and dashboards)
envguard scan . --json

# SARIF output (for GitHub Code Scanning integration)
envguard scan . --sarif
```

### Example output

```
                          Secrets Detected
+-----------+--------------------+------------------+------+------------------+
| Severity  | Rule               | File             | Line | Match            |
+-----------+--------------------+------------------+------+------------------+
| CRITICAL  | openai-api-key     | config/.env      |    3 | sk-proj-*****   |
| CRITICAL  | aws-access-key     | config/.env      |    5 | AKIAFAKE*****   |
| CRITICAL  | database-url       | settings.py      |   12 | postgres:*****  |
| HIGH      | github-token       | deploy.sh        |    8 | ghp_fake*****   |
| MEDIUM    | generic-secret     | app/config.py    |   22 | secret_k*****   |
+-----------+--------------------+------------------+------+------------------+

Total: 5 finding(s) -- 3 CRITICAL | 1 HIGH | 1 MEDIUM
```

### CI/CD exit codes

`envguard` returns exit code **1** when secrets are found, making it easy to use as a CI gate:

```bash
envguard scan . || echo "Secrets detected -- blocking deployment"
```

## What It Detects

| Rule | Severity | Example Pattern |
|------|----------|-----------------|
| OpenAI API key | Critical | `sk-...` |
| Anthropic API key | Critical | `sk-ant-...` |
| AWS Access Key | Critical | `AKIA...` |
| GitHub token | High | `ghp_...`, `gho_...`, `github_pat_...` |
| Stripe secret key | Critical | `sk_live_...`, `sk_test_...` |
| Stripe publishable key | Low | `pk_live_...`, `pk_test_...` |
| Slack token | High | `xoxb-...`, `xoxp-...` |
| JWT token | High | `eyJ...` (three Base64 segments) |
| Private key header | Critical | `-----BEGIN RSA PRIVATE KEY---` |
| Database URL | Critical | `protocol://user:pass@host` (postgres, mysql, mongodb, redis) |
| Generic API key | High | `API_KEY = "..."` |
| Generic secret | Medium | `password = "..."`, `token = "..."` |

## Configuration

### Suppressing false positives

Create a `.envguardrc` file in your project root to allowlist known safe patterns:

```json
{
    "allowlist": [
        {
            "path": "tests/fixtures/",
            "reason": "Test fixtures contain intentionally fake secrets"
        },
        {
            "rule": "stripe-publishable-key",
            "reason": "Publishable keys are safe to commit per Stripe docs"
        },
        {
            "rule": "generic-secret",
            "path": "docs/examples/",
            "reason": "Documentation examples use placeholder values"
        }
    ]
}
```

Each allowlist entry supports:
- `rule` -- match a specific rule name (optional)
- `path` -- match files whose path starts with this prefix (optional)
- `reason` -- human-readable explanation (optional but recommended)

### Respecting .gitignore

`envguard` automatically reads your project's `.gitignore` and skips files that git would ignore. It also skips common non-source directories (`node_modules`, `.git`, `__pycache__`, etc.) and binary file types.

## CI/CD Integration

### GitHub Actions

```yaml
name: Secret Scan

on: [push, pull_request]

jobs:
  envguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install envguard
        run: pip install git+https://github.com/orianna1510-code/envguard.git

      - name: Scan for secrets
        run: envguard scan .

      # Optional: upload SARIF to GitHub Code Scanning
      - name: Generate SARIF report
        if: always()
        run: envguard scan . --sarif > results.sarif || true

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### Pre-commit hook

```bash
#!/bin/sh
# .git/hooks/pre-commit
envguard scan . --severity high
```

## Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run tests with coverage
pytest --cov=envguard --cov-report=term-missing
```

## Architecture

```
envguard/
    cli.py        -- Click CLI entry point
    scanner.py    -- Core scanning engine (directory walking + rule matching)
    rules.py      -- Secret pattern definitions (regex rules with severity)
    gitignore.py  -- .gitignore parser for file exclusion
    allowlist.py  -- .envguardrc allowlist handling
    reporter.py   -- Output formatting (text, JSON, SARIF)
```

The scanner is fully decoupled from output formatting. Rules are defined as data (not code), making them easy to extend. The allowlist system lets teams adopt envguard incrementally without being blocked by false positives.

## License

MIT
