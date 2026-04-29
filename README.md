# Website Audit Engine

Automated security and performance auditor for website assessment at scale. Built with Playwright.

## What It Checks

**Security** (80+ checks)
- SSL/TLS configuration and certificate validity
- Security headers (CSP, HSTS, X-Frame-Options, etc.)
- Cookie hygiene and session token handling
- Payment surface classification (Stripe, PayPal, Square, Braintree)
- CSRF truthfulness verification
- Environment file (.env) exposure
- Sensitive path detection (.git, .htpasswd, config backups)

**Performance**
- Core Web Vitals benchmarking
- Lighthouse accessibility scoring

**Automation**
- Dual-mode browser automation (light and heavy evasion)
- Concurrent domain scanning with runtime error recovery
- Confidence-tiered results (Diamond / Gold / Standard)
- Batch GitHub Actions workflow for large-scale audits
- Audit results persisted to SQLite

## Usage

```bash
# Single domain audit
node audit-lead.js --domain example.com

# Run all tests (including security)
node audit-lead.security.test.js

# Trigger GitHub Actions batch
pwsh run-audit-gh.ps1 -Repo "owner/repo" -Domain "example.com"
```

## Configuration

Copy `.env.example` to `.env` and set your API keys:
- `AUDIT_ENCRYPTION_KEY` — for GitHub Actions secrets

GitHub Actions secrets required:
- `AUDIT_ENCRYPTION_KEY`

## Architecture

- `audit-lead.js` — main auditor
- `audit-lead.security.test.js` — security test suite
- `batch-audit-gh.ps1` — batch orchestrator
- `run-audit-gh.ps1` — single-run GitHub Actions trigger
- `.github/workflows/audit-lead.yml` — CI/CD workflow
