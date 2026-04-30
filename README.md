# Website Audit Engine

Evidence-tiered website security and performance auditor built with Playwright.

This repo demonstrates practical automation around messy public websites: browser-driven checks, security-header review, payment surface detection, confidence-ranked findings, SQLite persistence, and GitHub Actions batch runs. The goal is not to produce noisy scanner output; it is to separate verified, user-facing issues from weaker review signals.

## Why It Matters

- Runs repeatable audits across many domains without losing per-site evidence.
- Keeps security, performance, accessibility, and runtime errors in one review path.
- Uses confidence tiers so an operator can tell the difference between "verified issue" and "needs human review."
- Supports both local investigation and GitHub Actions batch execution.

## Proof Artifacts

| Artifact | What it shows |
| --- | --- |
| `audit-lead.security.test.js` | Security boundary tests and confidence-tier behavior |
| `audit-lead.js` | Browser automation, evidence capture, and audit orchestration |
| `.github/workflows/audit-lead.yml` | Batchable GitHub Actions audit workflow |
| `batch-audit-gh.ps1` | Multi-domain orchestration path |

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

## Recruiter Reading Guide

Start with `audit-lead.security.test.js` for the security boundary design, then read `audit-lead.js` for the browser automation and evidence model. The interesting engineering is the confidence discipline: findings are useful because they are tiered, not because every heuristic is treated as truth.
