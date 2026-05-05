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
| `docs/authorization-model.md` | Authorization, target, and dual-use safety boundary for audit runs |
| `docs/architecture-map.md` | Reviewer map for the large operational auditor file |
| `.github/workflows/audit-lead.yml` | Batchable GitHub Actions audit workflow |
| `batch-audit-gh.ps1` | Multi-domain orchestration path |

## What It Checks

**Security**
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
- Browser automation with a light default mode and heavier compatibility handling for sites that block ordinary inspection
- Concurrent domain scanning with runtime error recovery
- Confidence-tiered results (Diamond / Gold / Standard)
- Batch GitHub Actions workflow for large-scale audits
- Audit results persisted to SQLite

## Usage

```bash
# Install dependencies
npm install
npx playwright install chromium

# Self-contained verification
npm test

# Single domain audit
node audit-lead.js 1234 example.com

# Trigger GitHub Actions batch
pwsh ./run-audit-gh.ps1 -LeadId "1234" -Domain "example.com"
```

## Configuration

`npm test` is the fastest first click: it runs the confidence-tier and security-boundary tests without launching a browser. Local single-domain audits do not require API keys, but full profile output assumes a lead/profile workspace such as `leads/profiles/<range>/<lead>/profile.md`. GitHub Actions artifact encryption uses the `AUDIT_ENCRYPTION_KEY` repository secret.

## Authorization Boundary

This is an authorized-audit tool, not an open-ended reconnaissance system. It is intended for owned sites, client-authorized sites, and explicitly approved review queues. Batch runs should use target lists with prior authorization, and public outputs should avoid publishing private target lists, credentials, raw logs, or exploit instructions. See `docs/authorization-model.md`.

## Architecture

- `audit-lead.js` — main auditor
- `audit-lead.security.test.js` — security test suite
- `docs/authorization-model.md` — authorized-use and target-boundary model
- `docs/architecture-map.md` — map of the main auditor's regions and review path
- `batch-audit-gh.ps1` — batch orchestrator
- `run-audit-gh.ps1` — single-run GitHub Actions trigger
- `.github/workflows/audit-lead.yml` — CI/CD workflow

The main auditor is currently a large operational integration file. That is a conscious public-snapshot tradeoff: the working CLI/GitHub Actions path and the security-boundary exports remain together while the test suite protects the highest-risk confidence logic. See `docs/architecture-map.md` before reviewing `audit-lead.js` directly.

## Recruiter Reading Guide

Start with `audit-lead.security.test.js` for the security boundary design, then read `docs/architecture-map.md` before opening `audit-lead.js`. The interesting engineering is the confidence discipline: findings are useful because they are tiered, not because every heuristic is treated as truth.
