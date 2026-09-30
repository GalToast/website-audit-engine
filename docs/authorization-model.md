# Authorization Model

Website auditing is dual-use. This repo frames the tool as an authorized review system for owned, client-approved, or otherwise explicitly permitted targets.

## Allowed Target Classes

- Sites owned or operated by the user.
- Client sites covered by an active audit, maintenance, or discovery agreement.
- Public demo domains used only for local verification.
- Internal review queues where target provenance and permission have already been checked.

## Out of Scope

- Credentialed areas without explicit permission.
- Attempts to bypass authentication or access controls.
- Exploit development or destructive testing.
- Publishing private target lists, client run logs, credentials, cookies, or contact exports.
- Using batch automation against arbitrary third-party domains without review and authorization.

## What The Tool Does

The audit path checks public site behavior and review signals: transport/security headers, cookie hygiene, payment surface detection, runtime errors, selected sensitive-path exposure checks, Performance API signals (Core Web Vitals measured in-page, not a Lighthouse run), and confidence-tiered findings. Findings are treated as evidence for review, not proof of compromise.

## Operator Review

Batch output should be reviewed before any client-facing claim or outreach hook is written. The confidence tiers exist so weak heuristics stay separated from verified user-facing issues.
