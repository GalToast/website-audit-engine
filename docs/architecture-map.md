# Website Audit Engine Architecture Map

`audit-lead.js` is intentionally kept as a single operational auditor in this public snapshot so the GitHub Actions workflow, local CLI path, and security test exports stay easy to inspect together. This map gives reviewers a fast index into the file and separates the major concerns.

## Main Regions

| Region | Approx. lines | Responsibility |
| --- | ---: | --- |
| Browser setup and compatibility scripts | 1-790 | Playwright setup, tracking blocker, bot-blocker detection, alternate URL/user-agent handling, and CLI target normalization |
| Security dictionaries and result model | 924-1344 | Header definitions, technology signatures, sensitive paths/files, API-key pattern detection, social patterns, and the normalized audit result shape |
| Confidence and scoring helpers | 1355-2377 | Cookie classification, payment/security context, admin/DKIM review summaries, outreach summary logic, confidence-tier assignment, and scanner-noise suppression |
| Availability and transport checks | 2392-2812 | JavaScript verification pass, DNS/site availability, TLS certificate review, HTTPS redirect checks, and actionable broken-link filtering |
| Sanitization and enrichment model | 2825-3786 | Business/contact/address/social sanitization, enrichment field trust levels, security autofill export, and lead enrichment assembly |
| Page analysis probes | 3786-5228 | Email authentication, technology fingerprinting, forms, third-party scripts, DNS records, admin endpoints, and tech-stack detection |
| Report generation | 5228-5981 | Audit score calculation and profile-section rendering |
| Contact and business extraction | 5981-7906 | Contacts, address, business info, broken links, ecommerce, social profiles, team info, growth signals, reputation, newsletter, age, industry, and service area |
| Runtime orchestration | 7906-end | Full audit execution flow, desktop/mobile passes, evidence capture, persistence/export, and module exports used by tests |

## Review Path

For a fast technical review:

1. Start with `audit-lead.security.test.js` to see the intended security boundaries.
2. Read the confidence helpers around cookie, payment, CSRF, admin, DKIM, and review-queue logic.
3. Skim the page analysis probes for browser automation breadth.
4. Use this file only after the README and tests; the auditor is an operational integration script, not a small library API.

The database-URI rules in the API-key pattern dictionary are page-source exposure checks. For example, the MongoDB rule flags delivered `mongodb://` or `mongodb+srv://` strings with embedded credentials as a critical secret-looking artifact; it does not imply this repository runs a MongoDB backend.

## Why Not Split Yet?

The next maintainability step is to extract these regions into modules, but the current public version favors traceability of the working audit path over a large refactor. The test suite protects the most sensitive boundary behavior while that extraction remains future work.
