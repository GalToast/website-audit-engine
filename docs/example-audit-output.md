# Example Audit Output (Redacted Sample)

> **This is an illustrative sample, not a real scan.** It shows the shape of what
> `node audit-lead.js 1234 example.com` emits to stdout, using `example.com`
> (the standard documentation domain) with representative values. A live run was
> not executed to produce this file. Cookie values, fingerprints, and any
> target-specific strings are redacted or omitted.

A real run prints the full result object as pretty-printed JSON to stdout
(`console.log(JSON.stringify(result, null, 2))`), and the GitHub Actions
workflow saves it as `audit-<leadId>.json`. In parallel, the auditor writes:

- `leads/profiles/<range>/<lead>/evidence/headers.txt` — raw response headers
- `leads/profiles/<range>/<lead>/evidence/cookies.json` — observed cookies
- `leads/profiles/<range>/<lead>/evidence/cookie-security.json` — cookie analysis
- `leads/profiles/<range>/<lead>/evidence/security-findings.md` — human-readable findings
- `ops/screenshots/<leadId>-*.png` — page screenshots
- `leads/profiles/<range>/<lead>/profile.md` — appended/updated run summary

## Sample JSON (trimmed to the interesting sections)

```json
{
  "leadId": "1234",
  "domain": "example.com",
  "testUrl": "https://example.com",
  "timestamp": "2026-09-30T12:00:00.000Z",
  "siteAvailability": { "reachable": true, "method": "https", "statusCode": 200 },
  "ssl": {
    "valid": true,
    "issuer": "[REDACTED]",
    "expires": "2027-06-01T00:00:00.000Z",
    "daysUntilExpiry": 244,
    "error": null
  },
  "https": { "enabled": true, "redirects": true, "error": null },
  "securityHeaders": {
    "strict-transport-security": { "present": true, "value": "[REDACTED]" },
    "content-security-policy": { "present": false, "value": null },
    "x-frame-options": { "present": true, "value": "[REDACTED]" },
    "x-content-type-options": { "present": false, "value": null },
    "referrer-policy": { "present": true, "value": "[REDACTED]" }
  },
  "cookies": [
    { "name": "sessionid", "domain": ".example.com", "secure": true, "httpOnly": true, "sameSite": "Lax" },
    { "name": "_ga", "domain": ".example.com", "secure": true, "httpOnly": false, "sameSite": "Lax" }
  ],
  "cookieSecurity": {
    "findings": [
      { "severity": "warning", "message": "Analytics cookie set without Secure/HttpOnly flags", "evidence": { "cookie": "_ga" } }
    ],
    "sessionCookies": ["sessionid"],
    "authCookies": [],
    "csrfCookies": [],
    "analyticsCookies": ["_ga"]
  },
  "mixedContent": { "found": false, "resources": [] },
  "consoleErrors": [],
  "consoleWarnings": [
    { "message": "Third-party script blocked by tracking blocker", "count": 1 }
  ],
  "performance": {
    "loadTime": 1240,
    "domContentLoaded": 810,
    "firstPaint": 620,
    "firstContentfulPaint": 705,
    "largestContentfulPaint": 1180,
    "cumulativeLayoutShift": 0.02,
    "interactionToNextPaint": null
  },
  "techStack": {
    "cms": null,
    "frameworks": [],
    "analytics": ["Google Analytics"],
    "hosting": []
  },
  "seo": {
    "title": "Example Domain",
    "metaDescription": null,
    "h1": "Example Domain",
    "h1Count": 1,
    "images": 0,
    "imagesWithoutAlt": 0,
    "links": 1,
    "canonical": null
  },
  "mobile": { "friendly": true, "viewport": "width=device-width, initial-scale=1", "navWorks": true },
  "paymentSecurity": {
    "hasPaymentSurface": false,
    "hostedThirdPartyCheckout": false,
    "onSiteCardCollectionForms": 0,
    "providers": [],
    "findings": []
  },
  "emailAuth": { "spf": null, "dmarc": null, "dkim": null },
  "findingConfidence": {
    "verified": [
      {
        "severity": "medium",
        "message": "Content-Security-Policy header is missing",
        "evidence": { "header": "content-security-policy", "source": "response-headers" }
      }
    ],
    "probable": [],
    "observedUnderInstrumentation": [],
    "unverified": [
      {
        "severity": "info",
        "message": "No explicit cookie-consent banner detected",
        "evidence": { "source": "dom-heuristic" }
      }
    ]
  },
  "auditScore": 90,
  "criticalIssues": [],
  "warnings": [
    "Content-Security-Policy header is missing",
    "X-Content-Type-Options header is missing"
  ]
}
```

## How to read it

- **`findingConfidence`** is the core design: `verified` findings are backed by direct
  observation (e.g. a header actually absent from the response); `probable` and
  `unverified` findings are weaker review signals a human operator should check.
  This separation is what `audit-lead.security.test.js` (27 tests) protects.
- **`auditScore`** starts at 100 and is decremented by weighted deductions
  (TLS failures, missing headers, insecure forms, etc.).
- **`performance`** numbers come from the browser Performance API
  (`performance.getEntriesByType("navigation" | "paint" | "largest-contentful-paint" | "layout-shift")`),
  not from Lighthouse — there is no Lighthouse dependency in this repo.
- **Persistence** is file-based: this JSON, the `evidence/` files, screenshots,
  and `profile.md`. There is no database backend.
