const test = require("node:test");
const assert = require("node:assert/strict");

const {
  extractApiKeysFromPageContent,
  analyzeCookieSecurity,
  analyzePaymentSecurity,
  buildDkimReviewSummary,
  buildReviewQueueHighlights,
  buildLeadEnrichment,
  buildConfidenceFindings,
  buildSecurityOutreachSummary,
  calculateAuditScore,
  generateProfileSection,
  getMissingHeaderSeverity,
} = require("./audit-lead.js");

function createBaseResult(overrides = {}) {
  return {
    domain: "example.com",
    siteAvailability: { reachable: true, method: "https", statusCode: 200 },
    ssl: {
      valid: true,
      issuer: "Test CA",
      expires: "2099-01-01T00:00:00.000Z",
      daysUntilExpiry: 365,
      error: null,
      authorizationError: null,
      hostnameError: null,
    },
    https: { enabled: true, redirects: true, statusCode: 301, location: "https://example.com/" },
    securityHeaders: {
      "strict-transport-security": { present: true, value: "max-age=31536000" },
      "content-security-policy": { present: true, value: "default-src 'self'" },
      "x-frame-options": { present: true, value: "SAMEORIGIN" },
      "x-content-type-options": { present: true, value: "nosniff" },
      "referrer-policy": { present: true, value: "strict-origin-when-cross-origin" },
      "permissions-policy": { present: true, value: "geolocation=()" },
      "x-xss-protection": { present: false, value: null },
    },
    mixedContent: { found: false, resources: [] },
    emailAuth: {
      spf: "v=spf1 include:_spf.example.com ~all",
      dmarc: "v=DMARC1; p=none;",
      dkim: null,
      dkimDetectionMethod: "common-selector-guess",
      dkimCheckedSelectors: ["default", "selector1"],
    },
    dnsRecords: { mx: [], ns: [], a: ["203.0.113.10"] },
    contacts: { emails: [], phones: [] },
    cookies: [],
    cookieSecurity: { findings: [], sessionCookies: [], authCookies: [], csrfCookies: [], analyticsCookies: [] },
    seoFiles: { robotsTxt: null, sitemap: null },
    paymentSecurity: { hasPaymentSurface: false, hostedThirdPartyCheckout: false, onSiteCardCollectionForms: 0, providers: [], findings: [] },
    securityOutreach: { primaryHook: null, verifiedHooks: [], probableHooks: [] },
    sensitiveExposures: {
      sensitiveFiles: [],
      exposedGit: false,
      exposedEnv: false,
      exposedConfig: false,
      apiKeys: [],
      riskyEndpoints: [],
    },
    forms: {
      issues: [],
      forms: [],
      totalForms: 0,
    },
    brokenImages: ["https://example.com/broken.png"],
    brokenLinks: {
      broken: [{ url: "https://external.example/bad", status: 404, internal: false }],
    },
    jsErrorAnalysis: {
      verifiedPageErrors: [],
      verifiedConsoleErrors: [],
      scannerInducedPageErrors: [],
      scannerInducedConsoleErrors: [],
      provisionalPageErrors: [],
      provisionalConsoleErrors: [],
    },
    botBlocker: { detected: false, blocked: false, bypassed: false, name: null },
    renderTimeout: false,
    criticalIssues: [],
    warnings: [],
    findingConfidence: {
      verified: [],
      probable: [],
      observedUnderInstrumentation: [],
      unverified: [],
    },
    ...overrides,
  };
}

test("public identifiers stay informational and generic public-token contexts are suppressed", () => {
  const exampleStripeKey = `pk_live_${"123456789012345678901234"}`;
  const exampleTwilioSid = `AC${"0123456789abcdef0123456789abcdef"}`;
  const findings = extractApiKeysFromPageContent(`
    const stripeKey = "${exampleStripeKey}";
    const twilioSid = "${exampleTwilioSid}";
    const publicConfig = { access_token: "widget-public-token-1234567890" };
  `);

  assert.ok(findings.some((entry) => entry.type === "Stripe Live Publishable Key" && entry.severity === "info"));
  assert.ok(findings.some((entry) => entry.type === "Twilio Account SID" && entry.severity === "info"));
  assert.equal(findings.some((entry) => entry.type === "Access Token"), false);
});

test("confidence findings keep runtime noise and non-security gaps out of verified security claims", () => {
  const result = createBaseResult({
    brokenImages: ["https://example.com/broken.png"],
    brokenLinks: { broken: [{ url: "/bad", status: 404, internal: true }] },
    jsErrorAnalysis: {
      verifiedPageErrors: [{ message: "TypeError: boom", count: 1 }],
      verifiedConsoleErrors: [{ message: "Failed to load resource", count: 1 }],
      scannerInducedPageErrors: [],
      scannerInducedConsoleErrors: [],
      provisionalPageErrors: [],
      provisionalConsoleErrors: [],
    },
  });

  buildConfidenceFindings(result);

  assert.equal(result.findingConfidence.verified.some((entry) => /broken image|broken link|robots|sitemap/i.test(entry.message)), false);
  assert.equal(result.findingConfidence.verified.some((entry) => /Verified page error|Verified console error/i.test(entry.message)), false);
  assert.ok(result.findingConfidence.unverified.some((entry) => /Reproducible runtime error observed/i.test(entry.message)));
  assert.ok(result.findingConfidence.unverified.some((entry) => /Reproducible console error observed/i.test(entry.message)));
});

test("security score ignores general UX and SEO noise but still responds to concrete transport issues", () => {
  const mostlyNoise = createBaseResult({
    mobile: { friendly: false },
    seo: { title: null, metaDescription: null, h1Count: 0, imagesWithoutAlt: 5 },
    brokenImages: ["https://example.com/broken.png"],
    brokenLinks: { broken: [{ url: "/bad", status: 404, internal: true }] },
    contacts: { emails: [], phones: [] },
    cookieConsent: { detected: true, type: "banner" },
  });

  const withTransportFailure = createBaseResult({
    ssl: {
      valid: false,
      issuer: null,
      expires: null,
      daysUntilExpiry: null,
      error: "CERT_HAS_EXPIRED",
      authorizationError: "CERT_HAS_EXPIRED",
      hostnameError: null,
    },
  });

  assert.equal(calculateAuditScore(mostlyNoise), 100);
  assert.ok(calculateAuditScore(withTransportFailure) < 100);
});

test("cookie analysis distinguishes session risk from benign analytics cookies", () => {
  const analysis = analyzeCookieSecurity([
    { name: "connect.sid", domain: "example.com", secure: false, httpOnly: false, sameSite: null },
    { name: "XSRF-TOKEN", domain: "example.com", secure: false, httpOnly: false, sameSite: "Lax" },
    { name: "_ga", domain: "example.com", secure: false, httpOnly: false, sameSite: "Lax" },
  ]);

  assert.ok(analysis.sessionCookies.includes("connect.sid"));
  assert.ok(analysis.csrfCookies.includes("XSRF-TOKEN"));
  assert.ok(analysis.analyticsCookies.includes("_ga"));
  assert.ok(analysis.findings.some((finding) => /missing Secure flag: connect\.sid/i.test(finding.message) && finding.tier === "verified"));
  assert.ok(analysis.findings.some((finding) => /readable by client script: connect\.sid/i.test(finding.message) && finding.tier === "probable"));
  assert.equal(analysis.findings.some((finding) => /_ga/i.test(finding.message)), false);
});

test("ambiguous marketing session cookies do not become auth/session findings without stronger evidence", () => {
  const analysis = analyzeCookieSecurity([
    { name: "sbjs_session", domain: "example.com", secure: false, httpOnly: false, sameSite: null },
    { name: "_scc_session", domain: "example.com", secure: false, httpOnly: false, sameSite: null },
  ], createBaseResult());

  assert.ok(analysis.analyticsCookies.includes("sbjs_session"));
  assert.ok(analysis.analyticsCookies.includes("_scc_session"));
  assert.equal(analysis.sessionCookies.includes("sbjs_session"), false);
  assert.equal(analysis.sessionCookies.includes("_scc_session"), false);
  assert.equal(analysis.findings.length, 0);
});

test("custom session-like cookies need positive context before they become findings", () => {
  const weakContext = analyzeCookieSecurity([
    { name: "portal_session", domain: "example.com", secure: true, httpOnly: false, sameSite: "Lax" },
  ], createBaseResult());
  const strongContext = analyzeCookieSecurity([
    { name: "portal_session", domain: "example.com", secure: false, httpOnly: true, sameSite: "Lax" },
  ], createBaseResult({
    forms: {
      issues: [],
      forms: [{ hasPasswordField: true, hasCreditCardField: false, hasSsnField: false, action: "/account/login" }],
      totalForms: 1,
    },
    adminEndpoints: { found: [{ path: "/login", status: 200 }], accessible: [] },
    techStack: { backend: "Node.js", frameworks: ["Next.js"] },
  }));

  assert.equal(weakContext.sessionCookies.includes("portal_session"), false);
  assert.equal(strongContext.sessionCookies.includes("portal_session"), true);
  assert.ok(strongContext.findings.some((finding) => /missing Secure flag: portal_session/i.test(finding.message)));
});

test("generic token cookies stay quiet without authenticated context", () => {
  const analysis = analyzeCookieSecurity([
    { name: "token", domain: "example.com", secure: false, httpOnly: false, sameSite: null },
  ], createBaseResult());

  assert.equal(analysis.authCookies.includes("token"), false);
  assert.equal(analysis.sessionCookies.includes("token"), false);
  assert.equal(analysis.findings.length, 0);
});

test("framework noise cookies do not become session findings just because they look stateful", () => {
  const analysis = analyzeCookieSecurity([
    { name: "__stripe_mid", domain: "example.com", secure: false, httpOnly: false, sameSite: "Lax" },
    { name: "cf_clearance", domain: "example.com", secure: false, httpOnly: false, sameSite: "Lax" },
    { name: "_shopify_sa_t", domain: "example.com", secure: false, httpOnly: false, sameSite: "Lax" },
  ], createBaseResult({
    forms: {
      issues: [],
      forms: [{ hasPasswordField: true, hasCreditCardField: false, hasSsnField: false, action: "/account/login" }],
      totalForms: 1,
    },
  }));

  assert.equal(analysis.sessionCookies.length, 0);
  assert.equal(analysis.authCookies.length, 0);
  assert.equal(analysis.findings.length, 0);
});

test("checkout context alone does not promote ambiguous auth cookies", () => {
  const analysis = analyzeCookieSecurity([
    { name: "checkout_token", domain: "example.com", secure: true, httpOnly: true, sameSite: "Lax" },
  ], createBaseResult({
    forms: {
      issues: [],
      forms: [{ hasPasswordField: false, hasCreditCardField: true, hasSsnField: false, action: "/checkout" }],
      totalForms: 1,
    },
    techStack: { backend: "Node.js", frameworks: ["Next.js"] },
  }));

  assert.equal(analysis.authCookies.includes("checkout_token"), false);
  assert.equal(analysis.sessionCookies.includes("checkout_token"), false);
  assert.equal(analysis.findings.length, 0);
});

test("payment analysis separates hosted trusted checkout from on-site card collection", () => {
  const hosted = analyzePaymentSecurity(createBaseResult({
    leadIntelligence: { ecommerce: { detected: true, paymentMethods: ["stripe"] } },
    forms: {
      forms: [
        { isCrossOrigin: true, crossOriginTrusted: true, hasCreditCardField: true, crossOriginTarget: "https://checkout.stripe.com" },
      ],
    },
  }));
  const onsite = analyzePaymentSecurity(createBaseResult({
    leadIntelligence: { ecommerce: { detected: false, paymentMethods: [] } },
    forms: {
      forms: [
        { isCrossOrigin: false, crossOriginTrusted: false, hasCreditCardField: true },
      ],
    },
  }));

  assert.equal(hosted.hostedThirdPartyCheckout, true);
  assert.equal(hosted.paymentFlowType, "hosted-third-party-checkout");
  assert.ok(hosted.findings.some((finding) => /hosted or third-party payment flow/i.test(finding.message)));
  assert.equal(onsite.onSiteCardCollectionForms, 1);
  assert.equal(onsite.paymentFlowType, "apparent-on-site-card-collection");
  assert.ok(onsite.findings.some((finding) => /apparent on-site card collection/i.test(finding.message)));
});

test("payment analysis distinguishes embedded trusted widgets from apparent on-site card collection", () => {
  const embedded = analyzePaymentSecurity(createBaseResult({
    leadIntelligence: { ecommerce: { detected: true, paymentMethods: ["stripe"] } },
    thirdPartyScripts: {
      total: 1,
      firstParty: [],
      thirdParty: [],
      categories: {
        payment: [{ name: "Stripe", domain: "js.stripe.com" }],
      },
    },
    forms: {
      forms: [
        {
          isCrossOrigin: false,
          crossOriginTrusted: false,
          hasCreditCardField: true,
          action: "/checkout",
          fields: [
            { name: "cardNumber" },
            { name: "payment_method" },
          ],
          hiddenFields: [
            { name: "payment_intent_client_secret", valuePreview: "pi_123_secret_456" },
          ],
        },
      ],
    },
  }));

  assert.equal(embedded.embeddedTrustedWidget, true);
  assert.equal(embedded.onSiteCardCollectionForms, 0);
  assert.equal(embedded.paymentFlowType, "embedded-trusted-widget");
  assert.ok(embedded.findings.some((finding) => /embedded trusted payment widget/i.test(finding.message)));
});

test("header severity increases when sensitive surfaces are present", () => {
  const lowRisk = createBaseResult();
  const highRisk = createBaseResult({
    forms: {
      issues: [],
      forms: [{ hasPasswordField: true, hasCreditCardField: false, hasSsnField: false }],
      totalForms: 1,
    },
    cookieSecurity: {
      findings: [],
      sessionCookies: ["connect.sid"],
      authCookies: [],
      csrfCookies: [],
      analyticsCookies: [],
    },
  });

  assert.equal(getMissingHeaderSeverity("strict-transport-security", lowRisk), "info");
  assert.equal(getMissingHeaderSeverity("strict-transport-security", highRisk), "warning");
  assert.equal(getMissingHeaderSeverity("x-frame-options", highRisk), "warning");
});

test("outreach summary favors verified higher-signal hooks and suppresses low-value header gaps", () => {
  const result = createBaseResult({
    findingConfidence: {
      verified: [
        { severity: "info", message: "Missing security header: permissions-policy" },
        { severity: "warning", message: "Missing security header: content-security-policy" },
        { severity: "warning", message: "Mixed content detected (1 HTTP resource(s))" },
      ],
      probable: [
        { severity: "warning", message: "Session/auth cookie readable by client script: connect.sid" },
      ],
      observedUnderInstrumentation: [],
      unverified: [],
    },
  });

  const summary = buildSecurityOutreachSummary(result);
  assert.equal(summary.primaryHook, "Missing security header: content-security-policy");
  assert.equal(summary.verifiedHooks.includes("Missing security header: permissions-policy"), false);
  assert.ok(summary.verifiedHooks.includes("Mixed content detected (1 HTTP resource(s))"));
  assert.ok(summary.probableHooks.includes("Session/auth cookie readable by client script: connect.sid"));
});

test("weak CSRF observations stay unverified informational notes", () => {
  const result = createBaseResult({
    forms: {
      issues: ["INFO: POST form has no visible CSRF token; authenticated state-changing context not verified"],
      forms: [{ method: "POST", hasPasswordField: false, hasCreditCardField: false, hasSsnField: false }],
      totalForms: 1,
    },
  });

  buildConfidenceFindings(result);

  assert.equal(result.findingConfidence.probable.some((entry) => /csrf/i.test(entry.message)), false);
  assert.ok(result.findingConfidence.unverified.some((entry) => /no visible CSRF token/i.test(entry.message)));
});

test("stronger CSRF issues can still rise above review-only when state-changing context is explicit", () => {
  const result = createBaseResult({
    forms: {
      issues: ["Form 1: MEDIUM: POST form missing CSRF token"],
      forms: [{
        method: "POST",
        hasPasswordField: true,
        hasCreditCardField: false,
        hasSsnField: false,
        action: "/account/password",
      }],
      totalForms: 1,
    },
  });

  buildConfidenceFindings(result);

  assert.ok(result.findingConfidence.probable.some((entry) => /POST form missing CSRF token/i.test(entry.message)));
  assert.equal(result.findingConfidence.unverified.some((entry) => /POST form missing CSRF token/i.test(entry.message)), false);
});

test("medium exposed operational endpoints stay informational instead of becoming probable security claims", () => {
  const result = createBaseResult({
    sensitiveExposures: {
      sensitiveFiles: [],
      exposedGit: false,
      exposedEnv: false,
      exposedConfig: false,
      apiKeys: [],
      riskyEndpoints: [
        { path: "/server-status", type: "server", severity: "medium", status: 200, reportOnly: false },
      ],
    },
  });

  buildConfidenceFindings(result);

  assert.equal(result.findingConfidence.probable.some((entry) => /server-status/i.test(entry.message)), false);
  assert.ok(result.findingConfidence.unverified.some((entry) => /Operational endpoint observed publicly: \/server-status/i.test(entry.message)));
});

test("security autofill export keeps direct evidence separate from review-only heuristics", () => {
  const result = createBaseResult({
    leadId: 92,
    timestamp: "2026-03-29T12:00:00.000Z",
    domain: "example.com",
    contacts: { emails: ["owner@example.com"], phones: [] },
    ssl: {
      valid: true,
      issuer: "Test CA",
      expires: "2099-01-01T00:00:00.000Z",
      daysUntilExpiry: 365,
      error: null,
      authorizationError: null,
      hostnameError: null,
    },
    https: { enabled: true, redirects: false, statusCode: 200, location: null },
    securityHeaders: {
      "strict-transport-security": { present: false, value: null },
      "content-security-policy": { present: false, value: null },
      "x-frame-options": { present: true, value: "SAMEORIGIN" },
      "x-content-type-options": { present: true, value: "nosniff" },
      "referrer-policy": { present: true, value: "strict-origin-when-cross-origin" },
      "permissions-policy": { present: true, value: "geolocation=()" },
      "x-xss-protection": { present: false, value: null },
    },
    mixedContent: { found: true, resources: ["http://cdn.example.com/app.js"] },
    emailAuth: {
      spf: "v=spf1 include:_spf.example.com ~all",
      dmarc: "v=DMARC1; p=none;",
      dkim: null,
      dkimDetectionMethod: "common-selector-guess",
      dkimCheckedSelectors: ["default", "selector1"],
    },
    dnsRecords: { mx: ["mx.example.com"], ns: [], a: ["203.0.113.10"] },
    sensitiveExposures: {
      sensitiveFiles: [{ type: "env", url: "https://example.com/.env", severity: "critical", status: 200 }],
      exposedGit: false,
      exposedEnv: true,
      exposedConfig: false,
      apiKeys: [],
      riskyEndpoints: [],
    },
    cookieSecurity: {
      findings: [{ message: "Session/auth cookie readable by client script: portal_session" }],
      sessionCookies: ["portal_session"],
      authCookies: [],
      csrfCookies: [],
      analyticsCookies: [],
    },
    forms: {
      issues: ["INFO: POST form has no visible CSRF token; authenticated state-changing context not verified"],
      forms: [{ method: "POST", hasPasswordField: false, hasCreditCardField: true, action: "/checkout" }],
      totalForms: 1,
    },
    paymentSecurity: {
      hasPaymentSurface: true,
      hostedThirdPartyCheckout: false,
      embeddedTrustedWidget: true,
      onSiteCardCollectionForms: 1,
      providers: [],
      paymentFlowType: "embedded-trusted-widget",
      findings: [{ message: "Observed on-site payment field collection (1 form(s)); PCI posture not verified by this audit" }],
    },
    adminEndpoints: { found: [{ path: "/login", status: 200, accessState: "responds" }], accessible: [{ path: "/login", status: 200 }] },
    securityOutreach: {
      primaryHook: "Missing security header: content-security-policy",
      verifiedHooks: ["Missing security header: content-security-policy"],
      probableHooks: [],
    },
    findingConfidence: {
      verified: [
        { message: "Missing security header: content-security-policy" },
        { message: "Mixed content detected (1 HTTP resource(s))" },
      ],
      probable: [
        { message: "Session/auth cookie readable by client script: portal_session" },
      ],
      observedUnderInstrumentation: [
        { message: "Observed only under browser instrumentation: ResizeObserver loop limit exceeded" },
      ],
      unverified: [
        { message: "Reproducible console error observed: Failed to load resource" },
      ],
    },
  });

  const enrichment = buildLeadEnrichment(result);
  const securityExport = enrichment.securityAutofill;

  assert.equal(enrichment.schemaVersion, 2);
  assert.equal(securityExport.verifiedAutofill.https_redirects.value, false);
  assert.deepEqual(securityExport.verifiedAutofill.missing_security_headers.value, [
    "strict-transport-security",
    "content-security-policy",
  ]);
  assert.equal(securityExport.verifiedAutofill.mixed_content_found.value, true);
  assert.equal(securityExport.verifiedAutofill.spf_present.value, true);
  assert.equal(securityExport.verifiedAutofill.dmarc_present.value, true);
  assert.equal(securityExport.verifiedAutofill.exposed_env.value, true);
  assert.equal(securityExport.verifiedAutofill.security_outreach_primary_hook.value, "Missing security header: content-security-policy");

  assert.equal(securityExport.verifiedAutofill.cookie_security_posture, undefined);
  assert.ok(securityExport.reviewQueue.some((entry) => entry.field === "cookie_security_posture"));
  assert.ok(securityExport.reviewQueue.some((entry) => entry.field === "csrf_posture"));
  assert.ok(securityExport.reviewQueue.some((entry) => entry.field === "payment_security_posture"));
  assert.ok(securityExport.reviewQueue.some((entry) => entry.field === "payment_security_posture" && entry.summary.paymentFlowType === "embedded-trusted-widget"));
  assert.ok(securityExport.reviewQueue.some((entry) => entry.field === "admin_surface_exposure"));
  assert.ok(securityExport.reviewQueue.some((entry) => entry.field === "dkim_posture"));
  assert.ok(securityExport.reviewQueue.some((entry) => entry.field === "probable_findings"));
  assert.ok(securityExport.reviewQueue.some((entry) => entry.field === "instrumentation_only_observations"));
});

test("benign public disclosure files are excluded from verified sensitive exposure autofill", () => {
  const result = createBaseResult({
    leadId: 402,
    timestamp: "2026-03-29T13:30:00.000Z",
    sensitiveExposures: {
      sensitiveFiles: [
        { type: "security", path: "/.well-known/security.txt", severity: "info", status: 200, reportOnly: true },
        { type: "log", path: "/debug.log", severity: "medium", status: 200, reportOnly: false },
      ],
      exposedGit: false,
      exposedEnv: false,
      exposedConfig: false,
      apiKeys: [],
      riskyEndpoints: [],
    },
  });

  const enrichment = buildLeadEnrichment(result);
  const exposures = enrichment.securityAutofill.verifiedAutofill.sensitive_file_exposures.value;

  assert.equal(exposures.some((entry) => entry.path === "/.well-known/security.txt"), false);
  assert.ok(exposures.some((entry) => entry.path === "/debug.log"));
});

test("admin surface review distinguishes expected CMS login routes from atypical reachable admin paths", () => {
  const result = createBaseResult({
    techStack: { cms: "WordPress", backend: "PHP", frameworks: [] },
    adminEndpoints: {
      found: [
        { path: "/wp-login.php", status: 200, accessState: "responds", accessible: true },
        { path: "/backend", status: 200, accessState: "responds", accessible: true },
      ],
      accessible: [
        { path: "/wp-login.php", status: 200, accessState: "responds", accessible: true },
        { path: "/backend", status: 200, accessState: "responds", accessible: true },
      ],
    },
  });

  const enrichment = buildLeadEnrichment(result);
  const adminReview = enrichment.securityAutofill.reviewQueue.find((entry) => entry.field === "admin_surface_exposure");

  assert.equal(adminReview.summary.overall, "atypical-admin-surface-observed");
  assert.ok(adminReview.summary.surfaces.some((entry) => entry.path === "/wp-login.php" && entry.classification === "expected-cms-admin-surface"));
  assert.ok(adminReview.summary.surfaces.some((entry) => entry.path === "/backend" && entry.classification === "atypical-admin-surface-responds"));
});

test("dkim review summary distinguishes sampled presence from sampled absence", () => {
  const sampledPresence = buildDkimReviewSummary(createBaseResult({
    domain: "example.com",
    dnsRecords: { mx: ["mx.example.com"], ns: [], a: ["203.0.113.10"] },
    contacts: { emails: ["owner@example.com"], phones: [] },
    emailAuth: {
      spf: "v=spf1 include:_spf.example.com ~all",
      dmarc: "v=DMARC1; p=none;",
      dkim: { selector: "google", record: "v=DKIM1; p=abc", detectionMethod: "common-selector-guess" },
      dkimDetectionMethod: "common-selector-guess",
      dkimCheckedSelectors: ["default", "google"],
    },
  }));
  const sampledAbsence = buildDkimReviewSummary(createBaseResult({
    domain: "example.com",
    dnsRecords: { mx: ["mx.example.com"], ns: [], a: ["203.0.113.10"] },
    contacts: { emails: ["owner@example.com"], phones: [] },
    emailAuth: {
      spf: "v=spf1 include:_spf.example.com ~all",
      dmarc: "v=DMARC1; p=none;",
      dkim: null,
      dkimDetectionMethod: "common-selector-guess",
      dkimCheckedSelectors: ["default", "google"],
    },
  }));

  assert.equal(sampledPresence.classification, "dkim-present-common-selector-sample");
  assert.equal(sampledAbsence.classification, "dkim-not-found-in-common-selector-sample");
});

test("dkim review summary recognizes provider-informed selector sampling", () => {
  const providerInformed = buildDkimReviewSummary(createBaseResult({
    domain: "example.com",
    dnsRecords: { mx: ["aspmx.l.google.com"], ns: [], a: ["203.0.113.10"] },
    contacts: { emails: ["owner@example.com"], phones: [] },
    emailAuth: {
      spf: "v=spf1 include:_spf.google.com ~all",
      dmarc: "v=DMARC1; p=none;",
      dkim: null,
      dkimDetectionMethod: "provider-informed-selector-sample",
      dkimCheckedSelectors: ["google", "default", "selector1"],
      dkimProviderHints: ["google-workspace"],
    },
  }));

  assert.equal(providerInformed.classification, "dkim-not-found-in-provider-informed-sample");
  assert.deepEqual(providerInformed.providerHints, ["google-workspace"]);
});

test("dkim review is suppressed when no mail surface is observed and no record is found", () => {
  const result = createBaseResult({
    domain: "example.com",
    dnsRecords: { mx: [], ns: [], a: ["203.0.113.10"] },
    contacts: { emails: [], phones: [] },
    emailAuth: {
      spf: null,
      dmarc: null,
      dkim: null,
      dkimDetectionMethod: "common-selector-guess",
      dkimCheckedSelectors: ["default", "selector1"],
    },
  });

  const enrichment = buildLeadEnrichment(result);
  assert.equal(enrichment.securityAutofill.reviewQueue.some((entry) => entry.field === "dkim_posture"), false);
});

test("review queue highlights prioritize atypical admin and on-site payment above dkim sampling notes", () => {
  const highlights = buildReviewQueueHighlights([
    {
      field: "dkim_posture",
      summary: {
        classification: "dkim-not-found-in-provider-informed-sample",
        checkedSelectorCount: 4,
      },
    },
    {
      field: "payment_security_posture",
      summary: {
        paymentFlowType: "apparent-on-site-card-collection",
      },
    },
    {
      field: "admin_surface_exposure",
      summary: {
        overall: "atypical-admin-surface-observed",
      },
    },
  ]);

  assert.match(highlights[0], /\*\*Admin\/Login Routes:\*\*/);
  assert.match(highlights[1], /\*\*Payment Flow:\*\*/);
  assert.match(highlights[2], /\*\*DKIM:\*\*/);
});

test("profile section includes compact review highlights for dkim and payment context", () => {
  const result = createBaseResult({
    auditScore: 92,
    performance: {
      loadTime: null,
      domContentLoaded: null,
      firstPaint: null,
      firstContentfulPaint: null,
      largestContentfulPaint: null,
      cumulativeLayoutShift: null,
      interactionToNextPaint: null,
    },
    seo: { title: "Example", metaDescription: "desc", h1Count: 1, images: 0, imagesWithoutAlt: 0, canonical: null },
    mobile: { friendly: true, viewport: "width=device-width" },
    consoleErrors: [],
    pageErrors: [],
    screenshots: { desktop: null, mobile: null },
    forms: { found: false, forms: [], issues: [], totalForms: 0 },
    techStack: { cms: "WordPress", frameworks: [], indicators: [] },
    enrichment: {
      securityAutofill: {
        reviewQueue: [
          {
            field: "dkim_posture",
            summary: {
              classification: "dkim-not-found-in-common-selector-sample",
              checkedSelectorCount: 3,
            },
          },
          {
            field: "payment_security_posture",
            summary: {
              paymentFlowType: "embedded-trusted-widget",
            },
          },
        ],
      },
    },
  });

  const profile = generateProfileSection(result);
  assert.match(profile, /### Review Queue Highlights/);
  assert.match(profile, /\*\*DKIM:\*\* Not found in sampled selectors \(3 checked\)/);
  assert.match(profile, /\*\*Payment Flow:\*\* Classified as `embedded-trusted-widget`/);
});

test("security outreach primary hook is not autofill-safe when it only comes from probable findings", () => {
  const result = createBaseResult({
    leadId: 885,
    timestamp: "2026-03-29T12:30:00.000Z",
    contacts: { emails: ["owner@example.com"], phones: [] },
    dnsRecords: { mx: ["mx.example.com"], ns: [], a: ["203.0.113.10"] },
    emailAuth: {
      spf: "v=spf1 include:_spf.example.com ~all",
      dmarc: "v=DMARC1; p=none;",
      dkim: null,
      dkimDetectionMethod: "common-selector-guess",
      dkimCheckedSelectors: ["default"],
    },
    securityOutreach: {
      primaryHook: "Session/auth cookie readable by client script: portal_session",
      verifiedHooks: [],
      probableHooks: ["Session/auth cookie readable by client script: portal_session"],
    },
    findingConfidence: {
      verified: [],
      probable: [{ message: "Session/auth cookie readable by client script: portal_session" }],
      observedUnderInstrumentation: [],
      unverified: [],
    },
  });

  const enrichment = buildLeadEnrichment(result);
  const securityExport = enrichment.securityAutofill;

  assert.equal(securityExport.verifiedAutofill.security_outreach_primary_hook, undefined);
  assert.ok(securityExport.reviewQueue.some((entry) => entry.field === "probable_findings"));
});
