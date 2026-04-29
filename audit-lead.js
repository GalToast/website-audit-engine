/**
 * audit-lead.js - Comprehensive Website Audit Script
 * 
 * Usage: node audit-lead.js <lead-id> <domain> <profile-range>
 * Example: node audit-lead.js 1234 example.com 1200-1299
 * 
 * Performs deep security, performance, and technical audits.
 * Outputs JSON to stdout and updates profile.md.
 */

const { chromium } = require("playwright");
const fs = require("fs");
const path = require("path");
const https = require("https");
const tls = require("tls");
const { URL } = require("url");

/**
 * Light-touch detection-aware script for the default audit path.
 * This avoids the most common automation flags without heavily mutating browser APIs.
 */
const LIGHT_DETECTION_BYPASS_SCRIPT = `
(function() {
  'use strict';

  Object.defineProperty(navigator, 'webdriver', {
    get: () => undefined,
    configurable: true
  });

  Object.defineProperty(navigator, 'languages', {
    get: () => ['en-US', 'en'],
    configurable: true
  });

  Object.defineProperty(navigator, 'platform', {
    get: () => 'Win32',
    configurable: true
  });

  if (!window.chrome) {
    window.chrome = { runtime: {} };
  } else if (!window.chrome.runtime) {
    window.chrome.runtime = {};
  }

  if (navigator.permissions && typeof navigator.permissions.query === 'function') {
    const originalQuery = navigator.permissions.query.bind(navigator.permissions);
    navigator.permissions.query = function(parameters) {
      if (parameters && parameters.name === 'notifications') {
        return Promise.resolve({ state: Notification.permission, onchange: null });
      }
      return originalQuery(parameters);
    };
  }
})();
`;

/**
 * Heavy detection-aware script for blocker-circumvention fallback only.
 * This is intentionally more invasive and should not be used on the default audit path.
 */
const HEAVY_DETECTION_BYPASS_SCRIPT = `
(function() {
  'use strict';
  
  // ============================================
  // NAVIGATOR PROPERTIES
  // ============================================
  
  // Hide webdriver property (most common detection)
  Object.defineProperty(navigator, 'webdriver', {
    get: () => undefined,
    configurable: true
  });
  
  // Realistic plugins array (mimic Chrome)
  const fakePlugins = [
    { name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer', description: 'Portable Document Format', length: 1 },
    { name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai', description: '', length: 1 },
    { name: 'Native Client', filename: 'internal-nacl-plugin', description: '', length: 2 }
  ];
  
  // Create a proper PluginArray-like object
  const pluginArray = {
    length: fakePlugins.length,
    item: function(i) { return this[i] || null; },
    namedItem: function(name) { return fakePlugins.find(p => p.name === name) || null; },
    refresh: function() {},
    [Symbol.iterator]: function*() { for (const p of fakePlugins) yield p; }
  };
  fakePlugins.forEach((p, i) => { pluginArray[i] = p; });
  
  Object.defineProperty(navigator, 'plugins', {
    get: () => pluginArray,
    configurable: true
  });
  
  // Realistic mime types
  const fakeMimeTypes = [
    { type: 'application/pdf', suffixes: 'pdf', description: 'Portable Document Format' },
    { type: 'application/x-google-chrome-pdf', suffixes: 'pdf', description: 'Portable Document Format' },
    { type: 'application/x-nacl', suffixes: '', description: 'Native Client Executable' },
    { type: 'application/x-pnacl', suffixes: '', description: 'Portable Native Client Executable' }
  ];
  
  const mimeTypeArray = {
    length: fakeMimeTypes.length,
    item: function(i) { return this[i] || null; },
    namedItem: function(name) { return fakeMimeTypes.find(m => m.type === name) || null; },
    [Symbol.iterator]: function*() { for (const m of fakeMimeTypes) yield m; }
  };
  fakeMimeTypes.forEach((m, i) => { mimeTypeArray[i] = m; });
  
  Object.defineProperty(navigator, 'mimeTypes', {
    get: () => mimeTypeArray,
    configurable: true
  });
  
  // Languages matching Chrome
  Object.defineProperty(navigator, 'languages', {
    get: () => ['en-US', 'en'],
    configurable: true
  });
  
  // Platform
  Object.defineProperty(navigator, 'platform', {
    get: () => 'Win32',
    configurable: true
  });
  
  // Hardware concurrency (realistic for common machines)
  Object.defineProperty(navigator, 'hardwareConcurrency', {
    get: () => 8,
    configurable: true
  });
  
  // Device memory (realistic)
  Object.defineProperty(navigator, 'deviceMemory', {
    get: () => 8,
    configurable: true
  });
  
  // Max touch points (desktop = 0)
  Object.defineProperty(navigator, 'maxTouchPoints', {
    get: () => 0,
    configurable: true
  });
  
  // ============================================
  // CHROME OBJECT
  // ============================================
  
  window.chrome = {
    app: {
      isInstalled: false,
      InstallState: { DISABLED: 'disabled', INSTALLED: 'installed', NOT_INSTALLED: 'not_installed' },
      RunningState: { CANNOT_RUN: 'cannot_run', READY_TO_RUN: 'ready_to_run', RUNNING: 'running' }
    },
    runtime: {
      OnInstalledReason: { CHROME_UPDATE: 1, INSTALL: 2, SHARED_MODULE_UPDATE: 3, UPDATE: 4 },
      OnPlatformOsReason: { ANDROID: 'android', CROS: 'cros', LINUX: 'linux', MAC: 'mac', OPENBSD: 'openbsd', WIN: 'win' },
      PlatformArch: { ARM: 'arm', ARM64: 'arm64', MIPS: 'mips', MIPS64: 'mips64', X86_32: 'x86-32', X86_64: 'x86-64' },
      PlatformNaclArch: { ARM: 'arm', MIPS: 'mips', MIPS64: 'mips64', X86_32: 'x86-32', X86_64: 'x86-64' },
      RequestUpdateCheckStatus: { NO_UPDATE: 'no_update', THROTTLED: 'throttled', UPDATE_AVAILABLE: 'update_available' },
      connect: function() { return { onDisconnect: { addListener: function() {} }, onMessage: { addListener: function() {} }, postMessage: function() {} }; },
      sendMessage: function() {}
    },
    csi: function() { return {}; },
    loadTimes: function() { return { commitLoadTime: Date.now() / 1000, connectionInfo: 'http/1.1', finishDocumentLoadTime: Date.now() / 1000, finishLoadTime: Date.now() / 1000, firstPaintAfterLoadTime: 0, firstPaintTime: Date.now() / 1000, navigationType: 'Other', npnNegotiatedProtocol: 'unknown', requestTime: Date.now() / 1000, startLoadTime: Date.now() / 1000, wasAlternateProtocolAvailable: false, wasFetchedViaSpdy: false, wasNpnNegotiated: false }; },
    webstore: { onInstallStageChanged: { addListener: function() {} }, onDownloadProgress: { addListener: function() {} } }
  };
  
  // ============================================
  // PERMISSIONS API
  // ============================================
  
  const originalQuery = window.navigator.permissions.query;
  window.navigator.permissions.query = function(parameters) {
    if (parameters.name === 'notifications') {
      return Promise.resolve({ state: Notification.permission, onchange: null });
    }
    if (parameters.name === 'geolocation') {
      return Promise.resolve({ state: 'prompt', onchange: null });
    }
    if (parameters.name === 'camera' || parameters.name === 'microphone') {
      return Promise.resolve({ state: 'prompt', onchange: null });
    }
    return originalQuery.call(window.navigator.permissions, parameters);
  };
  
  // ============================================
  // WEBGL FINGERPRINT SPOOFING
  // ============================================
  
  const getParameterProxyHandler = {
    apply: function(target, thisArg, args) {
      const param = args[0];
      const gl = thisArg;
      
      // UNMASKED_VENDOR_WEBGL
      if (param === 37445) {
        return 'Google Inc. (NVIDIA)';
      }
      // UNMASKED_RENDERER_WEBGL
      if (param === 37446) {
        return 'ANGLE (NVIDIA, NVIDIA GeForce GTX 1080 Direct3D11 vs_5_0 ps_5_0, D3D11)';
      }
      
      return target.apply(thisArg, args);
    }
  };
  
  // Override WebGL getParameter for both WebGL and WebGL2
  const originalWebGLGetParameter = WebGLRenderingContext.prototype.getParameter;
  WebGLRenderingContext.prototype.getParameter = new Proxy(originalWebGLGetParameter, getParameterProxyHandler);
  
  if (typeof WebGL2RenderingContext !== 'undefined') {
    const originalWebGL2GetParameter = WebGL2RenderingContext.prototype.getParameter;
    WebGL2RenderingContext.prototype.getParameter = new Proxy(originalWebGL2GetParameter, getParameterProxyHandler);
  }
  
  // ============================================
  // CANVAS FINGERPRINT SPOOFING
  // ============================================
  
  // Add subtle noise to canvas operations
  const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
  const originalToBlob = HTMLCanvasElement.prototype.toBlob;
  const originalGetImageData = CanvasRenderingContext2D.prototype.getImageData;
  
  // Random noise function
  const noiseMap = new Map();
  const getNoise = function(canvas, x, y, channel) {
    const key = canvas.width + 'x' + canvas.height + '_' + x + '_' + y + '_' + channel;
    if (!noiseMap.has(key)) {
      // Small random noise (-1 to 1)
      noiseMap.set(key, Math.floor(Math.random() * 3) - 1);
    }
    return noiseMap.get(key);
  };
  
  HTMLCanvasElement.prototype.toDataURL = function(type) {
    if (this.width === 0 || this.height === 0) {
      return originalToDataURL.apply(this, arguments);
    }
    try {
      const ctx = this.getContext('2d');
      if (ctx) {
        const imageData = ctx.getImageData(0, 0, this.width, this.height);
        for (let i = 0; i < imageData.data.length; i += 4) {
          const x = (i / 4) % this.width;
          const y = Math.floor((i / 4) / this.width);
          imageData.data[i] = Math.max(0, Math.min(255, imageData.data[i] + getNoise(this, x, y, 0)));
          imageData.data[i + 1] = Math.max(0, Math.min(255, imageData.data[i + 1] + getNoise(this, x, y, 1)));
          imageData.data[i + 2] = Math.max(0, Math.min(255, imageData.data[i + 2] + getNoise(this, x, y, 2)));
        }
        ctx.putImageData(imageData, 0, 0);
      }
    } catch (e) {}
    return originalToDataURL.apply(this, arguments);
  };
  
  HTMLCanvasElement.prototype.toBlob = function(callback, type, quality) {
    const originalCallback = callback;
    const modifiedCallback = function(blob) {
      originalCallback(blob);
    };
    return originalToBlob.call(this, function(blob) {
      // Add noise before converting
      const canvas = document.createElement('canvas');
      const ctx = canvas.getContext('2d');
      const img = new Image();
      img.onload = function() {
        canvas.width = img.width;
        canvas.height = img.height;
        ctx.drawImage(img, 0, 0);
        // Noise already added via toDataURL override
        modifiedCallback(blob);
      };
      img.src = URL.createObjectURL(blob);
    }, type, quality);
  };
  
  // ============================================
  // AUDIO FINGERPRINT SPOOFING
  // ============================================
  
  const originalAudioContext = window.AudioContext || window.webkitAudioContext;
  if (originalAudioContext) {
    const OriginalAudioContext = originalAudioContext;
    window.AudioContext = function() {
      const ctx = new OriginalAudioContext();
      const originalGetChannelData = AudioBuffer.prototype.getChannelData;
      AudioBuffer.prototype.getChannelData = function(channel) {
        const data = originalGetChannelData.call(this, channel);
        // Add subtle noise
        for (let i = 0; i < data.length; i++) {
          data[i] += (Math.random() - 0.5) * 0.0000001;
        }
        return data;
      };
      return ctx;
    };
    
    // Copy static properties
    Object.setPrototypeOf(window.AudioContext, OriginalAudioContext);
    Object.setPrototypeOf(window.AudioContext.prototype, OriginalAudioContext.prototype);
  }
  
  // ============================================
  // IFRAME CONTENTWINDOW PATCH
  // ============================================
  
  const originalContentWindow = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, 'contentWindow');
  Object.defineProperty(HTMLIFrameElement.prototype, 'contentWindow', {
    get: function() {
      const window = originalContentWindow.get.call(this);
      if (window) {
        try {
          // Ensure navigator.webdriver is undefined in iframes too
          Object.defineProperty(window.navigator, 'webdriver', { get: () => undefined, configurable: true });
        } catch (e) {}
      }
      return window;
    }
  });
  
  // ============================================
  // SCREEN PROPERTIES
  // ============================================
  
  // Ensure consistent screen dimensions
  Object.defineProperty(screen, 'width', { get: () => 1920, configurable: true });
  Object.defineProperty(screen, 'height', { get: () => 1080, configurable: true });
  Object.defineProperty(screen, 'availWidth', { get: () => 1920, configurable: true });
  Object.defineProperty(screen, 'availHeight', { get: () => 1040, configurable: true });
  Object.defineProperty(screen, 'colorDepth', { get: () => 24, configurable: true });
  Object.defineProperty(screen, 'pixelDepth', { get: () => 24, configurable: true });
  
  // Window outer dimensions
  Object.defineProperty(window, 'outerWidth', { get: () => 1920, configurable: true });
  Object.defineProperty(window, 'outerHeight', { get: () => 1080, configurable: true });
  
  // ============================================
  // AUTOMATION DETECTION MARKERS
  // ============================================
  
  // Hide Playwright/Puppeteer/Selenium markers
  delete window.__playwright;
  delete window.__puppeteer;
  delete window.__webdriver_evaluate;
  delete window.__selenium_evaluate;
  delete window.__webdriver_script_function;
  delete window.__webdriver_script_func;
  delete window.__webdriver_script_fn;
  delete window.__fxdriver_evaluate;
  delete window.__driver_unwrapped;
  delete window.__webdriver_unwrapped;
  delete window.__driver_evaluate;
  delete window.__selenium_unwrapped;
  delete window.__fxdriver_unwrapped;
  delete window.$cdc_asdjflasutopfhvcZLmcfl_;
  delete window.$chrome_asyncScriptInfo;
  
  // Remove automation-related functions
  const originalDocument$ = document.$;
  if (originalDocument$ && originalDocument$.toString().includes('native code')) {
    // Keep if it's native
  } else {
    delete document.$;
  }
  
  // ============================================
  // BATTERY API
  // ============================================
  
  // Remove battery API (fingerprinting vector)
  if (navigator.getBattery) {
    Object.defineProperty(navigator, 'getBattery', {
      value: function() {
        return Promise.reject(new Error('Battery API not available'));
      },
      writable: true,
      configurable: true
    });
  }
  
  // ============================================
  // CONNECTION API
  // ============================================
  
  if (navigator.connection) {
    Object.defineProperty(navigator.connection, 'rtt', { get: () => 50, configurable: true });
    Object.defineProperty(navigator.connection, 'downlink', { get: () => 10, configurable: true });
    Object.defineProperty(navigator.connection, 'effectiveType', { get: () => '4g', configurable: true });
    Object.defineProperty(navigator.connection, 'saveData', { get: () => false, configurable: true });
  }
  
  // ============================================
  // WEBRTC IP LEAK PREVENTION
  // ============================================
  
  const originalRTCPeerConnection = window.RTCPeerConnection || window.webkitRTCPeerConnection || window.mozRTCPeerConnection;
  if (originalRTCPeerConnection) {
    const OriginalRTCPeerConnection = originalRTCPeerConnection;
    window.RTCPeerConnection = function(config, constraints) {
      // Force relay mode to prevent local IP leak
      if (config && config.iceServers) {
        // Keep servers but force relay
        const modifiedConfig = JSON.parse(JSON.stringify(config));
        modifiedConfig.iceTransportPolicy = 'relay';
        return new OriginalRTCPeerConnection(modifiedConfig, constraints);
      }
      return new OriginalRTCPeerConnection(config, constraints);
    };
    Object.setPrototypeOf(window.RTCPeerConnection, OriginalRTCPeerConnection);
    Object.setPrototypeOf(window.RTCPeerConnection.prototype, OriginalRTCPeerConnection.prototype);
  }
  
  // ============================================
  // HEADLESS DETECTION
  // ============================================
  
  // Override headless Chrome detection via User-Agent
  const originalUserAgent = navigator.userAgent;
  Object.defineProperty(navigator, 'userAgent', {
    get: () => originalUserAgent.replace(/HeadlessChrome/g, 'Chrome'),
    configurable: true
  });
  
  // Override navigator.webdriver detection via prototype
  Object.defineProperty(Navigator.prototype, 'webdriver', {
    get: () => undefined,
    configurable: true
  });
  
  // ============================================
  // DATE/TIMEZONE CONSISTENCY
  // ============================================
  
  // Ensure timezone is consistent
  const originalDateTimezoneOffset = Date.prototype.getTimezoneOffset;
  Date.prototype.getTimezoneOffset = function() {
    return -300; // EST (UTC-5)
  };
  
  // ============================================
  // FONT ENUMERATION PROTECTION
  // ============================================
  
  // This is handled by canvas spoofing - fonts render with noise
  
  // ============================================
  // MEDIA DEVICES
  // ============================================
  
  if (navigator.mediaDevices && navigator.mediaDevices.enumerateDevices) {
    const originalEnumerateDevices = navigator.mediaDevices.enumerateDevices;
    navigator.mediaDevices.enumerateDevices = function() {
      return originalEnumerateDevices.call(this).then(function(devices) {
        // Return consistent fake devices
        return [
          { deviceId: 'default', groupId: 'default', kind: 'audioinput', label: 'Default - Microphone (Realtek High Definition Audio)' },
          { deviceId: 'communications', groupId: 'default', kind: 'audioinput', label: 'Communications - Microphone (Realtek High Definition Audio)' },
          { deviceId: 'mic1', groupId: 'audio_group_1', kind: 'audioinput', label: 'Microphone (Realtek High Definition Audio)' },
          { deviceId: 'default', groupId: 'default', kind: 'audiooutput', label: 'Default - Speakers (Realtek High Definition Audio)' },
          { deviceId: 'communications', groupId: 'default', kind: 'audiooutput', label: 'Communications - Speakers (Realtek High Definition Audio)' },
          { deviceId: 'speaker1', groupId: 'audio_group_1', kind: 'audiooutput', label: 'Speakers (Realtek High Definition Audio)' }
        ];
      });
    };
  }
  
  // ============================================
  // PROTOTYPE INTEGRITY
  // ============================================
  
  // Make toString() return native code for our overrides
  const nativeToStringFunctionString = Function.prototype.toString.call(function() {});
  Function.prototype.toString = function() {
    if (this === navigator.permissions.query) {
      return 'function query() { [native code] }';
    }
    return nativeToStringFunctionString.call(this);
  };
  
  // ============================================
  // CONSOLE LOG (for debugging)
  // ============================================
  
  console.log('[EVASION] Enhanced evasion script injected');
  
})();
`;

/**
 * Tracking/analytics domains to block (reduces fingerprint surface + faster loads)
 * These scripts often detect automation and report to bot detection services
 */
const TRACKING_DOMAINS = [
  // Major analytics
  'google-analytics.com',
  'googletagmanager.com',
  'googlesyndication.com',
  'hotjar.com',
  'fullstory.com',
  'mixpanel.com',
  'segment.io',
  'amplitude.com',
  'heap.io',
  'mouseflow.com',
  'clicktale.net',
  'crazyegg.com',
  'optimizely.com',
  // Ad networks (often have bot detection)
  'doubleclick.net',
  'adservice.google.com',
  'ads.twitter.com',
  'facebook.net/tr',
  'connect.facebook.net',
  'ads.linkedin.com',
  // Bot detection services
  'datadome.co',
  'perimeterx.net',
  'arbor.net',
  'distilnetworks.com',
  'whiteops.com',
  'humansecurity.com',
  'kasada.io',
  'f5.com',
  // Fingerprinting services
  'fp.io',
  'fingerprintjs.com',
  'clientjs.org',
  'lighthouse.ai'
];

/**
 * Setup request interception to block tracking scripts
 * Reduces fingerprint surface and bot detection triggers
 */
async function setupTrackingBlocker(page) {
  await page.route('**/*', async (route) => {
    const url = route.request().url().toLowerCase();
    const resourceType = route.request().resourceType();
    
    // Block tracking domains
    for (const domain of TRACKING_DOMAINS) {
      if (url.includes(domain)) {
        await route.abort();
        return;
      }
    }
    
    // Allow everything else
    await route.continue();
  });
}

/**
 * Detect if page is a bot blocker challenge page
 */
function detectBotBlocker(page, url) {
  return page.evaluate(() => {
    const indicators = {
      cloudflare: false,
      akamai: false,
      incapsula: false,
      recaptcha: false,
      generic: false,
      challengeDetected: false,
      pageTitle: document.title || '',
      bodyText: document.body?.innerText?.substring(0, 500) || ''
    };
    
    // Cloudflare detection
    if (document.querySelector('[data-ray]') || 
        document.querySelector('.cf-error-details') ||
        document.body?.innerHTML?.includes('cf-browser-verification') ||
        document.body?.innerHTML?.includes('Just a moment...') ||
        document.body?.innerHTML?.includes('Checking your browser') ||
        document.title?.includes('Just a moment')) {
      indicators.cloudflare = true;
      indicators.challengeDetected = true;
    }
    
    // Akamai detection
    if (document.body?.innerHTML?.includes('Akamai') ||
        document.body?.innerHTML?.includes('Reference #') && document.body?.innerHTML?.includes('akamai')) {
      indicators.akamai = true;
      indicators.challengeDetected = true;
    }
    
    // Incapsula detection  
    if (document.body?.innerHTML?.includes('Incapsula') ||
        document.body?.innerHTML?.includes('incap_ses_')) {
      indicators.incapsula = true;
      indicators.challengeDetected = true;
    }
    
    // reCAPTCHA detection
    if (document.querySelector('iframe[src*="recaptcha"]') ||
        document.body?.innerHTML?.includes('g-recaptcha')) {
      indicators.recaptcha = true;
      indicators.challengeDetected = true;
    }
    
    // Generic challenge detection
    if (document.title?.toLowerCase().includes('access denied') ||
        document.title?.toLowerCase().includes('blocked') ||
        document.title?.toLowerCase().includes('forbidden') ||
        document.body?.innerText?.includes('Access Denied') ||
        document.body?.innerText?.includes('blocked') ||
        document.body?.innerText?.includes('You have been blocked')) {
      indicators.generic = true;
      indicators.challengeDetected = true;
    }
    
    return indicators;
  });
}

/**
 * Wait for Cloudflare challenge to complete (up to 30s)
 * Returns true if challenge passed, false if still blocked
 */
async function waitForCloudflareChallenge(page, maxWaitMs = 30000) {
  const startTime = Date.now();
  console.error("[EVASION] Waiting for Cloudflare challenge...");
  
  while (Date.now() - startTime < maxWaitMs) {
    const blocker = await detectBotBlocker(page);
    
    if (!blocker.cloudflare && !blocker.challengeDetected) {
      console.error("[EVASION] Cloudflare challenge passed!");
      return true;
    }
    
    // Check if we're still on challenge page
    const title = await page.title();
    if (!title.includes('Just a moment') && !title.includes('Checking')) {
      // Page changed - likely passed
      const newBlocker = await detectBotBlocker(page);
      if (!newBlocker.challengeDetected) {
        console.error("[EVASION] Challenge appears resolved");
        return true;
      }
    }
    
    // Wait and retry
    await page.waitForTimeout(1000);
  }
  
  console.error("[EVASION] Cloudflare challenge timed out after 30s");
  return false;
}

/**
 * Try alternative URL variations to circumvent bot blockers
 */
async function tryAlternativeUrls(page, domain, timeoutMs = 60000) {
  const variations = [
    { url: `https://www.${domain}`, desc: 'HTTPS with www' },
    { url: `https://${domain}`, desc: 'HTTPS without www' },
    { url: `http://www.${domain}`, desc: 'HTTP with www' },
    { url: `http://${domain}`, desc: 'HTTP without www' },
  ];
  
  for (const variation of variations) {
    try {
      console.error(`[EVASION] Trying ${variation.desc}: ${variation.url}`);
      
      const response = await page.goto(variation.url, {
        waitUntil: "domcontentloaded",
        timeout: timeoutMs,
      });
      
      if (response && response.status() < 500) {
        // Check for bot blocker
        await page.waitForTimeout(2000);
        const blocker = await detectBotBlocker(page);
        
        if (blocker.challengeDetected && blocker.cloudflare) {
          // Try to wait out Cloudflare
          const passed = await waitForCloudflareChallenge(page, 15000);
          if (passed) {
            console.error(`[EVASION] Successfully passed Cloudflare on ${variation.desc}`);
            return { response, url: variation.url, passed: true };
          }
        } else if (!blocker.challengeDetected) {
          console.error(`[EVASION] No bot blocker on ${variation.desc}`);
          return { response, url: variation.url, passed: true };
        }
      }
    } catch (e) {
      console.error(`[EVASION] Failed ${variation.desc}: ${e.message}`);
    }
  }
  
  return { response: null, url: null, passed: false };
}

/**
 * Alternative User-Agents for bot blocker circumvention
 * Includes legitimate search engine bots that some sites whitelist
 */
const ALTERNATIVE_USER_AGENTS = [
  { ua: "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", desc: 'Googlebot' },
  { ua: "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)", desc: 'Bingbot' },
  { ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", desc: 'Chrome Mac' },
  { ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0", desc: 'Firefox' },
  { ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15", desc: 'Safari Mac' },
];

/**
 * Try loading page with alternative User-Agents to circumvent bot blockers
 * Creates fresh browser contexts with different UAs
 */
async function tryAlternativeUserAgents(browser, domain, timeoutMs = 30000) {
  for (const uaConfig of ALTERNATIVE_USER_AGENTS) {
    let context = null;
    let page = null;
    let succeeded = false;
    
    try {
      console.error(`[EVASION] Trying User-Agent: ${uaConfig.desc}`);
      
      context = await browser.newContext({
        viewport: { width: 1920, height: 1080 },
        userAgent: uaConfig.ua,
        ignoreHTTPSErrors: true,
        locale: 'en-US',
        timezoneId: 'America/New_York',
      });
      
      page = await context.newPage();
      await page.addInitScript(HEAVY_DETECTION_BYPASS_SCRIPT);
      await setupTrackingBlocker(page);
      
      const url = `https://${domain}`;
      const response = await page.goto(url, {
        waitUntil: "domcontentloaded",
        timeout: timeoutMs,
      });
      
      if (response && response.status() < 500) {
        await page.waitForTimeout(2000);
        const blocker = await detectBotBlocker(page);
        
        if (blocker.challengeDetected && blocker.cloudflare) {
          const passed = await waitForCloudflareChallenge(page, 10000);
          if (passed) {
            console.error(`[EVASION] Passed Cloudflare with ${uaConfig.desc} UA`);
            succeeded = true;
            return { page, context, response, url, passed: true, userAgent: uaConfig };
          }
        } else if (!blocker.challengeDetected) {
          console.error(`[EVASION] Success with ${uaConfig.desc} UA - no blocker detected`);
          succeeded = true;
          return { page, context, response, url, passed: true, userAgent: uaConfig };
        }
      }
    } catch (e) {
      console.error(`[EVASION] Failed with ${uaConfig.desc}: ${e.message}`);
    } finally {
      // Clean up if we didn't succeed
      if (!succeeded && page && !page.isClosed?.()) {
        try { await page.close(); } catch (e) {}
      }
      if (!succeeded && context) {
        try { await context.close(); } catch (e) {}
      }
    }
  }
  
  return { page: null, context: null, response: null, url: null, passed: false };
}

/**
 * Add random delays to appear more human-like
 */
function randomDelay(minMs = 500, maxMs = 2000) {
  const delay = Math.floor(Math.random() * (maxMs - minMs + 1)) + minMs;
  return new Promise(resolve => setTimeout(resolve, delay));
}
const isMainModule = require.main === module;
const [, , cliLeadId, cliDomain, cliProfileRange] = process.argv;

if (isMainModule && (!cliLeadId || !cliDomain)) {
  console.error("Usage: node audit-lead.js <lead-id> <domain-or-url> [profile-range]");
  console.error("Example: node audit-lead.js 1234 example.com 1200-1299");
  process.exit(1);
}

const leadId = cliLeadId || "test-lead";
const domainOrUrl = cliDomain || "example.com";
const profileRange = cliProfileRange || null;

// Normalize the audit target so DNS/SSL checks use the hostname while browser navigation
// can still target full indexed URLs such as directory listings or store-locator pages.
function normalizeAuditTarget(value) {
  const raw = String(value || "").trim();
  if (!raw) {
    return {
      original: raw,
      hostname: "example.com",
      normalizedInput: "example.com",
      testUrl: "https://example.com",
      hasExplicitPath: false,
    };
  }

  const withScheme = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;
  try {
    const parsed = new URL(withScheme);
    const serialized = parsed.toString();
    const testUrl = parsed.pathname === "/" && !parsed.search && !parsed.hash
      ? serialized.replace(/\/$/, "")
      : serialized;
    return {
      original: raw,
      hostname: parsed.hostname.toLowerCase(),
      normalizedInput: raw.replace(/^https?:\/\//i, "").replace(/\/$/, ""),
      testUrl,
      hasExplicitPath: parsed.pathname !== "/" || !!parsed.search,
    };
  } catch {
    const normalizedInput = raw.replace(/^https?:\/\//i, "").replace(/\/$/, "");
    return {
      original: raw,
      hostname: normalizedInput.split("/")[0].toLowerCase(),
      normalizedInput,
      testUrl: `https://${normalizedInput}`,
      hasExplicitPath: normalizedInput.includes("/"),
    };
  }
}

const auditTarget = normalizeAuditTarget(domainOrUrl);
const normalizedDomain = auditTarget.hostname;
const testUrl = auditTarget.testUrl;
const hasExplicitPathTarget = auditTarget.hasExplicitPath;

function slugifyDomain(value) {
  return (value || "audit")
    .toLowerCase()
    .replace(/^www\./, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80) || "audit";
}

function ensureProfileTarget(profileRange, leadId, domain) {
  if (!profileRange) return null;

  const rangeDir = path.join(__dirname, "leads", "profiles", profileRange);
  const domainSlug = slugifyDomain(domain);
  const fallbackFolderName = `${leadId}-${domainSlug}`;

  fs.mkdirSync(rangeDir, { recursive: true });

  const matches = fs.readdirSync(rangeDir, { withFileTypes: true })
    .filter((entry) => entry.isDirectory() && entry.name.startsWith(`${leadId}-`))
    .map((entry) => entry.name)
    .sort();

  if (matches.length === 0) {
    const targetDir = path.join(rangeDir, fallbackFolderName);
    fs.mkdirSync(path.join(targetDir, "evidence"), { recursive: true });

    const profilePath = path.join(targetDir, "profile.md");
    if (!fs.existsSync(profilePath)) {
      fs.writeFileSync(
        profilePath,
        [
          `# ${leadId} - ${normalizedDomain}`,
          "",
          `**Lead ID:** ${leadId}`,
          `**Domain:** ${normalizedDomain}`,
          "**Status:** Pending Audit",
          "",
          "---",
          "",
        ].join("\n"),
        "utf8"
      );
    }

    return {
      rangeDir,
      profileDir: targetDir,
      profilePath,
      evidenceDir: path.join(targetDir, "evidence"),
    };
  }

  const preferredMatches = matches.filter((name) => name === fallbackFolderName);
  const nonPlaceholderMatches = matches.filter((name) => name !== `${leadId}-audit`);
  const resolvedName =
    preferredMatches[0] ||
    (matches.length === 1 ? matches[0] : null) ||
    (nonPlaceholderMatches.length === 1 ? nonPlaceholderMatches[0] : null);

  if (!resolvedName) {
    throw new Error(
      `Ambiguous profile directories for lead ${leadId} in ${profileRange}: ${matches.join(", ")}`
    );
  }

  const profileDir = path.join(rangeDir, resolvedName);
  const evidenceDir = path.join(profileDir, "evidence");
  fs.mkdirSync(evidenceDir, { recursive: true });

  return {
    rangeDir,
    profileDir,
    profilePath: path.join(profileDir, "profile.md"),
    evidenceDir,
  };
}

// Security headers we check for
const SECURITY_HEADERS = {
  "strict-transport-security": { severity: "big", description: "HSTS - Forces HTTPS connections" },
  "content-security-policy": { severity: "big", description: "CSP - Prevents XSS attacks" },
  "x-frame-options": { severity: "medium", description: "Prevents clickjacking" },
  "x-content-type-options": { severity: "medium", description: "Prevents MIME sniffing" },
  "referrer-policy": { severity: "small", description: "Controls referrer information" },
  "permissions-policy": { severity: "small", description: "Controls browser features" },
  "x-xss-protection": { severity: "small", description: "Legacy XSS filter (deprecated but still checked)" },
};

// Tech stack signatures
const TECH_SIGNATURES = {
  cms: {
    wordpress: [/wp-content|wp-includes|wp-json|xmlrpc\.php/i],
    squarespace: [/squarespace|static\.sqspcdn\.com/i],
    wix: [/wix\.com|wixstatic\.com|wixcode\.com/i],
    shopify: [/shopify|myshopify\.com|cdn\.shopify\.com/i],
    webflow: [/webflow|assets\.website-files\.com/i],
    drupal: [/drupal|\/sites\/default\/files/i],
    joomla: [/joomla|\/media\/jui/i],
    ghost: [/ghost|ghost\.org/i],
  },
  frameworks: {
    react: [/react|react\.production|react-dom/i],
    vue: [/vue|vue\.runtime|vuejs/i],
    angular: [/angular|ng-version|angular\.io/i],
    jquery: [/jquery|jquery-\d/i],
    nextjs: [/__next|_next\/static/i],
    svelte: [/svelte|svelte\./i],
  },
  analytics: {
    google_analytics: [/google-analytics\.com|gtag|ga\.js|analytics\.js/i],
    google_tag_manager: [/googletagmanager\.com|gtm\.js/i],
    facebook_pixel: [/connect\.facebook\.net.*fbevents|fbq\(/i],
    hotjar: [/hotjar|static\.hotjar\.com/i],
    clarity: [/clarity\.ms|clarity-js/i],
    mixpanel: [/mixpanel|cdn\.mxpnl\.com/i],
  },
  hosting: {
    cloudflare: [/cloudflare|cf-ray/i],
    aws: [/amazonaws|aws|cloudfront/i],
    google_cloud: [/googleapis|gstatic|gcp/i],
    azure: [/azure|azureedge|windows\.net/i],
    vercel: [/vercel|now\.sh/i],
    netlify: [/netlify|netlify\.com/i],
  },
};

// Sensitive files to probe
const SENSITIVE_PATHS = [
  // Source control
  "/.git/config",
  "/.git/HEAD",
  "/.gitignore",
  "/.svn/entries",
  "/.hg/store/data",
  
  // Environment & config files
  "/.env",
  "/.env.local",
  "/.env.production",
  "/.env.development",
  "/.env.staging",
  "/config/.env",
  "/app/.env",
  "/api/.env",
  
  // Backup files
  "/backup.sql",
  "/backup.sql.gz",
  "/backup.zip",
  "/backup.tar.gz",
  "/db_backup.sql",
  "/database.sql",
  "/dump.sql",
  
  // Config files
  "/wp-config.php",
  "/wp-config.php.bak",
  "/wp-config.php~",
  "/configuration.php",
  "/config.php",
  "/config.php.bak",
  "/settings.php",
  "/local.xml",
  "/app/etc/local.xml",
  
  // CMS specific
  "/administrator/.htaccess",
  "/admin/.htaccess",
  "/.htaccess",
  "/.htpasswd",
  
  // Logs & debug
  "/error_log",
  "/debug.log",
  "/php_error.log",
  "/server.log",
  "/access.log",
  
  // IDE & editor files
  "/.idea/",
  "/.vscode/",
  "/.project",
  "/.settings/",
  "*.swp",
  "*.swo",
  
  // Package files (may contain secrets)
  "/package.json",
  "/composer.json",
  "/Gemfile",
  
  // API endpoints
  "/.well-known/security.txt",
  "/server-status",
  "/server-info",
  "/phpinfo.php",
  "/info.php",
  "/test.php",
  
  // Cloud metadata
  "/.well-known/openid-configuration",
];

// Sensitive files with metadata
const SENSITIVE_FILES = {
  // Source control - these have very specific content
  "/.git/config": { type: "git", severity: "critical", description: "Git repository config exposed", indicators: ["[core]", "[remote", "[branch"] },
  "/.git/HEAD": { type: "git", severity: "critical", description: "Git HEAD file exposed", indicators: ["ref: refs/heads"] },
  "/.svn/entries": { type: "svn", severity: "critical", description: "SVN entries exposed", indicators: ["svn:", "text-base", "prop-base"] },
  "/.hg/store/data": { type: "hg", severity: "high", description: "Mercurial repo data exposed", indicators: ["data/", ".i\n", ".d\n"] },
  
  // Environment files - must have KEY=VALUE patterns, not just "="
  "/.env": { type: "env", severity: "critical", description: "Environment file exposed", indicators: ["DB_", "API_KEY=", "SECRET=", "PASSWORD=", "TOKEN="] },
  "/.env.local": { type: "env", severity: "critical", description: "Local environment file exposed", indicators: ["DB_", "API_KEY=", "SECRET=", "PASSWORD="] },
  "/.env.production": { type: "env", severity: "critical", description: "Production environment file exposed", indicators: ["DB_", "API_KEY=", "SECRET=", "PASSWORD="] },
  "/.env.development": { type: "env", severity: "high", description: "Development environment file exposed", indicators: ["DB_", "API_KEY=", "SECRET="] },
  "/config/.env": { type: "env", severity: "critical", description: "Config environment file exposed", indicators: ["DB_", "API_KEY=", "SECRET="] },
  
  // Backup files - SQL specific patterns
  "/backup.sql": { type: "backup", severity: "critical", description: "SQL backup file exposed", indicators: ["CREATE TABLE", "INSERT INTO", "DROP TABLE"] },
  "/backup.sql.gz": { type: "backup", severity: "critical", description: "Compressed SQL backup exposed", indicators: [], binary: true },
  "/database.sql": { type: "backup", severity: "critical", description: "Database dump exposed", indicators: ["CREATE TABLE", "INSERT INTO"] },
  "/dump.sql": { type: "backup", severity: "critical", description: "Database dump exposed", indicators: ["CREATE TABLE", "INSERT INTO"] },
  
  // Config files - CMS specific patterns
  "/wp-config.php": { type: "config", severity: "critical", description: "WordPress config exposed", indicators: ["DB_NAME", "DB_USER", "DB_PASSWORD", "$table_prefix"] },
  "/wp-config.php.bak": { type: "config", severity: "critical", description: "WordPress config backup exposed", indicators: ["DB_NAME", "DB_USER", "DB_PASSWORD"] },
  "/configuration.php": { type: "config", severity: "critical", description: "Joomla config exposed", indicators: ["JConfig", "public $", "private $"] },
  "/config.php": { type: "config", severity: "high", description: "Config file exposed", indicators: ["<?php", "$config", "$settings"] },
  "/settings.php": { type: "config", severity: "high", description: "Settings file exposed", indicators: ["<?php", "$settings"] },
  
  // Server files
  "/.htaccess": { type: "htaccess", severity: "medium", description: "Apache config exposed", indicators: ["RewriteEngine", "RewriteRule", "AuthType", "Deny from"] },
  "/.htpasswd": { type: "htpasswd", severity: "critical", description: "Apache password file exposed", indicators: [], htpasswd: true }, // username:encrypted_password format
  "/phpinfo.php": { type: "phpinfo", severity: "high", description: "PHP info page exposed", indicators: ["phpinfo()", "PHP Version", "Configuration"] },
  "/info.php": { type: "phpinfo", severity: "high", description: "PHP info page exposed", indicators: ["phpinfo()", "PHP Version", "Configuration"] },
  "/server-status": { type: "server", severity: "medium", description: "Apache server status exposed", indicators: ["Apache Server Status", "Server Version:", "Current Time:"] },
  "/server-info": { type: "server", severity: "medium", description: "Apache server info exposed", indicators: ["Apache Server Information", "Server Version", "Server Settings"] },
  
  // Log files - but not generic HTML error pages
  "/error_log": { type: "log", severity: "medium", description: "Error log exposed", indicators: ["[error]", "[warning]", "Fatal error:", "PHP Fatal"] },
  "/debug.log": { type: "log", severity: "medium", description: "Debug log exposed", indicators: ["[debug]", "[DEBUG]", "DEBUG:" ] },
  "/access.log": { type: "log", severity: "low", description: "Access log exposed", indicators: ["GET /", "POST /", 'HTTP/1.'] },
  
  // IDE files - check for project files
  "/.idea/workspace.xml": { type: "ide", severity: "low", description: "JetBrains workspace exposed", indicators: ["<project", "<component"] },
  "/.vscode/settings.json": { type: "ide", severity: "low", description: "VS Code settings exposed", indicators: [] },
  
  // Cloud metadata
  "/.well-known/security.txt": { type: "security", severity: "info", description: "Security contact file", indicators: ["Contact:", "Expires:"], reportOnly: true },
};

// API key patterns to detect in page content
const API_KEY_PATTERNS = [
  // AWS
  { regex: /AKIA[0-9A-Z]{16}/g, type: "AWS Access Key", severity: "critical", confidence: "probable" },
  { regex: /aws_access_key_id\s*[=:]\s*['"][A-Z0-9]{20}['"]/gi, type: "AWS Access Key", severity: "critical", confidence: "verified" },
  { regex: /aws_secret_access_key\s*[=:]\s*['"][A-Za-z0-9/+=]{40}['"]/gi, type: "AWS Secret Key", severity: "critical", confidence: "verified" },
  
  // Google
  { regex: /AIza[0-9A-Za-z\-_]{35}/g, type: "Google API Key", severity: "medium", confidence: "unverified" },
  { regex: /ya29\.[0-9A-Za-z\-_]+/g, type: "Google OAuth Token", severity: "critical", confidence: "verified" },
  { regex: /[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com/g, type: "Google Client ID", severity: "info", confidence: "unverified" },
  
  // Stripe
  { regex: /sk_live_[0-9a-zA-Z]{24}/g, type: "Stripe Live Secret Key", severity: "critical", confidence: "verified" },
  { regex: /sk_test_[0-9a-zA-Z]{24}/g, type: "Stripe Test Secret Key", severity: "high", confidence: "probable" },
  { regex: /pk_live_[0-9a-zA-Z]{24}/g, type: "Stripe Live Publishable Key", severity: "info", confidence: "unverified" },
  { regex: /rk_live_[0-9a-zA-Z]{24}/g, type: "Stripe Live Restricted Key", severity: "critical", confidence: "verified" },
  
  // GitHub
  { regex: /ghp_[0-9a-zA-Z]{36}/g, type: "GitHub Personal Access Token", severity: "critical", confidence: "verified" },
  { regex: /gho_[0-9a-zA-Z]{36}/g, type: "GitHub OAuth Token", severity: "critical", confidence: "verified" },
  { regex: /ghu_[0-9a-zA-Z]{36}/g, type: "GitHub User Token", severity: "critical", confidence: "verified" },
  { regex: /ghs_[0-9a-zA-Z]{36}/g, type: "GitHub Server Token", severity: "critical", confidence: "verified" },
  { regex: /ghr_[0-9a-zA-Z]{36}/g, type: "GitHub Refresh Token", severity: "critical", confidence: "verified" },
  
  // Slack
  { regex: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}/g, type: "Slack Token", severity: "critical", confidence: "verified" },
  { regex: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}/g, type: "Slack Token", severity: "critical", confidence: "verified" },
  
  // Twilio
  { regex: /SK[0-9a-fA-F]{32}/g, type: "Twilio API Key", severity: "critical", confidence: "verified" },
  { regex: /AC[a-f0-9]{32}/g, type: "Twilio Account SID", severity: "info", confidence: "unverified" },
  
  // SendGrid
  { regex: /SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}/g, type: "SendGrid API Key", severity: "critical", confidence: "verified" },
  
  // Mailgun
  { regex: /key-[0-9a-zA-Z]{32}/g, type: "Mailgun API Key", severity: "critical", confidence: "verified" },
  
  // Mailchimp
  { regex: /[0-9a-f]{32}-us[0-9]{1,2}/g, type: "Mailchimp API Key", severity: "critical", confidence: "verified" },
  
  // Private keys
  { regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g, type: "Private Key", severity: "critical", confidence: "verified" },
  { regex: /-----BEGIN PGP PRIVATE KEY BLOCK-----/g, type: "PGP Private Key", severity: "critical", confidence: "verified" },
  
  // JWT secrets (common patterns)
  { regex: /jwt[_-]?secret['"]\s*[:=]\s*['"][^'"]+['"]/gi, type: "JWT Secret", severity: "critical", confidence: "verified" },
  { regex: /jwt[_-]?key['"]\s*[:=]\s*['"][^'"]+['"]/gi, type: "JWT Key", severity: "critical", confidence: "verified" },
  
  // Generic secrets
  { regex: /secret[_-]?key['"]\s*[:=]\s*['"][^'"]{16,}['"]/gi, type: "Secret Key", severity: "medium", confidence: "probable" },
  { regex: /api[_-]?key['"]\s*[:=]\s*['"][^'"]{16,}['"]/gi, type: "API Key", severity: "medium", confidence: "probable" },
  { regex: /access[_-]?token['"]\s*[:=]\s*['"][^'"]{16,}['"]/gi, type: "Access Token", severity: "high", confidence: "unverified" },
  { regex: /auth[_-]?token['"]\s*[:=]\s*['"][^'"]{16,}['"]/gi, type: "Auth Token", severity: "high", confidence: "unverified" },
  { regex: /private[_-]?key['"]\s*[:=]\s*['"][^'"]{16,}['"]/gi, type: "Private Key Reference", severity: "high", confidence: "probable" },
  
  // Database connection strings
  { regex: /mongodb(\+srv)?:\/\/[^:]+:[^@]+@[^\s'"]+/gi, type: "MongoDB Connection String", severity: "critical", confidence: "verified" },
  { regex: /mysql:\/\/[^:]+:[^@]+@[^\s'"]+/gi, type: "MySQL Connection String", severity: "critical", confidence: "verified" },
  { regex: /postgres(ql)?:\/\/[^:]+:[^@]+@[^\s'"]+/gi, type: "PostgreSQL Connection String", severity: "critical", confidence: "verified" },
  { regex: /redis:\/\/[^:]*:[^@]+@[^\s'"]+/gi, type: "Redis Connection String", severity: "critical", confidence: "verified" },
  
  // Firebase
  { regex: /AIza[0-9A-Za-z\-_]{35}/g, type: "Firebase API Key", severity: "info", confidence: "unverified" },
];

const PUBLIC_TOKEN_CONTEXT_PATTERNS = [
  /storefront/i,
  /publishable/i,
  /public/i,
  /client[_-]?id/i,
  /shopify/i,
  /widget/i,
  /analytics/i,
];

const PUBLIC_IDENTIFIER_TYPES = new Set([
  "Google Client ID",
  "Stripe Live Publishable Key",
  "Twilio Account SID",
  "Firebase API Key",
]);

function extractApiKeysFromPageContent(pageContent) {
  const findings = [];

  for (const pattern of API_KEY_PATTERNS) {
    const matches = Array.from(pageContent.matchAll(pattern.regex));
    const keptMatches = [];

    for (const match of matches) {
      const matchText = match[0];
      const matchIndex = match.index || 0;
      const contextWindow = pageContent.slice(Math.max(0, matchIndex - 80), Math.min(pageContent.length, matchIndex + matchText.length + 80));

      if (
        (pattern.type === "Access Token" || pattern.type === "Auth Token" || pattern.type === "API Key" || pattern.type === "Secret Key") &&
        PUBLIC_TOKEN_CONTEXT_PATTERNS.some((ctx) => ctx.test(contextWindow))
      ) {
        continue;
      }

      keptMatches.push(matchText);
    }

    if (keptMatches.length > 0) {
      let severity = pattern.severity;
      let confidence = pattern.confidence || "probable";
      if (PUBLIC_IDENTIFIER_TYPES.has(pattern.type)) {
        severity = "info";
        confidence = "unverified";
      }
      findings.push({
        type: pattern.type,
        count: keptMatches.length,
        severity,
        confidence,
        samples: keptMatches.slice(0, 3).map((m) => m.substring(0, 15) + '...'),
      });
    }
  }

  return findings;
}

// Risky endpoints to probe
const RISKY_ENDPOINTS = [
  { path: "/.git/config", type: "git", severity: "critical", description: "Git config exposed", indicators: ["[core]", "[remote \"origin\"]", "[branch]"], requiredCount: 2 },
  { path: "/.env", type: "env", severity: "critical", description: "Environment file exposed", indicators: ["DB_PASSWORD", "API_KEY", "SECRET_KEY", "AWS_SECRET", "DATABASE_URL"], requiredCount: 1 },
  { path: "/.env.local", type: "env", severity: "critical", description: "Local environment file exposed", indicators: ["DB_PASSWORD", "API_KEY", "SECRET_KEY", "AWS_SECRET"], requiredCount: 1 },
  { path: "/wp-config.php", type: "config", severity: "critical", description: "WordPress config exposed", indicators: ["DB_NAME", "DB_USER", "DB_PASSWORD", "wp-settings.php"], requiredCount: 2 },
  { path: "/wp-config.php.bak", type: "config", severity: "critical", description: "WordPress config backup exposed", indicators: ["DB_NAME", "DB_USER", "DB_PASSWORD"], requiredCount: 2 },
  { path: "/phpinfo.php", type: "phpinfo", severity: "high", description: "PHP info exposed", indicators: ["phpinfo()", "PHP Version", "Configuration"], requiredCount: 2 },
  { path: "/server-status", type: "server", severity: "medium", description: "Apache server status", indicators: ["Apache Server Status", "Server Version", "Current Time"], requiredCount: 2 },
  { path: "/.htpasswd", type: "htpasswd", severity: "critical", description: "Apache password file", indicators: null, contentPattern: /^[a-zA-Z0-9_-]+:\$apr1\$/ },
  { path: "/backup.sql", type: "backup", severity: "critical", description: "SQL backup exposed", indicators: ["CREATE TABLE", "INSERT INTO", "DROP TABLE"], requiredCount: 2 },
  { path: "/backup.sql.gz", type: "backup", severity: "critical", description: "Compressed SQL backup exposed", indicators: null, binaryCheck: true },
  { path: "/dump.sql", type: "backup", severity: "critical", description: "SQL dump exposed", indicators: ["CREATE TABLE", "INSERT INTO"], requiredCount: 1 },
  { path: "/config.php.bak", type: "config", severity: "high", description: "PHP config backup exposed", indicators: ["<?php", "password", "config"], requiredCount: 2 },
  { path: "/web.config", type: "config", severity: "medium", description: "IIS config exposed", indicators: ["<configuration>", "connectionStrings", "appSettings"], requiredCount: 2 },
  { path: "/.svn/entries", type: "svn", severity: "high", description: "SVN entries exposed", indicators: ["dir ", "file "], requiredCount: 1 },
  { path: "/composer.json", type: "config", severity: "low", description: "Composer config exposed", indicators: ["require", "autoload"], requiredCount: 1, reportOnly: true },
  { path: "/package.json", type: "config", severity: "low", description: "NPM package config exposed", indicators: ["dependencies", "scripts"], requiredCount: 1, reportOnly: true },
];

// Social media patterns
const SOCIAL_PATTERNS = {
  facebook: [/facebook\.com\/(?!sharer|share\.php|plugins|dialog|common|login|signup|help|policy|legal|ads|business|pages\/create|marketplace|messenger|watch|gaming|groups|events|friends|bookmarks|notifications|settings|photo\.php|media|photo|album|videos|notes|games|apps|developers|graph|connect|platform|plugins|widget|like\.php|share\.php)([a-zA-Z0-9._-]+)/i],
  instagram: [/instagram\.com\/(?!p\/|reel\/|explore|accounts|stories|tv|challenge|qr|directory|create|legal|about|help|developer|api|static)([a-zA-Z0-9._]+)/i],
  twitter: [/twitter\.com\/(?!status|intent|home|search|explore|notifications|messages|settings|i|hashtag|following|followers|likes|lists|moments|account|compose|oauth|share|statuses)([a-zA-Z0-9_]+)/i],
  linkedin: [/linkedin\.com\/company\/([a-zA-Z0-9_-]+)/i, /linkedin\.com\/in\/([a-zA-Z0-9_-]+)/i],
  youtube: [/youtube\.com\/(channel|user|c)\/([a-zA-Z0-9_-]+)/i, /youtube\.com\/@([a-zA-Z0-9_-]+)/i],
  tiktok: [/tiktok\.com\/@([a-zA-Z0-9_.]+)/i],
  pinterest: [/pinterest\.com\/([a-zA-Z0-9_-]+)/i],
  yelp: [/yelp\.com\/biz\/([a-zA-Z0-9_-]+)/i],
  tripadvisor: [/tripadvisor\.com\/(Restaurant_Review|Hotel_Review|Attraction_Review)/i],
  nextdoor: [/nextdoor\.com\/pages\/([a-zA-Z0-9_-]+)/i],
  angieslist: [/angieslist\.com\/companylistings\/([a-zA-Z0-9_-]+)/i, /angi\.com\/company\/([a-zA-Z0-9_-]+)/i],
};

// Result object
const result = {
  leadId,
  domain: normalizedDomain,
  testUrl,
  timestamp: new Date().toISOString(),
  ssl: { valid: false, issuer: null, expires: null, daysUntilExpiry: null, error: null },
  https: { enabled: false, redirects: false, error: null },
  securityHeaders: {},
  cookies: [],
  cookieSecurity: { findings: [], sessionCookies: [], authCookies: [], csrfCookies: [], analyticsCookies: [] },
  mixedContent: { found: false, resources: [] },
  consoleErrors: [],
  consoleWarnings: [],
  pageErrors: [],
  performance: { 
    loadTime: null, 
    domContentLoaded: null, 
    firstPaint: null, 
    firstContentfulPaint: null,
    largestContentfulPaint: null,
    cumulativeLayoutShift: null,
    interactionToNextPaint: null,
  },
  techStack: { cms: null, frameworks: [], analytics: [], hosting: [] },
  seo: { title: null, metaDescription: null, h1: null, h1Count: 0, images: 0, imagesWithoutAlt: 0, links: 0, canonical: null },
  mobile: { friendly: false, viewport: null, navWorks: false },
  forms: { found: false, totalForms: 0, forms: [], secureForms: 0, insecureForms: 0, issues: [], contactPage: null },
  formAnalysis: null,
  brokenImages: [],
  adminEndpoints: { found: [], accessible: [] },
  emailAuth: { spf: null, dmarc: null, dkim: null },
  thirdPartyScripts: null,
  dnsRecords: { mx: [], ns: [], a: [] },
  // New fields
  contacts: { emails: [], phones: [], socials: {} },
  address: { raw: null, street: null, city: null, state: null, zip: null, country: null, coordinates: null },
  businessInfo: { name: null, tagline: null, description: null, hours: null, services: [], founded: null, employeeCount: null, hasReviews: false, hasTestimonials: false, isUnderConstruction: false },
  brokenLinks: { checked: 0, broken: [], internal: [], external: [] },
  enrichment: null,
  paymentSecurity: { hasPaymentSurface: false, hostedThirdPartyCheckout: false, onSiteCardCollectionForms: 0, providers: [], findings: [] },
  securityOutreach: { primaryHook: null, verifiedHooks: [], probableHooks: [] },
  sensitiveExposures: { sensitiveFiles: [], exposedGit: false, exposedEnv: false, exposedConfig: false, apiKeys: [], riskyEndpoints: [] },
  seoFiles: { robotsTxt: null, sitemap: null },
  cookieConsent: { detected: false, type: null },
  // Lead Intelligence fields
  leadIntelligence: {
    ecommerce: { detected: false, platform: null, hasCart: false, hasCheckout: false, products: 0, paymentMethods: [] },
    socialProfiles: { linkedin: null, facebook: null, instagram: null, twitter: null, youtube: null, tiktok: null, yelp: null, gmb: null },
    teamInfo: { hasTeamPage: false, teamPageUrl: null, employeeCount: null, keyPeople: [] },
    growthSignals: { hiring: false, jobListings: [], expansion: false, expansionSignals: [], fundingStage: null },
    reputation: { hasReviews: false, reviewPlatforms: [], rating: null, reviewCount: 0, hasTestimonials: false },
    newsletter: { detected: false, provider: null, formUrl: null },
    yearsInBusiness: { estimated: null, source: null, foundedYear: null },
    industryClassification: { primary: null, secondary: [], naics: null },
    serviceArea: { type: null, regions: [], hasServiceAreaPage: false }
  },
  auditScore: 0,
  criticalIssues: [],
  warnings: [],
  screenshots: { desktop: null, mobile: null },
  renderTimeout: false, // Flag set when page load times out
  botBlocker: { detected: false, name: null, blocked: false }, // Bot blocker detection (cloudflare, akamai, etc.)
  botBlocked: false, // Flag set when bot blocker detected (Cloudflare, etc.)
  botBlockerType: null, // Type of bot blocker: 'cloudflare', 'akamai', etc.
  siteAvailability: { reachable: false, method: null, statusCode: null, blockerHint: null }, // Site availability check (curl/googlebot/chrome)
  jsErrorAnalysis: {
    auditMode: "light-default-with-clean-verification",
    cleanPass: { attempted: false, succeeded: false, blocked: false, finalUrl: null, status: null },
    rawConsoleErrors: [],
    rawPageErrors: [],
    verifiedConsoleErrors: [],
    verifiedPageErrors: [],
    provisionalConsoleErrors: [],
    provisionalPageErrors: [],
    scannerInducedConsoleErrors: [],
    scannerInducedPageErrors: [],
  },
  findingConfidence: {
    verified: [],
    probable: [],
    observedUnderInstrumentation: [],
    unverified: [],
  },
};

const SCANNER_INDUCED_ERROR_PATTERNS = [
  /nativeToStringFunctionString\.call is not a function/i,
  /\bjQuery is not defined\b/i,
  /\belementorModules is not defined\b/i,
  /Cannot set properties of undefined \(setting 'payment'\)/i,
  /Cannot read properties of undefined \(reading 'init'\)/i,
  /\ba\.getterFor is not a function\b/i,
  /^\s*e is not a function\s*$/i,
];

function normalizeObservedMessage(message) {
  return String(message || "")
    .replace(/\s+/g, " ")
    .trim();
}

function normalizeCookieName(name) {
  return String(name || "").trim().toLowerCase();
}

function isLikelyAnalyticsCookieName(name) {
  return /^(_ga|_gid|_gat|_fbp|_gcl_au|hubspotutk|_hj|ajs_|mp_|sbjs_|_scc_)/i.test(String(name || ""));
}

function isKnownFrameworkNoiseCookieName(name) {
  const normalized = normalizeCookieName(name);
  if (!normalized) return false;
  return (
    /^(__cf_bm|cf_clearance|_cfuvid)$/i.test(normalized) ||
    /^_shopify/i.test(normalized) ||
    /^(cart_currency|localization|keep_alive|secure_customer_sig|tracked_start_checkout|cart_sig|cart_ts)$/i.test(normalized) ||
    /^(__stripe_mid|__stripe_sid)$/i.test(normalized) ||
    /^(_paypal_storage__|tsrce|l7_az)$/i.test(normalized) ||
    /^intercom-/i.test(normalized) ||
    /^cookieyes/i.test(normalized)
  );
}

function isLikelyCsrfCookieName(name) {
  return /(^|[_.-])(csrf|xsrf|__requestverificationtoken|csrftoken|_csrf|csrf-token)($|[_.-])/i.test(String(name || ""));
}

function isHighConfidenceSessionCookieName(name) {
  const normalized = normalizeCookieName(name);
  if (!normalized) return false;
  return [
    "phpsessid",
    "connect.sid",
    "laravel_session",
    "sessionid",
    "jsessionid",
    "ci_session",
    "cfid",
    "cftoken",
    "asp.net_sessionid",
    "aspsessionid",
    "wordpress_logged_in",
    "wordpress_sec",
  ].includes(normalized) || /^woocommerce_session_/i.test(normalized);
}

function isHighConfidenceAuthCookieName(name) {
  const normalized = normalizeCookieName(name);
  if (!normalized) return false;
  return [
    "auth",
    "authorization",
    "remember_me",
    "remember_token",
    "id_token",
    "access_token",
    "refresh_token",
    "jwt",
    "wordpress_logged_in",
    "wordpress_sec",
  ].includes(normalized) || /(^|[_-])(auth|logged_in|remember|jwt|id_token|access_token|refresh_token|auth_token)($|[_-])/i.test(normalized);
}

function isAmbiguousSessionCookieName(name) {
  const normalized = normalizeCookieName(name);
  if (!normalized || isLikelyAnalyticsCookieName(normalized) || isLikelyCsrfCookieName(normalized)) {
    return false;
  }
  return (
    /(^|[_-])(session|sess|sid)($|[_-])/i.test(normalized) ||
    /(^|[_-])(session|sess|sid)$/i.test(normalized) ||
    /^__host-session$/i.test(normalized) ||
    /^__secure-session$/i.test(normalized)
  );
}

function isAmbiguousAuthCookieName(name) {
  const normalized = normalizeCookieName(name);
  if (!normalized || isLikelyAnalyticsCookieName(normalized) || isLikelyCsrfCookieName(normalized)) {
    return false;
  }
  return /(^|[_-])(auth|login|logged_in|remember|identity|id|token)($|[_-])/i.test(normalized);
}

function getCookieContextSignals(cookie = {}, result = {}) {
  const normalized = normalizeCookieName(cookie.name);
  const forms = result.forms?.forms || [];
  const hasPasswordForm = forms.some((form) => form.hasPasswordField);
  const hasAccountForm = forms.some((form) => {
    const action = String(form.action || "").toLowerCase();
    return form.hasPasswordField || /(login|signin|sign-in|account|profile|reset|register|admin|dashboard|portal)/i.test(action);
  });
  const hasCheckoutForm = forms.some((form) => {
    const action = String(form.action || "").toLowerCase();
    return form.hasCreditCardField || /(checkout|billing|payment|donat|subscribe|order)/i.test(action);
  });
  const hasObservedAdminSurface = (result.adminEndpoints?.found || []).length > 0;
  const backend = String(result.techStack?.backend || "").toLowerCase();
  const frameworks = Array.isArray(result.techStack?.frameworks) ? result.techStack.frameworks.join(" ").toLowerCase() : "";
  const signals = [];

  if (cookie.httpOnly === true) signals.push("httpOnly");
  if (cookie.secure === true) signals.push("secure");
  if (cookie.sameSite) signals.push(`sameSite:${String(cookie.sameSite).toLowerCase()}`);
  if (/^(__host-|__secure-)/i.test(normalized)) signals.push("cookie-prefix");
  if (hasPasswordForm) signals.push("password-form");
  if (hasAccountForm) signals.push("account-form");
  if (hasCheckoutForm) signals.push("checkout-form");
  if (hasObservedAdminSurface) signals.push("admin-surface");
  if (/(django|laravel|rails|express|node|wordpress|woocommerce|asp\.net|java)/i.test(`${backend} ${frameworks}`)) {
    signals.push("known-backend");
  }
  if (/(^|[_-])(session|sess|sid|auth|login|remember|token)($|[_-])/i.test(normalized)) {
    signals.push("name-hint");
  }

  return signals;
}

function hasFrameworkCookieAffinity(cookie = {}, result = {}) {
  const normalized = normalizeCookieName(cookie.name);
  const backend = String(result.techStack?.backend || "").toLowerCase();
  const frameworks = Array.isArray(result.techStack?.frameworks) ? result.techStack.frameworks.join(" ").toLowerCase() : "";
  const fingerprint = `${backend} ${frameworks}`;

  if (!normalized || !fingerprint.trim()) {
    return false;
  }

  if (/wordpress|woocommerce/.test(fingerprint) && (/^wordpress_(logged_in|sec)/i.test(normalized) || /^woocommerce_session_/i.test(normalized))) {
    return true;
  }
  if (/laravel/.test(fingerprint) && /^(laravel_session|xsrf-token)$/i.test(normalized)) {
    return true;
  }
  if (/django/.test(fingerprint) && /^(sessionid|csrftoken)$/i.test(normalized)) {
    return true;
  }
  if (/(express|node)/.test(fingerprint) && /^(connect\.sid|express:sess|express:sess\.sig)$/i.test(normalized)) {
    return true;
  }
  if (/rails/.test(fingerprint) && /^(_.+_session|_session)$/i.test(normalized)) {
    return true;
  }
  if (/asp\.net/.test(fingerprint) && /^(asp\.net_sessionid|\.aspnetcore\..+)/i.test(normalized)) {
    return true;
  }
  if (/java/.test(fingerprint) && /^jsessionid$/i.test(normalized)) {
    return true;
  }
  if (/(next\.js|nextjs|next-auth|auth\.js)/.test(fingerprint) && /^(next-auth|authjs)\./i.test(normalized)) {
    return true;
  }

  return false;
}

function hasStrongSessionCookieContext(cookie = {}, result = {}) {
  const signals = getCookieContextSignals(cookie, result);
  const protectiveScore =
    (signals.includes("httpOnly") ? 2 : 0) +
    (signals.includes("secure") ? 1 : 0) +
    (signals.some((entry) => entry.startsWith("sameSite:")) ? 1 : 0) +
    (signals.includes("cookie-prefix") ? 1 : 0);
  const appSurfaceSignals = ["password-form", "account-form", "admin-surface"];
  const hasMeaningfulAppSurface = appSurfaceSignals.some((signal) => signals.includes(signal));

  return hasFrameworkCookieAffinity(cookie, result) || (hasMeaningfulAppSurface && protectiveScore >= 2);
}

function classifyCookieSecuritySignals(cookie = {}, result = {}) {
  const normalized = normalizeCookieName(cookie.name);
  const analytics = isLikelyAnalyticsCookieName(normalized);
  const csrf = isLikelyCsrfCookieName(normalized);
  const frameworkNoise = isKnownFrameworkNoiseCookieName(normalized);
  const contextSignals = getCookieContextSignals(cookie, result);
  const session = !frameworkNoise && (isHighConfidenceSessionCookieName(normalized) || (isAmbiguousSessionCookieName(normalized) && hasStrongSessionCookieContext(cookie, result)));
  const auth = !frameworkNoise && (isHighConfidenceAuthCookieName(normalized) || (
    isAmbiguousAuthCookieName(normalized) &&
    (contextSignals.includes("password-form") || contextSignals.includes("account-form") || contextSignals.includes("admin-surface")) &&
    (contextSignals.includes("httpOnly") || contextSignals.includes("secure")) &&
    !contextSignals.includes("checkout-form")
  ));
  return { analytics, csrf, session, auth, contextSignals, frameworkNoise };
}

function determineSensitiveSurfaceContext(result) {
  const forms = result.forms?.forms || [];
  const hasSensitiveForms = forms.some((form) => form.hasPasswordField || form.hasCreditCardField || form.hasSsnField);
  const hasPaymentSurface = !!result.paymentSecurity?.hasPaymentSurface || forms.some((form) => form.hasCreditCardField);
  const hasObservedAdminSurface = (result.adminEndpoints?.found || []).length > 0;
  const hasSessionCookies = (result.cookieSecurity?.sessionCookies || []).length > 0;
  return {
    hasSensitiveForms,
    hasPaymentSurface,
    hasObservedAdminSurface,
    hasSessionCookies,
    highRiskSurface: hasSensitiveForms || hasPaymentSurface || hasObservedAdminSurface || hasSessionCookies,
  };
}

function getMissingHeaderSeverity(header, result) {
  const context = determineSensitiveSurfaceContext(result);
  switch (header) {
    case "strict-transport-security":
      return context.highRiskSurface ? "warning" : "info";
    case "content-security-policy":
      return context.hasSensitiveForms || context.hasPaymentSurface || (result.thirdPartyScripts?.thirdParty?.length || 0) > 5 ? "warning" : "info";
    case "x-frame-options":
      return context.hasSensitiveForms || context.hasObservedAdminSurface ? "warning" : "info";
    case "x-content-type-options":
      return context.highRiskSurface ? "warning" : "info";
    case "referrer-policy":
    case "permissions-policy":
      return "info";
    default:
      return "info";
  }
}

function analyzeCookieSecurity(cookies = [], result = {}) {
  const analysis = {
    findings: [],
    sessionCookies: [],
    authCookies: [],
    csrfCookies: [],
    analyticsCookies: [],
  };

  for (const cookie of cookies) {
    const name = String(cookie.name || "");
    const normalizedSameSite = cookie.sameSite ? String(cookie.sameSite) : null;
    const { session: isSession, auth: isAuth, csrf: isCsrf, analytics: isAnalytics, frameworkNoise } = classifyCookieSecuritySignals(cookie, result);

    if (isSession) analysis.sessionCookies.push(name);
    if (isAuth) analysis.authCookies.push(name);
    if (isCsrf) analysis.csrfCookies.push(name);
    if (isAnalytics) analysis.analyticsCookies.push(name);

    if (frameworkNoise && !(isCsrf || isSession || isAuth)) {
      continue;
    }

    if (!(isSession || isAuth || isCsrf)) {
      continue;
    }

    if ((isSession || isAuth) && !cookie.secure) {
      analysis.findings.push({
        tier: "verified",
        severity: "critical",
        message: `Session/auth cookie missing Secure flag: ${name}`,
        evidence: { cookie: name, domain: cookie.domain || null },
      });
    }

    if ((isSession || isAuth) && !cookie.httpOnly) {
      analysis.findings.push({
        tier: "probable",
        severity: "warning",
        message: `Session/auth cookie readable by client script: ${name}`,
        evidence: { cookie: name, domain: cookie.domain || null },
      });
    }

    if ((isSession || isAuth) && !normalizedSameSite) {
      analysis.findings.push({
        tier: "probable",
        severity: "info",
        message: `Session/auth cookie missing SameSite attribute: ${name}`,
        evidence: { cookie: name, domain: cookie.domain || null },
      });
    }

    if ((isSession || isAuth) && /^none$/i.test(normalizedSameSite || "") && !cookie.secure) {
      analysis.findings.push({
        tier: "verified",
        severity: "warning",
        message: `Session/auth cookie uses SameSite=None without Secure: ${name}`,
        evidence: { cookie: name, domain: cookie.domain || null },
      });
    }

    if (isCsrf && !cookie.secure) {
      analysis.findings.push({
        tier: "probable",
        severity: "warning",
        message: `CSRF-related cookie missing Secure flag: ${name}`,
        evidence: { cookie: name, domain: cookie.domain || null },
      });
    }
  }

  return analysis;
}

function normalizePaymentProviderName(name) {
  const normalized = String(name || "").trim().toLowerCase();
  if (!normalized) return null;
  const aliases = {
    stripe: "Stripe",
    paypal: "PayPal",
    square: "Square",
    applepay: "Apple Pay",
    googlepay: "Google Pay",
    afterpay: "Afterpay",
    klarna: "Klarna",
    affirm: "Affirm",
    braintree: "Braintree",
    "authorize.net": "Authorize.net",
    authorize_net: "Authorize.net",
    woo: "WooCommerce",
    woocommerce: "WooCommerce",
  };
  return aliases[normalized] || String(name).trim();
}

function getPaymentProviderSignals(result = {}) {
  const signals = new Set();

  for (const provider of result.leadIntelligence?.ecommerce?.paymentMethods || []) {
    const normalized = normalizePaymentProviderName(provider);
    if (normalized) signals.add(normalized);
  }

  for (const entry of result.thirdPartyScripts?.categories?.payment || []) {
    const normalized = normalizePaymentProviderName(entry.name || entry.domain);
    if (normalized) signals.add(normalized);
  }

  for (const form of result.forms?.forms || []) {
    const action = `${form.action || ""} ${form.crossOriginTarget || ""}`.toLowerCase();
    if (/stripe/.test(action)) signals.add("Stripe");
    if (/paypal/.test(action)) signals.add("PayPal");
    if (/square/.test(action) || /squareup/.test(action)) signals.add("Square");
    if (/braintree/.test(action)) signals.add("Braintree");
    if (/authorize\.net/.test(action)) signals.add("Authorize.net");
    if (/klarna/.test(action)) signals.add("Klarna");
    if (/affirm/.test(action)) signals.add("Affirm");
    if (/afterpay/.test(action)) signals.add("Afterpay");
  }

  return Array.from(signals);
}

function isEmbeddedTrustedPaymentWidget(form = {}, providers = []) {
  if (!form.hasCreditCardField || form.isCrossOrigin) {
    return false;
  }

  const action = String(form.action || "").toLowerCase();
  const fieldNames = (form.fields || [])
    .map((field) => String(field.name || "").toLowerCase())
    .filter(Boolean);
  const providerHints = providers.join(" ").toLowerCase();
  const hasKnownProvider =
    /stripe|paypal|square|braintree|authorize\.net|klarna|affirm|afterpay/.test(`${action} ${providerHints}`) ||
    fieldNames.some((name) => /(stripe|paypal|square|braintree|authorize|klarna|affirm|afterpay)/i.test(name));

  if (!hasKnownProvider) {
    return false;
  }

  const hiddenFields = (form.hiddenFields || [])
    .map((field) => `${field.name || ""} ${field.valuePreview || ""}`.toLowerCase())
    .join(" ");

  return (
    /payment-intent|setup-intent|client_secret|payment_method|elements|hosted_fields|stripe|paypal|square|braintree|nonce|token/i.test(hiddenFields) ||
    fieldNames.some((name) => /(payment_method|paymentintent|setupintent|nonce|token)/i.test(name))
  );
}

function analyzePaymentSecurity(result) {
  const forms = result.forms?.forms || [];
  const ecommerce = result.leadIntelligence?.ecommerce || {};
  const providers = getPaymentProviderSignals(result);
  const hostedThirdPartyCheckoutForms = forms.filter((form) => {
    const action = `${form.action || ""} ${form.crossOriginTarget || ""}`.toLowerCase();
    return form.isCrossOrigin && form.crossOriginTrusted && (form.hasCreditCardField || /checkout|paypal|stripe|square|braintree|authorize\.net|klarna|affirm|afterpay/i.test(action));
  });
  const embeddedPaymentWidgetForms = forms.filter((form) => isEmbeddedTrustedPaymentWidget(form, providers));
  const onSiteCardCollectionForms = forms.filter((form) => form.hasCreditCardField && !form.isCrossOrigin && !isEmbeddedTrustedPaymentWidget(form, providers)).length;
  const hostedThirdPartyCheckout = hostedThirdPartyCheckoutForms.length > 0;
  const embeddedTrustedWidget = embeddedPaymentWidgetForms.length > 0;
  const paymentFlowType = hostedThirdPartyCheckout
    ? "hosted-third-party-checkout"
    : embeddedTrustedWidget
      ? "embedded-trusted-widget"
      : onSiteCardCollectionForms > 0
        ? "apparent-on-site-card-collection"
        : ecommerce.detected || providers.length > 0
          ? "payment-surface-detected"
          : null;

  const findings = [];
  if (onSiteCardCollectionForms > 0) {
    findings.push({
      tier: "unverified",
      severity: "info",
      message: `Observed apparent on-site card collection (${onSiteCardCollectionForms} form(s)); PCI posture not verified by this audit`,
      evidence: { formCount: onSiteCardCollectionForms },
    });
  }
  if (embeddedTrustedWidget) {
    findings.push({
      tier: "unverified",
      severity: "info",
      message: `Observed embedded trusted payment widget (${providers.join(", ") || "provider not classified"})`,
      evidence: { providers, formCount: embeddedPaymentWidgetForms.length },
    });
  }
  if (hostedThirdPartyCheckout) {
    findings.push({
      tier: "unverified",
      severity: "info",
      message: `Observed hosted or third-party payment flow (${providers.join(", ") || "provider not classified"})`,
      evidence: { providers, formCount: hostedThirdPartyCheckoutForms.length },
    });
  }

  return {
    hasPaymentSurface: !!ecommerce.detected || onSiteCardCollectionForms > 0 || hostedThirdPartyCheckout || embeddedTrustedWidget,
    hostedThirdPartyCheckout,
    embeddedTrustedWidget,
    onSiteCardCollectionForms,
    providers,
    paymentFlowType,
    findings,
  };
}

function classifyExposedEndpointConfidence(endpoint = {}) {
  if (endpoint.reportOnly) {
    return {
      tier: "unverified",
      severity: "info",
      message: `Interesting public file observed: ${endpoint.path}`,
    };
  }

  if (endpoint.severity === "critical") {
    return {
      tier: "verified",
      severity: "critical",
      message: `Exposed endpoint: ${endpoint.path}`,
    };
  }

  if (endpoint.severity === "high") {
    return {
      tier: "probable",
      severity: "warning",
      message: `Potentially sensitive endpoint exposed: ${endpoint.path}`,
    };
  }

  if (endpoint.type === "server") {
    return {
      tier: "unverified",
      severity: "info",
      message: `Operational endpoint observed publicly: ${endpoint.path}`,
    };
  }

  if (endpoint.type === "log" || endpoint.type === "ide" || endpoint.type === "htaccess") {
    return {
      tier: "unverified",
      severity: "info",
      message: `Potentially sensitive public file observed: ${endpoint.path}`,
    };
  }

  return {
    tier: "unverified",
    severity: "info",
    message: `Interesting public endpoint observed: ${endpoint.path}`,
  };
}

function classifyAdminSurfaceExpectation(entry = {}, result = {}) {
  const pathValue = String(entry.path || "").toLowerCase();
  const cms = String(result.techStack?.cms || "").toLowerCase();
  const backend = String(result.techStack?.backend || "").toLowerCase();
  const frameworks = Array.isArray(result.techStack?.frameworks) ? result.techStack.frameworks.join(" ").toLowerCase() : "";
  const fingerprint = `${cms} ${backend} ${frameworks}`;

  const expectedCmsSurface =
    (cms === "wordpress" && /^\/(wp-admin|wp-login\.php)/.test(pathValue)) ||
    (cms === "joomla" && pathValue === "/administrator") ||
    (cms === "drupal" && pathValue === "/user/login");

  const expectedGenericLogin =
    /^\/(login|signin|user\/login)$/.test(pathValue);

  const atypicalAdminSurface =
    /^\/(administrator|dashboard|manage|controlpanel|backend|api\/admin|admin\.php)$/.test(pathValue) &&
    !expectedCmsSurface &&
    !expectedGenericLogin;

  const directlyReachable = entry.status >= 200 && entry.status < 300;

  if (expectedCmsSurface) {
    return {
      classification: directlyReachable ? "expected-cms-admin-surface" : "expected-cms-admin-protected",
      expected: true,
      atypical: false,
      directlyReachable,
    };
  }

  if (expectedGenericLogin) {
    return {
      classification: directlyReachable ? "expected-login-entrypoint" : "expected-login-protected",
      expected: true,
      atypical: false,
      directlyReachable,
    };
  }

  if (atypicalAdminSurface) {
    return {
      classification: directlyReachable ? "atypical-admin-surface-responds" : "atypical-admin-surface-observed",
      expected: false,
      atypical: true,
      directlyReachable,
    };
  }

  if (/wordpress|joomla|drupal|woocommerce|laravel|django|rails|asp\.net|java/.test(fingerprint) && /^\/admin$/.test(pathValue)) {
    return {
      classification: directlyReachable ? "framework-admin-surface-responds" : "framework-admin-surface-observed",
      expected: false,
      atypical: false,
      directlyReachable,
    };
  }

  return {
    classification: directlyReachable ? "unclassified-admin-surface-responds" : "unclassified-admin-surface-observed",
    expected: false,
    atypical: false,
    directlyReachable,
  };
}

function buildAdminSurfaceReviewSummary(result = {}) {
  const found = result.adminEndpoints?.found || [];
  const surfaces = found.map((entry) => ({
    path: entry.path,
    status: entry.status,
    accessState: entry.accessState || null,
    ...classifyAdminSurfaceExpectation(entry, result),
  }));

  const atypicalReachableCount = surfaces.filter((entry) => entry.atypical && entry.directlyReachable).length;
  const expectedCount = surfaces.filter((entry) => entry.expected).length;

  return {
    overall: atypicalReachableCount > 0
      ? "atypical-admin-surface-observed"
      : expectedCount === surfaces.length && surfaces.length > 0
        ? "expected-login-surfaces-only"
        : "mixed-admin-surface-observations",
    surfaces,
  };
}

function buildDkimReviewSummary(result = {}) {
  const hasMailSurface = (result.dnsRecords?.mx?.length || 0) > 0 ||
    (result.contacts?.emails || []).some((email) => String(email).toLowerCase().endsWith(`@${result.domain}`));
  const detectionMethod = result.emailAuth?.dkimDetectionMethod || null;
  const checkedSelectors = result.emailAuth?.dkimCheckedSelectors || [];
  const providerHints = result.emailAuth?.dkimProviderHints || [];
  const dkimRecord = result.emailAuth?.dkim || null;

  if (!hasMailSurface) {
    return {
      classification: "mail-surface-not-observed",
      hasMailSurface: false,
      dkimPresent: !!dkimRecord,
      detectionMethod,
      providerHints,
      checkedSelectors,
      checkedSelectorCount: checkedSelectors.length,
    };
  }

  if (dkimRecord) {
    return {
      classification: /provider-informed/i.test(detectionMethod || "")
        ? "dkim-present-provider-informed-sample"
        : /guess/i.test(detectionMethod || "")
          ? "dkim-present-common-selector-sample"
          : "dkim-present",
      hasMailSurface: true,
      dkimPresent: true,
      selector: dkimRecord.selector || null,
      detectionMethod,
      providerHints,
      checkedSelectors,
      checkedSelectorCount: checkedSelectors.length,
    };
  }

  return {
    classification: /provider-informed/i.test(detectionMethod || "")
      ? "dkim-not-found-in-provider-informed-sample"
      : /guess/i.test(detectionMethod || "")
        ? "dkim-not-found-in-common-selector-sample"
        : "dkim-not-verified",
    hasMailSurface: true,
    dkimPresent: false,
    detectionMethod,
    providerHints,
    checkedSelectors,
    checkedSelectorCount: checkedSelectors.length,
  };
}

function inferMailProvidersFromSignals(spfRecord = null, mxHosts = []) {
  const haystack = `${spfRecord || ""} ${(mxHosts || []).join(" ")}`.toLowerCase();
  const providers = [];

  if (/google|googlemail|aspmx\.l\.google\.com|_spf\.google\.com/.test(haystack)) providers.push("google-workspace");
  if (/outlook|protection\.outlook\.com|office365|microsoft/.test(haystack)) providers.push("microsoft-365");
  if (/amazonses|amazonaws/.test(haystack)) providers.push("amazon-ses");
  if (/sendgrid|smtpapi/.test(haystack)) providers.push("sendgrid");
  if (/zoho/.test(haystack)) providers.push("zoho");

  return providers;
}

function buildDkimSelectorSample(spfRecord = null, mxHosts = []) {
  const commonSelectors = ["default", "selector1", "selector2", "k1", "google", "mail", "dkim", "smtpapi", "sendgrid", "amazonses"];
  const providers = inferMailProvidersFromSignals(spfRecord, mxHosts);
  const providerSelectors = [];

  if (providers.includes("google-workspace")) {
    providerSelectors.push("google");
  }
  if (providers.includes("microsoft-365")) {
    providerSelectors.push("selector1", "selector2");
  }
  if (providers.includes("amazon-ses")) {
    providerSelectors.push("amazonses");
  }
  if (providers.includes("sendgrid")) {
    providerSelectors.push("sendgrid", "smtpapi");
  }
  if (providers.includes("zoho")) {
    providerSelectors.push("zoho");
  }

  return {
    providers,
    selectors: Array.from(new Set([...providerSelectors, ...commonSelectors])),
    strategy: providers.length > 0 ? "provider-informed-selector-sample" : "common-selector-guess",
  };
}

function buildReviewQueueHighlights(reviewQueue = []) {
  const highlights = [];

  for (const entry of reviewQueue) {
    if (!entry || !entry.field) continue;

    if (entry.field === "admin_surface_exposure" && entry.summary?.overall === "atypical-admin-surface-observed") {
      highlights.push({
        priority: 10,
        text: "- **Admin/Login Routes:** At least one atypical reachable admin surface was observed and should be reviewed in context.",
      });
      continue;
    }

    if (entry.field === "payment_security_posture" && entry.summary?.paymentFlowType) {
      const flow = String(entry.summary.paymentFlowType);
      const priority =
        flow === "apparent-on-site-card-collection" ? 9 :
        flow === "embedded-trusted-widget" ? 7 :
        flow === "hosted-third-party-checkout" ? 6 : 5;
      highlights.push({
        priority,
        text: `- **Payment Flow:** Classified as \`${flow}\`; security/compliance meaning still requires review.`,
      });
      continue;
    }

    if (entry.field === "probable_findings" && Array.isArray(entry.summary) && entry.summary.length > 0) {
      highlights.push({
        priority: 8,
        text: `- **Probable Findings:** ${entry.summary.length} item(s) remain below the database-safe threshold and need review.`,
      });
      continue;
    }

    if (entry.field === "admin_surface_exposure" && entry.summary?.overall === "expected-login-surfaces-only") {
      highlights.push({
        priority: 4,
        text: "- **Admin/Login Routes:** Only expected login/admin entrypoints were observed; this remains review context, not a claim of exposure.",
      });
      continue;
    }

    if (entry.field === "dkim_posture" && entry.summary) {
      const dkim = entry.summary;
      if (dkim.classification === "dkim-present-provider-informed-sample") {
        highlights.push({
          priority: 5,
          text: `- **DKIM:** Present on provider-informed sampled selector \`${dkim.selector || "unknown"}\`, but still review-only because coverage is sampled rather than exhaustive.`,
        });
      } else if (dkim.classification === "dkim-present-common-selector-sample") {
        highlights.push({
          priority: 4,
          text: `- **DKIM:** Present on sampled selector \`${dkim.selector || "unknown"}\`, but still review-only because coverage is based on common-selector sampling.`,
        });
      } else if (dkim.classification === "dkim-not-found-in-provider-informed-sample") {
        highlights.push({
          priority: 4,
          text: `- **DKIM:** Not found in provider-informed sampled selectors (${dkim.checkedSelectorCount || 0} checked); absence is still review-only, not a verified gap.`,
        });
      } else if (dkim.classification === "dkim-not-found-in-common-selector-sample") {
        highlights.push({
          priority: 3,
          text: `- **DKIM:** Not found in sampled selectors (${dkim.checkedSelectorCount || 0} checked); absence is still review-only, not a verified gap.`,
        });
      } else if (dkim.classification === "mail-surface-not-observed") {
        highlights.push({
          priority: 1,
          text: "- **DKIM:** No clear mail surface observed, so DKIM absence is not being treated as a meaningful security gap.",
        });
      }
      continue;
    }
  }

  return highlights
    .sort((a, b) => b.priority - a.priority || a.text.localeCompare(b.text))
    .slice(0, 4)
    .map((entry) => entry.text);
}

function buildSecurityOutreachSummary(result) {
  const skipLowValueHeaderHooks = [
    /Missing security header: permissions-policy/i,
    /Missing security header: referrer-policy/i,
  ];
  const outreachEligible = (entry) => {
    if (!entry) return false;
    if (entry.severity === "info") return false;
    if (skipLowValueHeaderHooks.some((pattern) => pattern.test(entry.message))) return false;
    if (/cookie missing samesite/i.test(entry.message)) return false;
    return true;
  };

  const verifiedHooks = (result.findingConfidence?.verified || []).filter(outreachEligible).slice(0, 3);
  const probableHooks = (result.findingConfidence?.probable || []).filter(outreachEligible).slice(0, 2);
  const primaryHook = verifiedHooks[0]?.message || probableHooks[0]?.message || null;

  return {
    primaryHook,
    verifiedHooks: verifiedHooks.map((entry) => entry.message),
    probableHooks: probableHooks.map((entry) => entry.message),
  };
}

function observeMessage(store, message) {
  const normalized = normalizeObservedMessage(message);
  if (!normalized) return;
  const current = store.get(normalized);
  if (current) {
    current.count += 1;
  } else {
    store.set(normalized, { message: normalized, count: 1 });
  }
}

function getObservedEntries(store) {
  return Array.from(store.values()).sort((a, b) => b.count - a.count || a.message.localeCompare(b.message));
}

function formatObservedSummary(entries) {
  return entries.map((entry) => entry.count > 1 ? `${entry.message} (x${entry.count})` : entry.message);
}

function isLikelyScannerInducedError(message) {
  return SCANNER_INDUCED_ERROR_PATTERNS.some((pattern) => pattern.test(message));
}

function addConfidenceFinding(result, tier, severity, message, evidence = {}) {
  const bucket = result.findingConfidence?.[tier];
  if (!bucket) return;
  const fingerprint = `${severity}::${message}`;
  if (bucket.some((entry) => entry.fingerprint === fingerprint)) {
    return;
  }
  bucket.push({
    fingerprint,
    severity,
    message,
    evidence,
  });
}

function buildConfidenceFindings(result) {
  result.findingConfidence = {
    verified: [],
    probable: [],
    observedUnderInstrumentation: [],
    unverified: [],
  };

  if (!result.siteAvailability.reachable && result.siteAvailability.method === "dns") {
    addConfidenceFinding(result, "verified", "critical", "Domain does not resolve (DNS failure)", {
      source: "dns",
      method: result.siteAvailability.method,
    });
  }

  if (!result.ssl.valid) {
    addConfidenceFinding(result, "verified", "critical", "TLS certificate validation failed", {
      source: "tls",
      error: result.ssl.error || null,
      authorizationError: result.ssl.authorizationError || null,
      hostnameError: result.ssl.hostnameError || null,
    });
  } else if (result.ssl.daysUntilExpiry !== null && result.ssl.daysUntilExpiry < 30) {
    addConfidenceFinding(result, "verified", "warning", `SSL certificate expires in ${result.ssl.daysUntilExpiry} days`, {
      source: "tls",
      expires: result.ssl.expires || null,
    });
  }

  if (result.https.redirects === false) {
    addConfidenceFinding(result, "verified", "warning", "HTTP does not redirect to HTTPS", {
      source: "http-head-check",
      statusCode: result.https.statusCode || null,
      location: result.https.location || null,
      error: result.https.error || null,
    });
  }

  for (const [header, status] of Object.entries(result.securityHeaders || {})) {
    if (
      status.present === false &&
      header !== "x-xss-protection"
    ) {
      const severity = getMissingHeaderSeverity(header, result);
      addConfidenceFinding(result, "verified", severity, `Missing security header: ${header}`, {
        source: "response-headers",
      });
    }
  }

  if (result.mixedContent?.found) {
    addConfidenceFinding(result, "verified", "warning", `Mixed content detected (${result.mixedContent.resources.length} HTTP resource(s))`, {
      source: "dom-scan",
      sample: result.mixedContent.resources.slice(0, 3),
    });
  }

  const hasMailSurface = (result.dnsRecords?.mx?.length || 0) > 0 ||
    (result.contacts?.emails || []).some((email) => String(email).toLowerCase().endsWith(`@${result.domain}`));
  if (hasMailSurface && !result.emailAuth.spf) {
    addConfidenceFinding(result, "verified", "warning", "Missing SPF record", {
      source: "dns",
    });
  }
  if (hasMailSurface && !result.emailAuth.dmarc) {
    addConfidenceFinding(result, "verified", "warning", "Missing DMARC record", {
      source: "dns",
    });
  }

  if (result.sensitiveExposures?.exposedGit) {
    addConfidenceFinding(result, "verified", "critical", "Exposed .git directory", {
      source: "direct-fetch",
    });
  }
  if (result.sensitiveExposures?.exposedEnv) {
    addConfidenceFinding(result, "verified", "critical", "Exposed .env file", {
      source: "direct-fetch",
    });
  }
  if (result.sensitiveExposures?.exposedConfig) {
    addConfidenceFinding(result, "verified", "critical", "Exposed config file", {
      source: "direct-fetch",
    });
  }

  for (const endpoint of result.sensitiveExposures?.riskyEndpoints || []) {
    const classified = classifyExposedEndpointConfidence(endpoint);
    addConfidenceFinding(
      result,
      classified.tier,
      classified.severity,
      classified.message,
      {
        source: "direct-fetch",
        status: endpoint.status,
        endpointType: endpoint.type,
        reportOnly: !!endpoint.reportOnly,
      }
    );
  }

  for (const key of result.sensitiveExposures?.apiKeys || []) {
    const tier = key.confidence || (key.severity === "critical" ? "verified" : "probable");
    addConfidenceFinding(
      result,
      tier,
      key.severity === "critical" ? "critical" : key.severity === "high" || key.severity === "medium" ? "warning" : "info",
      `Exposed key in page source: ${key.type}`,
      {
        source: "page-source-scan",
        samples: key.samples || [],
      }
    );
  }

  for (const finding of result.cookieSecurity?.findings || []) {
    addConfidenceFinding(result, finding.tier, finding.severity, finding.message, {
      source: "cookie-analysis",
      ...(finding.evidence || {}),
    });
  }

  for (const finding of result.paymentSecurity?.findings || []) {
    addConfidenceFinding(result, finding.tier, finding.severity, finding.message, {
      source: "payment-surface-analysis",
      ...(finding.evidence || {}),
    });
  }

  for (const issue of result.forms?.issues || []) {
    let tier = "probable";
    let severity = "info";
    if (/CRITICAL: (Password|Credit card|SSN).*HTTP/i.test(issue) || /Sensitive data submitted to non-allowlisted cross-origin domain/i.test(issue)) {
      tier = "verified";
      severity = "critical";
    } else if (/INFO: POST form has no visible CSRF token/i.test(issue)) {
      tier = "unverified";
      severity = "info";
    } else if (/HIGH:/i.test(issue)) {
      severity = "warning";
    } else if (/MEDIUM:/i.test(issue)) {
      severity = "info";
    }
    addConfidenceFinding(result, tier, severity, issue, {
      source: "form-heuristics",
    });
  }

  for (const entry of result.jsErrorAnalysis?.verifiedPageErrors || []) {
    addConfidenceFinding(result, "unverified", "info", `Reproducible runtime error observed: ${entry.message}`, {
      source: "clean-browser-pass",
      count: entry.count,
    });
  }
  for (const entry of result.jsErrorAnalysis?.verifiedConsoleErrors || []) {
    addConfidenceFinding(result, "unverified", "info", `Reproducible console error observed: ${entry.message}`, {
      source: "clean-browser-pass",
      count: entry.count,
    });
  }
  for (const entry of result.jsErrorAnalysis?.scannerInducedPageErrors || []) {
    addConfidenceFinding(result, "observedUnderInstrumentation", "info", `Likely scanner-induced page error: ${entry.message}`, {
      source: "instrumented-browser-pass",
      count: entry.count,
    });
  }
  for (const entry of result.jsErrorAnalysis?.scannerInducedConsoleErrors || []) {
    addConfidenceFinding(result, "observedUnderInstrumentation", "info", `Likely scanner-induced console error: ${entry.message}`, {
      source: "instrumented-browser-pass",
      count: entry.count,
    });
  }
  for (const entry of result.jsErrorAnalysis?.provisionalPageErrors || []) {
    addConfidenceFinding(result, "observedUnderInstrumentation", "info", `Instrumentation-only page error: ${entry.message}`, {
      source: "instrumented-browser-pass",
      count: entry.count,
    });
  }
  for (const entry of result.jsErrorAnalysis?.provisionalConsoleErrors || []) {
    addConfidenceFinding(result, "observedUnderInstrumentation", "info", `Instrumentation-only console error: ${entry.message}`, {
      source: "instrumented-browser-pass",
      count: entry.count,
    });
  }

  if (result.botBlocker?.detected && result.botBlocker.blocked) {
    addConfidenceFinding(result, "observedUnderInstrumentation", "info", `Bot blocker active during audit: ${result.botBlocker.name || "unknown"}`, {
      source: "browser-detection",
      bypassed: false,
    });
  } else if (result.botBlocker?.detected && result.botBlocker.bypassed) {
    addConfidenceFinding(result, "unverified", "info", `Bot blocker was present but bypassed (${result.botBlocker.name || result.botBlocker.method || "unknown"})`, {
      source: "browser-detection",
      bypassed: true,
    });
  }

  if (result.siteAvailability.reachable && result.renderTimeout) {
    addConfidenceFinding(result, "unverified", "warning", "Site responded to direct checks but browser rendering was unreliable", {
      source: "availability-vs-render-mismatch",
      method: result.siteAvailability.method,
      statusCode: result.siteAvailability.statusCode,
    });
  }

  for (const bucketName of Object.keys(result.findingConfidence)) {
    result.findingConfidence[bucketName].forEach((entry) => {
      delete entry.fingerprint;
    });
  }
}

function attachErrorObservers(page, stores) {
  page.on("console", (msg) => {
    const text = msg.text();
    if (msg.type() === "error") {
      observeMessage(stores.consoleErrors, text);
    } else if (msg.type() === "warning") {
      observeMessage(stores.consoleWarnings, text);
    }
  });

  page.on("pageerror", (error) => {
    observeMessage(stores.pageErrors, error.message);
  });
}

async function runJavaScriptVerificationPass(browser, url, baseUserAgent) {
  const verification = {
    attempted: true,
    succeeded: false,
    blocked: false,
    finalUrl: null,
    status: null,
    consoleErrors: [],
    pageErrors: [],
  };

  let context = null;
  let page = null;

  try {
    context = await browser.newContext({
      viewport: { width: 1920, height: 1080 },
      userAgent: baseUserAgent,
      ignoreHTTPSErrors: true,
      locale: "en-US",
      timezoneId: "America/New_York",
      colorScheme: "light",
    });

    page = await context.newPage();

    const stores = {
      consoleErrors: new Map(),
      consoleWarnings: new Map(),
      pageErrors: new Map(),
    };
    attachErrorObservers(page, stores);

    const response = await page.goto(url, {
      waitUntil: "domcontentloaded",
      timeout: 45000,
    });

    verification.status = response?.status?.() ?? null;
    verification.finalUrl = page.url();

    await page.waitForTimeout(2500);
    try {
      await page.waitForLoadState("networkidle", { timeout: 10000 });
    } catch (error) {
      // Some sites keep background requests alive indefinitely; partial stabilization is enough.
    }

    const blocker = await detectBotBlocker(page);
    verification.blocked = !!blocker.challengeDetected;
    if (!verification.blocked) {
      verification.succeeded = true;
      verification.consoleErrors = getObservedEntries(stores.consoleErrors);
      verification.pageErrors = getObservedEntries(stores.pageErrors);
    }
  } catch (error) {
    verification.error = error.message;
  } finally {
    if (page && !page.isClosed?.()) {
      try { await page.close(); } catch (error) {}
    }
    if (context) {
      try { await context.close(); } catch (error) {}
    }
  }

  return verification;
}

async function reconcileJavaScriptFindings(browser, url, result, baseUserAgent) {
  const rawConsoleEntries = getObservedEntries(result._observedConsoleErrors);
  const rawPageEntries = getObservedEntries(result._observedPageErrors);

  result.jsErrorAnalysis.rawConsoleErrors = rawConsoleEntries;
  result.jsErrorAnalysis.rawPageErrors = rawPageEntries;

  if (rawConsoleEntries.length === 0 && rawPageEntries.length === 0) {
    result.consoleErrors = [];
    result.pageErrors = [];
    return;
  }

  const cleanPass = await runJavaScriptVerificationPass(browser, url, baseUserAgent);
  result.jsErrorAnalysis.cleanPass = {
    attempted: cleanPass.attempted,
    succeeded: cleanPass.succeeded,
    blocked: cleanPass.blocked,
    finalUrl: cleanPass.finalUrl,
    status: cleanPass.status,
    error: cleanPass.error || null,
  };

  const cleanConsoleSet = new Set((cleanPass.consoleErrors || []).map((entry) => entry.message));
  const cleanPageSet = new Set((cleanPass.pageErrors || []).map((entry) => entry.message));

  const classifyEntries = (entries, cleanSet) => {
    const verified = [];
    const scannerInduced = [];
    const provisional = [];

    for (const entry of entries) {
      if (cleanSet.has(entry.message)) {
        verified.push(entry);
      } else if (isLikelyScannerInducedError(entry.message)) {
        scannerInduced.push(entry);
      } else {
        provisional.push(entry);
      }
    }

    return { verified, scannerInduced, provisional };
  };

  const consoleGroups = classifyEntries(rawConsoleEntries, cleanConsoleSet);
  const pageGroups = classifyEntries(rawPageEntries, cleanPageSet);

  result.jsErrorAnalysis.verifiedConsoleErrors = consoleGroups.verified;
  result.jsErrorAnalysis.verifiedPageErrors = pageGroups.verified;
  result.jsErrorAnalysis.provisionalConsoleErrors = consoleGroups.provisional;
  result.jsErrorAnalysis.provisionalPageErrors = pageGroups.provisional;
  result.jsErrorAnalysis.scannerInducedConsoleErrors = consoleGroups.scannerInduced;
  result.jsErrorAnalysis.scannerInducedPageErrors = pageGroups.scannerInduced;

  result.consoleErrors = formatObservedSummary(consoleGroups.verified);
  result.pageErrors = formatObservedSummary(pageGroups.verified);

  if (pageGroups.scannerInduced.length > 0) {
    result.warnings.push(`Filtered ${pageGroups.scannerInduced.length} likely scanner-induced JavaScript error pattern(s)`);
  }
  if (pageGroups.provisional.length > 0 || consoleGroups.provisional.length > 0) {
    result.warnings.push(
      `${pageGroups.provisional.length + consoleGroups.provisional.length} JavaScript issue(s) observed only under audit instrumentation`
    );
  }
}

/**
 * Check if site is truly down vs bot-blocked using multiple methods
 * Returns: { reachable: boolean, method: string, statusCode: number|null, blockerHint: string|null }
 */
async function checkSiteAvailability(hostname) {
  const dns = require("dns");
  const results = [];
  
  // Method 1: Plain HTTP HEAD with minimal headers
  const checkHTTP = (ua, timeout = 15000) => new Promise((resolve) => {
    const http = require("http");
    let resolved = false;
    const req = http.request(`http://${hostname}`, {
      method: "HEAD",
      timeout,
      headers: {
        "User-Agent": ua,
        "Accept": "*/*",
      }
    }, (res) => {
      if (!resolved) {
        resolved = true;
        resolve({ 
          ok: true, 
          method: "http-head", 
          status: res.statusCode, 
          headers: res.headers,
          ua: ua.substring(0, 30) + "..."
        });
      }
    });
    req.on("error", (e) => {
      if (!resolved) {
        resolved = true;
        resolve({ ok: false, method: "http-head", error: e.message, ua: ua.substring(0, 30) + "..." });
      }
    });
    req.on("timeout", () => {
      if (!resolved) {
        resolved = true;
        req.destroy();
        resolve({ ok: false, method: "http-head", error: "timeout" });
      }
    });
    req.end();
  });
  
  // Method 2: HTTPS HEAD with curl user agent
  const checkHTTPS = (ua, timeout = 15000) => new Promise((resolve) => {
    let resolved = false;
    const req = https.request(`https://${hostname}`, {
      method: "HEAD",
      timeout,
      rejectUnauthorized: false,
      headers: {
        "User-Agent": ua,
        "Accept": "*/*",
      }
    }, (res) => {
      if (!resolved) {
        resolved = true;
        resolve({ 
          ok: true, 
          method: "https-head", 
          status: res.statusCode, 
          headers: res.headers,
          ua: ua.substring(0, 30) + "..."
        });
      }
    });
    req.on("error", (e) => {
      if (!resolved) {
        resolved = true;
        resolve({ ok: false, method: "https-head", error: e.message, ua: ua.substring(0, 30) + "..." });
      }
    });
    req.on("timeout", () => {
      if (!resolved) {
        resolved = true;
        req.destroy();
        resolve({ ok: false, method: "https-head", error: "timeout" });
      }
    });
    req.end();
  });
  
  // Try multiple user agents to detect bot blocking
  const userAgents = [
    "curl/8.0",  // Minimal - many sites accept this
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",  // Googlebot - often whitelisted
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",  // Chrome
  ];
  
  // Try HTTPS first with curl UA
  const curlResult = await checkHTTPS(userAgents[0]);
  if (curlResult.ok && curlResult.status && curlResult.status < 500) {
    return { 
      reachable: true, 
      method: "https-curl", 
      statusCode: curlResult.status,
      blockerHint: curlResult.status === 403 ? "Possible bot block (403 with curl UA)" : null
    };
  }
  
  // Try Googlebot UA - often whitelisted
  const botResult = await checkHTTPS(userAgents[1]);
  if (botResult.ok && botResult.status && botResult.status < 500) {
    // If Googlebot works but curl doesn't, definite bot blocker
    const isBlocked = curlResult.ok && curlResult.status === 403 && botResult.status < 400;
    return {
      reachable: true,
      method: "https-googlebot",
      statusCode: botResult.status,
      blockerHint: isBlocked ? "Bot blocker detected (works with Googlebot UA, blocks curl)" : null
    };
  }
  
  // Try regular Chrome UA
  const chromeResult = await checkHTTPS(userAgents[2]);
  if (chromeResult.ok && chromeResult.status && chromeResult.status < 500) {
    return { reachable: true, method: "https-chrome", statusCode: chromeResult.status, blockerHint: null };
  }
  
  // Try HTTP as last resort
  const httpResult = await checkHTTP(userAgents[2]);
  if (httpResult.ok && httpResult.status) {
    return { reachable: true, method: "http", statusCode: httpResult.status, blockerHint: null };
  }
  
  // Check DNS resolution to see if domain exists at all
  const dnsCheck = await new Promise((resolve) => {
    dns.resolve(hostname, (err, addresses) => {
      resolve({ ok: !err, addresses: addresses || [], error: err?.message });
    });
  });
  
  if (!dnsCheck.ok) {
    return { reachable: false, method: "dns", statusCode: null, blockerHint: `DNS resolution failed: ${dnsCheck.error}` };
  }
  
  // Domain exists but we can't reach it - likely down or heavy bot protection
  return { 
    reachable: false, 
    method: "all-failed", 
    statusCode: null, 
    blockerHint: `Domain resolves (${dnsCheck.addresses.length} IPs) but all HTTP methods failed. Likely heavy bot protection or server down.`
  };
}

/**
 * Check SSL/TLS certificate
 */
async function checkSSLCertificate(hostname) {
  return new Promise((resolve) => {
    const socket = tls.connect(443, hostname, { 
      servername: hostname,
      rejectUnauthorized: false 
    }, () => {
      try {
        const cert = socket.getPeerCertificate();
        if (cert && Object.keys(cert).length > 0) {
          const expires = new Date(cert.valid_to);
          const now = new Date();
          const daysUntilExpiry = Math.floor((expires - now) / (1000 * 60 * 60 * 24));
          const hostnameError = tls.checkServerIdentity(hostname, cert);
          const authorizationError = socket.authorized ? null : socket.authorizationError || null;
          const isValid = socket.authorized && !hostnameError && daysUntilExpiry > 0;
          
          resolve({
            valid: isValid,
            issuer: cert.issuer?.O || cert.issuer?.CN || "Unknown",
            issuerCN: cert.issuer?.CN || null,
            subject: cert.subject?.CN || hostname,
            expires: expires.toISOString(),
            daysUntilExpiry,
            fingerprint: cert.fingerprint,
            selfSigned: cert.issuer?.CN === cert.subject?.CN,
            authorized: socket.authorized,
            authorizationError,
            hostnameError: hostnameError?.message || null,
            error: authorizationError || hostnameError?.message || null,
          });
        } else {
          resolve({ valid: false, error: "No certificate returned" });
        }
      } catch (e) {
        resolve({ valid: false, error: e.message });
      } finally {
        socket.end();
      }
    });
    
    socket.on("error", (e) => {
      resolve({ valid: false, error: e.message });
    });
    
    socket.setTimeout(10000, () => {
      socket.destroy();
      resolve({ valid: false, error: "Connection timeout" });
    });
  });
}

/**
 * Check HTTP to HTTPS redirect
 */
async function checkHTTPSRedirect(hostname) {
  return new Promise((resolve) => {
    const http = require("http");
    
    // First, check if HTTPS is available at all
    const checkHTTPS = () => new Promise((resHTTPS) => {
      https.request(`https://${hostname}`, { method: "HEAD", timeout: 10000, rejectUnauthorized: false }, (res) => {
        resHTTPS({ available: true, statusCode: res.statusCode });
      }).on("error", () => {
        resHTTPS({ available: false });
      }).setTimeout(10000, () => {
        resHTTPS({ available: false });
      }).end();
    });
    
    // Check HTTP redirect behavior
    const httpReq = http.request(`http://${hostname}`, { 
      method: "HEAD", 
      timeout: 10000,
    }, async (res) => {
      const httpsResult = await checkHTTPS();
      
      if (res.statusCode >= 300 && res.statusCode < 400) {
        // It's a redirect - check if to HTTPS
        const location = res.headers.location || "";
        const redirectsToHTTPS = location.startsWith("https://") || 
                                  location.includes(`https://${hostname}`);
        resolve({ 
          enabled: httpsResult.available, 
          redirects: redirectsToHTTPS, 
          statusCode: res.statusCode,
          location: location 
        });
      } else if (res.statusCode >= 200 && res.statusCode < 300) {
        // HTTP serves content directly - check if HTTPS also available
        resolve({ 
          enabled: httpsResult.available, 
          redirects: false, 
          statusCode: res.statusCode,
          warning: "HTTP serves content without redirect"
        });
      } else if (res.statusCode >= 400 && httpsResult.available) {
        // Some hosts block bare HTTP HEAD probes but still redirect real browsers to HTTPS.
        // Treat this as inconclusive instead of a verified no-redirect finding.
        resolve({
          enabled: true,
          redirects: null,
          statusCode: res.statusCode,
          warning: "HTTP probe blocked before redirect could be verified"
        });
      } else {
        resolve({ 
          enabled: httpsResult.available, 
          redirects: false, 
          statusCode: res.statusCode 
        });
      }
    });
    
    httpReq.on("error", async (e) => {
      // HTTP failed - check if HTTPS works
      const httpsResult = await checkHTTPS();
      if (httpsResult.available) {
        // HTTPS works, HTTP doesn't - effectively HTTPS-only (good)
        resolve({ enabled: true, redirects: true, statusCode: httpsResult.statusCode, note: "HTTP unreachable, HTTPS only" });
      } else {
        resolve({ enabled: false, redirects: false, error: "Site unreachable on HTTP and HTTPS" });
      }
    });
    
    httpReq.setTimeout(10000, () => {
      httpReq.destroy();
      resolve({ enabled: false, redirects: false, error: "Timeout" });
    });
    httpReq.end();
  });
}

function getActionableBrokenLinks(result) {
  const brokenLinks = result.brokenLinks?.broken || [];
  return brokenLinks.filter(link => {
    if (link.internal) {
      return true;
    }

    // External services often return 400/403/405/429 for bot-like or unauthenticated probes.
    // Keep only clearly dead external links as actionable findings.
    return ![400, 401, 403, 405, 429].includes(link.status);
  });
}

function compactString(value) {
  if (typeof value !== "string") {
    return null;
  }
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function isJunkBusinessName(value) {
  const normalized = compactString(value);
  if (!normalized) return true;
  const lowered = normalized.toLowerCase();
  const junkPatterns = [
    /^thank you!?$/,
    /^thanks!?$/,
    /^welcome!?$/,
    /^home$/,
    /^homepage$/,
    /^contact us$/,
    /^about us$/,
    /^our team$/,
    /^our staff$/,
    /^submit$/,
    /^success$/,
    /^loading$/,
    /^error$/,
    /^page not found$/,
    /^coming soon$/,
    /^under construction$/,
    /^order by category$/,
    /^shop now$/,
    /^all collections$/,
    /^json$/,
    /^login$/,
    /^logo$/,
    /^logo image$/,
    /^independent agency$/,
    /^open navigation$/,
    /^how to build your own website$/,
    /^looks like this domain isn't connected to a website yet$/,
    /^this domain isn't connected to a website yet$/,
    /^.+\s+»\s+feed$/,
    /^.+\s+rss$/,
    /^[a-z0-9-]+\.(?:com|net|org|co|io|biz|us)$/,
  ];
  if (junkPatterns.some((pattern) => pattern.test(lowered))) {
    return true;
  }
  if (
    /^start from\b/i.test(normalized) ||
    /\b(?:wordpress|woocommerce|shopify|wix)\s+theme\b/i.test(normalized) ||
    /\bnot connected to a website yet\b/i.test(normalized) ||
    /\bplease contact our support team\b/i.test(normalized) ||
    /\blogo\b/i.test(normalized) ||
    /\bopen navigation\b/i.test(normalized) ||
    /\bhow to build your own website\b/i.test(normalized) ||
    /\bfederal voc\b/i.test(normalized) ||
    /\b(?:rss|atom)\b/i.test(normalized) ||
    /\b»\s*feed\b/i.test(normalized)
  ) {
    return true;
  }
  const genericTokens = lowered
    .replace(/[^a-z0-9&+\s-]/g, " ")
    .split(/\s+/)
    .filter((token) => token && token !== "&" && token !== "+");
  const genericNameWords = new Set([
    "all", "and", "appointment", "appointments", "book", "booking", "brand", "brands",
    "business", "by", "care", "category", "collections", "company", "consulting", "contact",
    "customer", "effect", "group", "hair", "home", "maintenance", "message", "methods", "now",
    "order", "our", "payment", "people", "policies", "policy", "products", "professional",
    "projects", "properties", "service", "services", "shop", "shopping", "staffing", "store",
    "strong", "submit", "team", "us", "login", "logo", "theme", "website", "connected",
    "support", "medical", "clinic", "wordpress"
  ]);
  if (
    genericTokens.length > 0 &&
    genericTokens.every((token) => genericNameWords.has(token))
  ) {
    return true;
  }
  if (/.+\bin\s+[a-z .'-]+,\s*[a-z]{2}$/i.test(lowered)) {
    return true;
  }
  if (/.+,\s*[a-z]{2}\s+[a-z]{2,}$/i.test(lowered)) {
    return true;
  }
  if (!/[a-z]/i.test(normalized)) {
    return true;
  }
  if (normalized.length < 3 || normalized.length > 80) {
    return true;
  }
  return false;
}

function sanitizeBusinessName(value) {
  const normalized = compactString(value)
    ?.replace(/(?<=[A-Za-z])\d{1,2}$/, "")
    .replace(/\s*[-|:–—]+\s*$/, "");
  if (!normalized || isJunkBusinessName(normalized)) {
    return null;
  }
  return normalized;
}

function sanitizeBusinessDescription(description, businessName = null) {
  const normalized = compactString(description);
  if (!normalized) return null;

  const normalizedName = compactString(businessName);
  if (normalizedName) {
    const descKey = normalized.toLowerCase().replace(/[^\w]+/g, "");
    const nameKey = normalizedName.toLowerCase().replace(/[^\w]+/g, "");
    if (descKey === nameKey) {
      return null;
    }
    if (normalized.length <= Math.max(24, normalizedName.length + 6) && normalized.toLowerCase().includes(normalizedName.toLowerCase())) {
      return null;
    }
  }

  if (
    /(all rights reserved|copyright|created by|payment methods|privacy policy|terms of service)/i.test(normalized) &&
    normalized.length < 220
  ) {
    return null;
  }
  if (
    /\b(?:wordpress|woocommerce|shopify|wix)\s+theme\b/i.test(normalized) ||
    /\bnot connected to a website yet\b/i.test(normalized) ||
    /\bplease contact our support team\b/i.test(normalized) ||
    /\bpowered by wix\b/i.test(normalized) ||
    /\bpowered by webador\b/i.test(normalized)
  ) {
    return null;
  }
  if (
    /^home\b/i.test(normalized) ||
    /^start from\b/i.test(normalized) ||
    /\bserving\s+[a-z .'-]+,\s*[a-z]{2,}\.?\s*[a-z .'-]*$/i.test(normalized) ||
    /\b\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/.test(normalized)
  ) {
    return null;
  }

  return normalized;
}

function extractUsAddressCandidate(text) {
  const normalized = compactString(text);
  if (!normalized) return null;

  const cleaned = normalized
    .replace(/\b\d+\s+Address\s+/gi, " ")
    .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/ig, " ")
    .replace(/(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}/g, " ")
    .replace(/\b(Search Facebook|Powered by Shopify|Powered by Webador|American Express|Apple Pay|Diners Club|Discover|Master ?Card|Master|Visa|Home Services|Contact More Information|More Information)\b/gi, " ")
    .replace(/\s+/g, " ")
    .trim();

  const patterns = [
    /\b(\d{1,6}\s+[A-Za-z0-9.#'\- ]+?\s+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Way|Court|Ct|Place|Pl|Circle|Cir|Parkway|Pkwy|Highway|Hwy|Route|Rt|Loop|Lp|Suite|Ste|Unit|FM|Interstate|I-\d+)[^,\n]{0,40},?\s+[A-Za-z .'-]+,\s*(?:[A-Z]{2}|Texas|Louisiana|Florida|California|Oklahoma)\s+\d{5}(?:-\d{4})?)/i,
    /\b(\d{1,6}\s+[A-Za-z0-9.#'\- ]+?\s+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Way|Court|Ct|Place|Pl|Circle|Cir|Parkway|Pkwy|Highway|Hwy|Route|Rt|Loop|Lp|Suite|Ste|Unit|FM|Interstate|I-\d+)\s+[A-Za-z .'-]+,\s*(?:[A-Z]{2}|Texas|Louisiana|Florida|California|Oklahoma)\s+\d{5}(?:-\d{4})?)/i,
    /\b(\d{1,6}\s+[A-Za-z0-9.#'\- ]+?\s+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Way|Court|Ct|Place|Pl|Circle|Cir|Parkway|Pkwy|Highway|Hwy|Route|Rt|Loop|Lp|Suite|Ste|Unit|FM|Interstate|I-\d+)\s+[A-Za-z .'-]+\s+(?:[A-Z]{2}|Texas|Louisiana|Florida|California|Oklahoma)\s+\d{5}(?:-\d{4})?)/i,
    /\b(\d{1,6}\s+[NSEW]?\s*Loop\s+\d+[NSEW]?\s+[A-Za-z .'-]+\s+(?:[A-Z]{2}|Texas|Louisiana|Florida|California|Oklahoma)\s+\d{5}(?:-\d{4})?)/i,
    /\b(P\.?\s*O\.?\s*Box\s+\d+[A-Za-z0-9\- ]*,?\s+[A-Za-z .'-]+,\s*(?:[A-Z]{2}|Texas|Louisiana|Florida|California|Oklahoma)\s+\d{5}(?:-\d{4})?)/i,
  ];

  for (const pattern of patterns) {
    const match = cleaned.match(pattern);
    if (match && match[1]) {
      return compactString(match[1]);
    }
  }

  return null;
}

function sanitizeAddressData(address = {}) {
  let structuredStreet = compactString(address.street);
  let structuredCity = compactString(address.city);
  const structuredState = compactString(address.state);
  const structuredZip = compactString(address.zip);
  const structuredCountry = compactString(address.country);
  const rawAddress = compactString(address.raw);
  const rawLooksLikePoBox = !!rawAddress && /\bP\.?\s*O\.?\s*Box\b/i.test(rawAddress);
  const rawLooksLikeLocationBlob = !!rawAddress && /\bLocation\s*#?\d+\b/i.test(rawAddress);
  const streetLooksSuspicious =
    !!structuredStreet &&
    (
      /\baddress\b/i.test(structuredStreet) ||
      /\bLocation\s*#?\d+\b/i.test(structuredStreet) ||
      (!/\b(?:P\.?\s*O\.?\s*Box|Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Way|Court|Ct|Place|Pl|Circle|Cir|Parkway|Pkwy|Highway|Hwy|Route|Rt|Loop|Lp|Suite|Ste|Unit|FM|Interstate|I-\d+)\b/i.test(structuredStreet) &&
        /\d/.test(structuredStreet))
    );
  const hasSuspiciousStructuredParts =
    streetLooksSuspicious ||
    rawLooksLikePoBox ||
    rawLooksLikeLocationBlob ||
    (structuredCity && /\b(?:street|st|avenue|ave|road|rd|drive|dr|lane|ln|boulevard|blvd|parkway|pkwy|highway|hwy)\b/i.test(structuredCity));

  let raw = compactString(address.raw);
  const extractedRaw = extractUsAddressCandidate(raw);

  if (hasSuspiciousStructuredParts) {
    structuredStreet = null;
    structuredCity = null;
  }

  const structuredRaw = [structuredStreet, structuredCity, structuredState, structuredZip, structuredCountry]
    .filter(Boolean)
    .join(", ");

  if (structuredStreet && structuredCity && structuredState && structuredZip) {
    raw = structuredRaw;
  } else if (raw) {
    raw = extractedRaw || raw;
  }

  const contaminated =
    raw &&
    (
      /@/.test(raw) ||
      /\b(Search Facebook|Powered by Shopify|Powered by Wix|Powered by Webador|American Express|Apple Pay|Diners Club|Discover|Master ?Card|Visa|Home Services|Contact More Information|All Rights Reserved|Copyright|Payment methods|Created By|Support Team|Website Yet|WordPress Theme|reCAPTCHA|privacy policy|terms of service)\b/i.test(raw)
    );

  if (contaminated) {
    raw = extractUsAddressCandidate(raw);
  }

  if (raw && !extractUsAddressCandidate(raw) && /(all rights reserved|copyright|payment methods|created by|contact message us|shop now|all collections|support team|website yet|wordpress theme|powered by wix|powered by webador|recaptcha|privacy policy|terms of service)/i.test(raw)) {
    raw = null;
  }

  if (!raw) {
    return {
      raw: null,
      street: structuredStreet,
      city: structuredCity,
      state: structuredState,
      zip: structuredZip,
      country: structuredCountry,
    };
  }

  return {
    raw,
    street: structuredStreet,
    city: structuredCity,
    state: structuredState,
    zip: structuredZip,
    country: structuredCountry,
  };
}

function sanitizeContactRoute(value, websiteUrl = null, allowHomepage = false) {
  const normalized = compactString(value);
  if (!normalized) return null;

  let parsed;
  let websiteParsed = null;
  try {
    parsed = new URL(normalized);
    if (websiteUrl) {
      websiteParsed = new URL(websiteUrl);
    }
  } catch {
    return null;
  }

  if (!/^https?:$/.test(parsed.protocol)) {
    return null;
  }

  const normalizeRouteHost = hostname => hostname.toLowerCase().replace(/^www\./, "");
  const host = normalizeRouteHost(parsed.hostname);
  const path = parsed.pathname.toLowerCase();
  if (websiteParsed && normalizeRouteHost(websiteParsed.hostname) !== host) {
    return null;
  }

  if (
    (!allowHomepage && path === "/") ||
    /\/(faq|privacy|terms|policy|policies|search|account|login|signin|register|cart|checkout)\b/.test(path) ||
    /contact\/faq/.test(path)
  ) {
    return null;
  }

  if (!/(contact|get-in-touch|quote|estimate|consult|request-service|request-quote|contact-us|contactus)/.test(path)) {
    return null;
  }

  return parsed.toString().split("?")[0].replace(/\/$/, "");
}

function sanitizeSocialUrl(field, value) {
  const normalized = compactString(value);
  if (!normalized) return null;

  let parsed;
  try {
    parsed = new URL(normalized);
  } catch {
    return null;
  }

  const host = parsed.hostname.toLowerCase();
  const path = parsed.pathname.toLowerCase();
  const hostChecks = {
    facebook_url: ["facebook.com", "fb.com"],
    instagram_url: ["instagram.com"],
    linkedin_url: ["linkedin.com"],
    twitter_url: ["twitter.com", "x.com"],
    youtube_url: ["youtube.com", "youtu.be"],
    tiktok_url: ["tiktok.com"],
    yelp_url: ["yelp.com"],
    google_business_url: ["google.com", "g.page"],
  };

  const allowedHosts = hostChecks[field] || [];
  if (allowedHosts.length > 0 && !allowedHosts.some((candidate) => host === candidate || host.endsWith(`.${candidate}`))) {
    return null;
  }

  if (field === "facebook_url" && /(^|\/)profile\.php$/.test(path)) {
    return null;
  }

  if (field === "facebook_url" && (path === "/" || path === "")) {
    return null;
  }

  if (field === "instagram_url" && (path === "/" || path === "")) {
    return null;
  }

  if (field === "linkedin_url" && !(host.includes("linkedin.com") && /\/(company|in|school)\//.test(path))) {
    return null;
  }

  if (field === "twitter_url" && (path === "/" || path === "" || /\/(home|search|explore|intent)\b/.test(path))) {
    return null;
  }

  if (field === "youtube_url" && (path === "/" || path === "" || /\.js$/i.test(path))) {
    return null;
  }

  if (field === "yelp_url" && (path === "/" || path === "" || path.startsWith("/search"))) {
    return null;
  }
  if (/(?:citydirect|conroedirect|condroedirect)/i.test(`${host}${path}`)) {
    return null;
  }

  if (/(?:^|[/.])wix(?:[/-]|$)/i.test(`${host}${path}`)) {
    return null;
  }

  return parsed.toString().split("?")[0].replace(/\/$/, "");
}

function sanitizeTeamPageUrl(value, websiteUrl = null) {
  const normalized = compactString(value);
  if (!normalized) return null;

  let parsed;
  let websiteParsed = null;
  try {
    parsed = new URL(normalized);
    if (websiteUrl) {
      websiteParsed = new URL(websiteUrl);
    }
  } catch {
    return null;
  }

  const host = parsed.hostname.toLowerCase();
  const path = parsed.pathname.toLowerCase();

  if (!/^https?:$/.test(parsed.protocol)) {
    return null;
  }

  if (websiteParsed && websiteParsed.hostname.toLowerCase() !== host) {
    return null;
  }

  if (
    host.includes("facebook.com") ||
    host.includes("instagram.com") ||
    host.includes("linkedin.com") ||
    host.includes("x.com") ||
    host.includes("twitter.com") ||
    host.includes("youtube.com") ||
    host.includes("tiktok.com")
  ) {
    return null;
  }

  if (path === "/" || path === "") {
    return null;
  }

  return parsed.toString().split("?")[0].replace(/\/$/, "");
}

function dedupeStrings(values) {
  const seen = new Set();
  const deduped = [];
  for (const value of values || []) {
    const normalized = compactString(value);
    if (!normalized) continue;
    const key = normalized.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    deduped.push(normalized);
  }
  return deduped;
}

function createEnrichmentField(value, trustLevel, source, notes = null) {
  return {
    value,
    trustLevel,
    source,
    notes,
  };
}

function hasMeaningfulEnrichmentValue(value) {
  if (Array.isArray(value)) return value.length > 0;
  if (typeof value === "boolean") return true;
  return value !== null && value !== undefined && value !== "";
}

function createSecurityAutofillField(value, confidence, source, evidenceType, notes = null) {
  return {
    value,
    confidence,
    source,
    evidenceType,
    notes,
  };
}

function setVerifiedSecurityField(store, field, value, source, evidenceType, notes = null) {
  if (!hasMeaningfulEnrichmentValue(value)) return;
  store[field] = createSecurityAutofillField(value, "verified", source, evidenceType, notes);
}

function pushSecurityReview(queue, field, summary, reason, evidenceType, details = null) {
  if (!hasMeaningfulEnrichmentValue(summary) && !hasMeaningfulEnrichmentValue(details)) return;
  queue.push({
    field,
    confidence: "review",
    summary,
    reason,
    evidenceType,
    details,
  });
}

function buildSecurityAutofillExport(result) {
  const verifiedAutofill = {};
  const reviewQueue = [];
  const missingHeaders = Object.entries(result.securityHeaders || {})
    .filter(([header, status]) => status?.present === false && header !== "x-xss-protection")
    .map(([header]) => header);
  const hasMailSurface = (result.dnsRecords?.mx?.length || 0) > 0 ||
    (result.contacts?.emails || []).some((email) => String(email).toLowerCase().endsWith(`@${result.domain}`));
  const exposureFacts = (result.sensitiveExposures?.sensitiveFiles || [])
    .filter((entry) => !entry?.reportOnly)
    .map((entry) => ({
      type: entry.type || entry.endpointType || null,
      path: entry.url || entry.path || entry.endpoint || null,
      severity: entry.severity || null,
      status: entry.status || null,
    }))
    .filter((entry) => entry.type || entry.path);
  const verifiedFindingMessages = (result.findingConfidence?.verified || []).map((entry) => entry.message);
  const probableFindingMessages = (result.findingConfidence?.probable || []).map((entry) => entry.message);
  const instrumentationMessages = [
    ...((result.findingConfidence?.observedUnderInstrumentation || []).map((entry) => entry.message)),
    ...((result.findingConfidence?.unverified || [])
      .map((entry) => entry.message)
      .filter((message) => /runtime error|console error|instrumentation/i.test(message))),
  ];

  setVerifiedSecurityField(
    verifiedAutofill,
    "tls_valid",
    !!result.ssl?.valid,
    "tls-check",
    "direct-observation",
    result.ssl?.valid ? null : "Certificate trust, hostname, or chain validation failed."
  );
  setVerifiedSecurityField(
    verifiedAutofill,
    "tls_expires_at",
    result.ssl?.expires || null,
    "tls-check",
    "direct-observation"
  );
  setVerifiedSecurityField(
    verifiedAutofill,
    "tls_days_until_expiry",
    result.ssl?.daysUntilExpiry ?? null,
    "tls-check",
    "direct-observation"
  );
  setVerifiedSecurityField(
    verifiedAutofill,
    "tls_issuer",
    result.ssl?.issuer || null,
    "tls-check",
    "direct-observation"
  );
  setVerifiedSecurityField(
    verifiedAutofill,
    "tls_error",
    result.ssl?.valid ? null : (result.ssl?.error || "TLS validation failed"),
    "tls-check",
    "direct-observation"
  );
  setVerifiedSecurityField(
    verifiedAutofill,
    "tls_authorization_error",
    result.ssl?.authorizationError || null,
    "tls-check",
    "direct-observation"
  );
  setVerifiedSecurityField(
    verifiedAutofill,
    "tls_hostname_error",
    result.ssl?.hostnameError || null,
    "tls-check",
    "direct-observation"
  );
  setVerifiedSecurityField(
    verifiedAutofill,
    "https_redirects",
    result.https?.redirects === true,
    "http-head-check",
    "direct-observation",
    result.https?.redirects === false ? "HTTP did not redirect to HTTPS during validation." : null
  );
  setVerifiedSecurityField(
    verifiedAutofill,
    "https_status_code",
    result.https?.statusCode ?? null,
    "http-head-check",
    "direct-observation"
  );
  setVerifiedSecurityField(
    verifiedAutofill,
    "missing_security_headers",
    missingHeaders,
    "response-headers",
    "direct-observation"
  );
  setVerifiedSecurityField(
    verifiedAutofill,
    "mixed_content_found",
    !!result.mixedContent?.found,
    "dom-scan",
    "direct-observation"
  );
  setVerifiedSecurityField(
    verifiedAutofill,
    "mixed_content_resource_count",
    result.mixedContent?.found ? (result.mixedContent?.resources?.length || 0) : null,
    "dom-scan",
    "direct-observation"
  );
  if (hasMailSurface) {
    setVerifiedSecurityField(
      verifiedAutofill,
      "spf_present",
      !!result.emailAuth?.spf,
      "dns",
      "direct-observation"
    );
    setVerifiedSecurityField(
      verifiedAutofill,
      "spf_record",
      result.emailAuth?.spf || null,
      "dns",
      "direct-observation"
    );
    setVerifiedSecurityField(
      verifiedAutofill,
      "dmarc_present",
      !!result.emailAuth?.dmarc,
      "dns",
      "direct-observation"
    );
    setVerifiedSecurityField(
      verifiedAutofill,
      "dmarc_record",
      result.emailAuth?.dmarc || null,
      "dns",
      "direct-observation"
    );
  }
  setVerifiedSecurityField(
    verifiedAutofill,
    "exposed_git",
    !!result.sensitiveExposures?.exposedGit,
    "light-probe",
    "direct-observation"
  );
  setVerifiedSecurityField(
    verifiedAutofill,
    "exposed_env",
    !!result.sensitiveExposures?.exposedEnv,
    "light-probe",
    "direct-observation"
  );
  setVerifiedSecurityField(
    verifiedAutofill,
    "exposed_config",
    !!result.sensitiveExposures?.exposedConfig,
    "light-probe",
    "direct-observation"
  );
  setVerifiedSecurityField(
    verifiedAutofill,
    "sensitive_file_exposures",
    exposureFacts,
    "light-probe",
    "direct-observation"
  );
  setVerifiedSecurityField(
    verifiedAutofill,
    "verified_findings",
    verifiedFindingMessages,
    "finding-confidence",
    "verified-bucket"
  );
  if (
    result.securityOutreach?.primaryHook &&
    (result.securityOutreach?.verifiedHooks || []).includes(result.securityOutreach.primaryHook)
  ) {
    setVerifiedSecurityField(
      verifiedAutofill,
      "security_outreach_primary_hook",
      result.securityOutreach.primaryHook,
      "security-outreach-summary",
      "verified-derived"
    );
  }

  if (
    (result.cookieSecurity?.findings || []).length > 0 ||
    (result.cookieSecurity?.sessionCookies || []).length > 0 ||
    (result.cookieSecurity?.authCookies || []).length > 0
  ) {
    pushSecurityReview(
      reviewQueue,
      "cookie_security_posture",
      {
        sessionCookies: result.cookieSecurity?.sessionCookies || [],
        authCookies: result.cookieSecurity?.authCookies || [],
        csrfCookies: result.cookieSecurity?.csrfCookies || [],
        findings: (result.cookieSecurity?.findings || []).map((finding) => finding.message),
      },
      "Cookie flags are directly observed, but session/auth significance still depends on stack and app context.",
      "cookie-analysis"
    );
  }

  const csrfSignals = (result.forms?.issues || []).filter((issue) => /csrf/i.test(issue));
  if (csrfSignals.length > 0) {
    pushSecurityReview(
      reviewQueue,
      "csrf_posture",
      csrfSignals,
      "Visible token absence alone is not enough to claim a CSRF vulnerability without stronger authenticated state-change evidence.",
      "form-analysis"
    );
  }

  if (result.paymentSecurity?.hasPaymentSurface) {
    pushSecurityReview(
      reviewQueue,
      "payment_security_posture",
      {
        paymentFlowType: result.paymentSecurity?.paymentFlowType || null,
        hostedThirdPartyCheckout: !!result.paymentSecurity?.hostedThirdPartyCheckout,
        embeddedTrustedWidget: !!result.paymentSecurity?.embeddedTrustedWidget,
        onSiteCardCollectionForms: result.paymentSecurity?.onSiteCardCollectionForms || 0,
        providers: result.paymentSecurity?.providers || [],
        findings: (result.paymentSecurity?.findings || []).map((finding) => finding.message),
      },
      "Payment surfaces were observed directly, but the compliance/security meaning still needs human review.",
      "payment-analysis"
    );
  }

  if ((result.adminEndpoints?.found || []).length > 0) {
    pushSecurityReview(
      reviewQueue,
      "admin_surface_exposure",
      buildAdminSurfaceReviewSummary(result),
      "Admin/login route presence is observed, but exposure significance depends on whether the route is expected and properly protected.",
      "admin-endpoint-probe"
    );
  }

  const dkimReviewSummary = buildDkimReviewSummary(result);
  if (dkimReviewSummary.hasMailSurface ? (!result.emailAuth?.dkim || /guess/i.test(result.emailAuth?.dkimDetectionMethod || "")) : !!result.emailAuth?.dkim) {
    pushSecurityReview(
      reviewQueue,
      "dkim_posture",
      dkimReviewSummary,
      dkimReviewSummary.hasMailSurface
        ? "DKIM is still conservative here because selector coverage can be incomplete; absence or sampled presence should be reviewed before CRM autofill."
        : "DKIM review is suppressed when no real mail surface is observed; sampled presence can still be useful context for a human reviewer.",
      "dns"
    );
  }

  if (probableFindingMessages.length > 0) {
    pushSecurityReview(
      reviewQueue,
      "probable_findings",
      probableFindingMessages,
      "These findings are intentionally below the database-safe threshold and should be reviewed before use.",
      "finding-confidence"
    );
  }

  if (instrumentationMessages.length > 0) {
    pushSecurityReview(
      reviewQueue,
      "instrumentation_only_observations",
      instrumentationMessages,
      "Browser/runtime observations can reflect instrumentation side effects or third-party behavior rather than a target-site vulnerability.",
      "browser-instrumentation"
    );
  }

  return {
    schemaVersion: 1,
    verifiedAutofill,
    reviewQueue,
    summary: {
      verifiedFieldCount: Object.keys(verifiedAutofill).length,
      reviewItemCount: reviewQueue.length,
      autofillSafe: Object.keys(verifiedAutofill).length > 0,
    },
  };
}

function buildLeadEnrichment(result) {
  const li = result.leadIntelligence || {};
  const contacts = result.contacts || {};
  const socials = {
    ...(contacts.socials || {}),
    ...(li.socialProfiles || {}),
  };

  const paymentMethods = dedupeStrings(li.ecommerce?.paymentMethods || []);
  const services = dedupeStrings(result.businessInfo?.services || []);
  const emails = dedupeStrings(contacts.emails || []);
  const phones = dedupeStrings(contacts.phones || []);
  const secondaryIndustries = dedupeStrings(li.industryClassification?.secondary || []);
  const serviceRegions = dedupeStrings(li.serviceArea?.regions || []);
  const websiteUrl = result.actualUrl || result.testUrl || null;
  const addressData = sanitizeAddressData(result.address || {});
  const normalizedContactPage = compactString(result.forms?.contactPage)?.replace(/\/$/, "");
  const normalizedWebsiteUrl = compactString(websiteUrl)?.replace(/\/$/, "");
  const contactRoute = sanitizeContactRoute(
    result.forms?.contactPage,
    websiteUrl,
    !!normalizedContactPage && !!normalizedWebsiteUrl && normalizedContactPage === normalizedWebsiteUrl
  );
  const socialFields = {
    facebook_url: sanitizeSocialUrl("facebook_url", socials.facebook?.url || socials.facebook || null),
    instagram_url: sanitizeSocialUrl("instagram_url", socials.instagram?.url || socials.instagram || null),
    linkedin_url: sanitizeSocialUrl("linkedin_url", socials.linkedin?.url || socials.linkedin || null),
    twitter_url: sanitizeSocialUrl("twitter_url", socials.twitter?.url || socials.twitter || null),
    youtube_url: sanitizeSocialUrl("youtube_url", socials.youtube?.url || socials.youtube || null),
    tiktok_url: sanitizeSocialUrl("tiktok_url", socials.tiktok?.url || socials.tiktok || null),
    yelp_url: sanitizeSocialUrl("yelp_url", socials.yelp?.url || socials.yelp || null),
    google_business_url: sanitizeSocialUrl("google_business_url", socials.gmb?.url || socials.google_business || null),
  };
  const teamPageUrl = sanitizeTeamPageUrl(li.teamInfo?.teamPageUrl, websiteUrl);
  const primaryIndustry = compactString(li.industryClassification?.primary);
  const cms = compactString(result.techStack?.cms);
  const ecommercePlatform = compactString(li.ecommerce?.platform);
  const businessName = sanitizeBusinessName(result.businessInfo?.name);
  const businessDescription = sanitizeBusinessDescription(result.businessInfo?.description, businessName);

  const databaseAutofill = {
    lead_id: result.leadId,
    domain: result.domain || null,
    website_url: websiteUrl,
    email_primary: emails[0] || null,
    phone_primary: phones[0] || null,
    contact_form: contactRoute,
    business_name: businessName,
    business_tagline: compactString(result.businessInfo?.tagline),
    business_description: businessDescription,
    address_raw: addressData.raw,
    street: addressData.street,
    city: addressData.city,
    state: addressData.state,
    zip: addressData.zip,
    country: addressData.country,
    cms,
    ecommerce_platform: ecommercePlatform,
    has_ecommerce: !!li.ecommerce?.detected,
    has_cart: !!li.ecommerce?.hasCart,
    has_checkout: !!li.ecommerce?.hasCheckout,
    primary_industry: primaryIndustry,
    service_area_type: compactString(li.serviceArea?.type),
    newsletter_detected: !!li.newsletter?.detected,
    team_page_url: teamPageUrl,
    estimated_years_in_business: li.yearsInBusiness?.estimated ?? null,
    founded_year: li.yearsInBusiness?.foundedYear ?? result.businessInfo?.founded ?? null,
    employee_count: li.teamInfo?.employeeCount ?? result.businessInfo?.employeeCount ?? null,
    payment_methods: paymentMethods,
    services: services,
    service_regions: serviceRegions,
    secondary_industries: secondaryIndustries,
    ...socialFields,
  };

  const fieldConfidence = {
    lead_id: createEnrichmentField(result.leadId, "verified", "audit-input"),
    domain: createEnrichmentField(result.domain || null, "verified", "audit-input"),
    website_url: createEnrichmentField(websiteUrl, "verified", result.actualUrl ? "browser-final-url" : "audit-input"),
    email_primary: createEnrichmentField(emails[0] || null, emails[0] ? "observed" : "unverified", emails[0] ? "homepage-dom" : "missing"),
    phone_primary: createEnrichmentField(phones[0] || null, phones[0] ? "observed" : "unverified", phones[0] ? "homepage-dom" : "missing"),
    contact_form: createEnrichmentField(contactRoute, contactRoute ? "observed" : "unverified", contactRoute ? "form-analysis" : "missing"),
    business_name: createEnrichmentField(businessName, businessName ? "observed" : "unverified", businessName ? "business-extraction" : "missing"),
    business_tagline: createEnrichmentField(compactString(result.businessInfo?.tagline), result.businessInfo?.tagline ? "observed" : "unverified", result.businessInfo?.tagline ? "business-extraction" : "missing"),
    business_description: createEnrichmentField(businessDescription, businessDescription ? "observed" : "unverified", businessDescription ? "business-extraction" : "missing"),
    address_raw: createEnrichmentField(addressData.raw, addressData.raw ? "observed" : "unverified", addressData.raw ? "address-extraction" : "missing"),
    street: createEnrichmentField(addressData.street, addressData.street ? "observed" : "unverified", addressData.street ? "address-extraction" : "missing"),
    city: createEnrichmentField(addressData.city, addressData.city ? "observed" : "unverified", addressData.city ? "address-extraction" : "missing"),
    state: createEnrichmentField(addressData.state, addressData.state ? "observed" : "unverified", addressData.state ? "address-extraction" : "missing"),
    zip: createEnrichmentField(addressData.zip, addressData.zip ? "observed" : "unverified", addressData.zip ? "address-extraction" : "missing"),
    country: createEnrichmentField(addressData.country, addressData.country ? "observed" : "unverified", addressData.country ? "address-extraction" : "missing"),
    cms: createEnrichmentField(cms, cms ? "inferred" : "unverified", cms ? "tech-fingerprint" : "missing"),
    ecommerce_platform: createEnrichmentField(ecommercePlatform, ecommercePlatform ? "inferred" : "unverified", ecommercePlatform ? "lead-intelligence:ecommerce" : "missing"),
    has_ecommerce: createEnrichmentField(!!li.ecommerce?.detected, li.ecommerce?.detected ? "inferred" : "unverified", li.ecommerce?.detected ? "lead-intelligence:ecommerce" : "missing"),
    has_cart: createEnrichmentField(!!li.ecommerce?.hasCart, li.ecommerce?.hasCart ? "observed" : "unverified", li.ecommerce?.hasCart ? "lead-intelligence:ecommerce" : "missing"),
    has_checkout: createEnrichmentField(!!li.ecommerce?.hasCheckout, li.ecommerce?.hasCheckout ? "observed" : "unverified", li.ecommerce?.hasCheckout ? "lead-intelligence:ecommerce" : "missing"),
    primary_industry: createEnrichmentField(primaryIndustry, primaryIndustry ? "inferred" : "unverified", primaryIndustry ? "lead-intelligence:industry" : "missing"),
    service_area_type: createEnrichmentField(compactString(li.serviceArea?.type), li.serviceArea?.type ? "inferred" : "unverified", li.serviceArea?.type ? "lead-intelligence:service-area" : "missing"),
    newsletter_detected: createEnrichmentField(!!li.newsletter?.detected, li.newsletter?.detected ? "observed" : "unverified", li.newsletter?.detected ? "lead-intelligence:newsletter" : "missing"),
    team_page_url: createEnrichmentField(teamPageUrl, teamPageUrl ? "observed" : "unverified", teamPageUrl ? "lead-intelligence:team-page" : "missing"),
    estimated_years_in_business: createEnrichmentField(li.yearsInBusiness?.estimated ?? null, li.yearsInBusiness?.estimated ? "inferred" : "unverified", li.yearsInBusiness?.estimated ? "lead-intelligence:years-in-business" : "missing"),
    founded_year: createEnrichmentField(li.yearsInBusiness?.foundedYear ?? result.businessInfo?.founded ?? null, (li.yearsInBusiness?.foundedYear ?? result.businessInfo?.founded) ? "inferred" : "unverified", (li.yearsInBusiness?.foundedYear ?? result.businessInfo?.founded) ? "lead-intelligence:years-in-business" : "missing"),
    employee_count: createEnrichmentField(li.teamInfo?.employeeCount ?? result.businessInfo?.employeeCount ?? null, (li.teamInfo?.employeeCount ?? result.businessInfo?.employeeCount) ? "inferred" : "unverified", (li.teamInfo?.employeeCount ?? result.businessInfo?.employeeCount) ? "lead-intelligence:team" : "missing"),
    payment_methods: createEnrichmentField(paymentMethods, paymentMethods.length > 0 ? "inferred" : "unverified", paymentMethods.length > 0 ? "lead-intelligence:ecommerce" : "missing"),
    services: createEnrichmentField(services, services.length > 0 ? "observed" : "unverified", services.length > 0 ? "business-extraction" : "missing"),
    service_regions: createEnrichmentField(serviceRegions, serviceRegions.length > 0 ? "inferred" : "unverified", serviceRegions.length > 0 ? "lead-intelligence:service-area" : "missing"),
    secondary_industries: createEnrichmentField(secondaryIndustries, secondaryIndustries.length > 0 ? "inferred" : "unverified", secondaryIndustries.length > 0 ? "lead-intelligence:industry" : "missing"),
  };

  for (const [field, value] of Object.entries(socialFields)) {
    const platform = field.replace("_url", "");
    const socialSource = contacts.socials?.[platform]
      ? "contact-extraction"
      : li.socialProfiles?.[platform]
        ? "lead-intelligence:social-profile"
        : "missing";
    fieldConfidence[field] = createEnrichmentField(
      value,
      value ? "observed" : "unverified",
      socialSource
    );
  }

  const availableFields = Object.fromEntries(
    Object.entries(databaseAutofill).filter(([, value]) => hasMeaningfulEnrichmentValue(value))
  );
  const securityAutofill = buildSecurityAutofillExport(result);

  return {
    schemaVersion: 2,
    generatedAt: result.timestamp,
    mergeReadiness: {
      ready: true,
      strategy: "fill-missing-only",
      recommendedKey: result.leadId,
      availableFieldCount: Object.keys(availableFields).length,
    },
    sourceAudit: {
      leadId: result.leadId,
      inputUrl: result.testUrl,
      actualUrl: result.actualUrl || result.testUrl || null,
      siteReachable: !!result.siteAvailability?.reachable,
      siteAvailabilityMethod: result.siteAvailability?.method || null,
      auditScore: result.auditScore ?? null,
      findingConfidenceCounts: {
        verified: result.findingConfidence?.verified?.length || 0,
        probable: result.findingConfidence?.probable?.length || 0,
        observedUnderInstrumentation: result.findingConfidence?.observedUnderInstrumentation?.length || 0,
        unverified: result.findingConfidence?.unverified?.length || 0,
      },
    },
    contacts: {
      emails: emails.map(value => ({ value, source: "homepage-dom", confidence: "medium" })),
      phones: phones.map(value => ({ value, source: "homepage-dom", confidence: "medium" })),
      contact_form: contactRoute ? { value: contactRoute, source: "form-analysis", confidence: "medium" } : null,
      socials: Object.entries(socialFields)
        .filter(([, value]) => compactString(value))
        .map(([field, value]) => ({
          field,
          value,
          source: contacts.socials?.[field.replace("_url", "")] ? "contact-extraction" : "lead-intelligence",
          confidence: "medium",
        })),
    },
    business: {
      name: businessName,
      tagline: compactString(result.businessInfo?.tagline),
      description: businessDescription,
      hours: compactString(result.businessInfo?.hours),
      services,
      employeeCount: li.teamInfo?.employeeCount ?? result.businessInfo?.employeeCount ?? null,
      hasReviews: !!li.reputation?.hasReviews || !!result.businessInfo?.hasReviews,
      hasTestimonials: !!li.reputation?.hasTestimonials || !!result.businessInfo?.hasTestimonials,
    },
    digitalPresence: {
      cms: compactString(result.techStack?.cms),
      frameworks: dedupeStrings(result.techStack?.frameworks || []),
      analytics: dedupeStrings(result.techStack?.analytics || []),
      hosting: dedupeStrings(result.techStack?.hosting || []),
      ecommercePlatform: compactString(li.ecommerce?.platform),
      paymentMethods,
      newsletterDetected: !!li.newsletter?.detected,
      newsletterProvider: compactString(li.newsletter?.provider),
      teamPageUrl,
      primaryIndustry: compactString(li.industryClassification?.primary),
      serviceAreaType: compactString(li.serviceArea?.type),
      serviceRegions,
    },
    databaseAutofill,
    securityAutofill,
    availableFields,
    fieldConfidence,
    autofillCandidates: Object.fromEntries(
      Object.entries(fieldConfidence).filter(([, meta]) => {
        const value = meta.value;
        return hasMeaningfulEnrichmentValue(value);
      })
    ),
  };
}

/**
 * Check DNS-based email authentication (SPF, DMARC, DKIM)
 */
async function checkEmailAuth(hostname) {
  const dns = require("dns").promises;
  const results = {
    spf: null,
    dmarc: null,
    dkim: null,
    dkimDetectionMethod: "common-selector-guess",
    dkimCheckedSelectors: [],
    dkimProviderHints: [],
  };
  
  // SPF check
  try {
    const txtRecords = await dns.resolveTxt(hostname).catch(() => []);
    const spfRecord = txtRecords.flat().find(r => r.startsWith("v=spf1"));
    results.spf = spfRecord || null;
  } catch (e) {
    results.spf = null;
  }
  
  // DMARC check
  try {
    const dmarcRecords = await dns.resolveTxt(`_dmarc.${hostname}`).catch(() => []);
    const dmarcRecord = dmarcRecords.flat().find(r => r.startsWith("v=DMARC1"));
    results.dmarc = dmarcRecord || null;
  } catch (e) {
    results.dmarc = null;
  }

  let mxHosts = [];
  try {
    const mxRecords = await dns.resolveMx(hostname).catch(() => []);
    mxHosts = mxRecords.map((record) => record.exchange).filter(Boolean);
  } catch (e) {
    mxHosts = [];
  }

  const selectorSample = buildDkimSelectorSample(results.spf, mxHosts);
  results.dkimDetectionMethod = selectorSample.strategy;
  results.dkimCheckedSelectors = selectorSample.selectors;
  results.dkimProviderHints = selectorSample.providers;
  
  // DKIM check - try provider-informed selectors first when signals exist
  for (const selector of selectorSample.selectors) {
    try {
      const dkimRecords = await dns.resolveTxt(`${selector}._domainkey.${hostname}`).catch(() => []);
      const dkimRecord = dkimRecords.flat().find(r => r.startsWith('v=DKIM1') || r.includes('p='));
      if (dkimRecord) {
        results.dkim = { selector, record: dkimRecord, detectionMethod: selectorSample.strategy };
        break;
      }
    } catch (e) {
      // Continue to next selector
    }
  }
  
  return results;
}

/**
 * Fingerprint the tech stack of a website
 * Enhanced with confidence scoring, more platforms, hosting detection, and backend hints
 */
async function fingerprintTechStack(page) {
  return page.evaluate(() => {
    const tech = {
      cms: null,
      cmsConfidence: null, // 'high', 'medium', 'low'
      ecommerce: null,
      ecommerceConfidence: null,
      frameworks: [],
      libraries: [],
      analytics: [],
      advertising: [],
      cdn: [],
      hosting: null,
      hostingConfidence: null,
      server: null,
      backend: null,
      backendConfidence: null,
      builders: [],
      indicators: [],
      confidence: {
        cms: [],
        ecommerce: [],
        hosting: [],
        backend: []
      }
    };
    
    const html = document.documentElement.outerHTML;
    const htmlLower = html.toLowerCase();
    const head = document.head ? document.head.innerHTML : '';
    const scripts = Array.from(document.querySelectorAll('script[src]')).map(s => s.src.toLowerCase());
    const scriptTags = Array.from(document.querySelectorAll('script[src]')).map(s => s.src);
    const metas = Array.from(document.querySelectorAll('meta')).map(m => ({
      name: m.getAttribute('name') || m.getAttribute('property') || '',
      content: m.getAttribute('content') || ''
    }));
    const links = Array.from(document.querySelectorAll('link[href]')).map(l => l.href.toLowerCase());
    const cookies = document.cookie;
    
    // Helper to add detection with confidence
    const addDetection = (category, name, confidence, indicator) => {
      if (category === 'cms') {
        tech.cms = name;
        tech.cmsConfidence = confidence;
        tech.indicators.push(indicator);
        tech.confidence.cms.push({ name, confidence, indicator });
      } else if (category === 'ecommerce') {
        tech.ecommerce = name;
        tech.ecommerceConfidence = confidence;
        tech.indicators.push(indicator);
        tech.confidence.ecommerce.push({ name, confidence, indicator });
      } else if (category === 'hosting') {
        tech.hosting = name;
        tech.hostingConfidence = confidence;
        tech.indicators.push(indicator);
        tech.confidence.hosting.push({ name, confidence, indicator });
      } else if (category === 'backend') {
        tech.backend = name;
        tech.backendConfidence = confidence;
        tech.indicators.push(indicator);
        tech.confidence.backend.push({ name, confidence, indicator });
      }
    };
    
    // ==========================================
    // CMS DETECTION (with confidence levels)
    // ==========================================
    
    // WordPress - HIGH confidence indicators
    if (html.includes('/wp-content/') || html.includes('/wp-includes/')) {
      addDetection('cms', 'WordPress', 'high', 'WordPress core paths detected');
    } else if (document.querySelector('link[href*="wp-"]') || html.includes('wp-json')) {
      addDetection('cms', 'WordPress', 'high', 'WordPress API or assets detected');
    } else if (html.includes('WordPress') && html.includes('wpemoji')) {
      addDetection('cms', 'WordPress', 'high', 'WordPress emoji script detected');
    }
    // WordPress - MEDIUM confidence
    else if (html.includes('xmlrpc.php') || cookies.includes('wordpress_')) {
      addDetection('cms', 'WordPress', 'medium', 'WordPress endpoints or cookies detected');
    }
    
    // Shopify - HIGH confidence
    if (html.includes('Shopify') || document.querySelector('script[src*="cdn.shopify"]')) {
      addDetection('cms', 'Shopify', 'high', 'Shopify CDN detected');
      addDetection('ecommerce', 'Shopify', 'high', 'Shopify platform');
    } else if (document.querySelector('script[src*="shopify"]') || cookies.includes('_shopify')) {
      addDetection('cms', 'Shopify', 'high', 'Shopify scripts or cookies');
      addDetection('ecommerce', 'Shopify', 'high', 'Shopify platform');
    }
    
    // Squarespace - HIGH confidence
    if (html.includes('Squarespace') || document.querySelector('[class*="squarespace"]') || 
        document.querySelector('script[src*="squarespace"]')) {
      addDetection('cms', 'Squarespace', 'high', 'Squarespace detected');
    }
    
    // Wix - HIGH confidence
    if (html.includes('Wix.com') || document.querySelector('[class*="wix-"]') || 
        document.querySelector('script[src*="wixstatic"]') || document.querySelector('script[src*="wix.com"]')) {
      addDetection('cms', 'Wix', 'high', 'Wix detected');
    }
    
    // Webflow - HIGH confidence
    if (html.includes('Webflow') || document.querySelector('script[src*="webflow"]') ||
        document.querySelector('[data-wf-site]') || document.querySelector('[data-wf-page]')) {
      addDetection('cms', 'Webflow', 'high', 'Webflow site attributes detected');
    }
    
    // Ghost - HIGH confidence
    if (document.querySelector('script[src*="ghost.io"]') || html.includes('Ghost CMS') ||
        document.querySelector('meta[name="generator"][content*="Ghost"]')) {
      addDetection('cms', 'Ghost', 'high', 'Ghost CMS detected');
    }
    
    // Drupal - HIGH confidence
    if (html.includes('Drupal') || document.querySelector('script[src*="drupal"]') ||
        document.querySelector('meta[name="generator"][content*="Drupal"]')) {
      addDetection('cms', 'Drupal', 'high', 'Drupal detected');
    }
    
    // Joomla - HIGH confidence
    if (html.includes('Joomla') || document.querySelector('script[src*="joomla"]') ||
        document.querySelector('meta[name="generator"][content*="Joomla"]')) {
      addDetection('cms', 'Joomla', 'high', 'Joomla detected');
    }
    
    // BigCommerce - HIGH confidence
    if (html.includes('BigCommerce') || document.querySelector('script[src*="bigcommerce"]') ||
        html.includes('cdn-') && html.includes('bigcommerce')) {
      addDetection('cms', 'BigCommerce', 'high', 'BigCommerce detected');
      addDetection('ecommerce', 'BigCommerce', 'high', 'BigCommerce platform');
    }
    
    // Salesforce Commerce Cloud - HIGH confidence
    if (html.includes('Commerce Cloud') || document.querySelector('script[src*="demandware"]') ||
        cookies.includes('dwac_') || cookies.includes('dwsid')) {
      addDetection('cms', 'Salesforce Commerce Cloud', 'high', 'Salesforce Commerce Cloud detected');
      addDetection('ecommerce', 'Salesforce Commerce Cloud', 'high', 'Salesforce platform');
    }
    
    // Adobe Experience Manager
    if (html.includes('Adobe Experience Manager') || document.querySelector('script[src*="adobeaem"]')) {
      addDetection('cms', 'Adobe Experience Manager', 'high', 'AEM detected');
    }
    
    // Contentful (headless CMS)
    if (html.includes('contentful') || document.querySelector('script[src*="contentful"]')) {
      tech.cms = tech.cms || 'Headless CMS';
      tech.indicators.push('Contentful headless CMS detected');
    }
    
    // ==========================================
    // E-COMMERCE PLATFORMS
    // ==========================================
    
    // WooCommerce - HIGH confidence
    if (document.querySelector('script[src*="woocommerce"]') || html.includes('wc-block') ||
        html.includes('woocommerce') || document.querySelector('[class*="woocommerce"]')) {
      addDetection('ecommerce', 'WooCommerce', 'high', 'WooCommerce detected');
      if (!tech.cms) {
        addDetection('cms', 'WordPress', 'medium', 'WooCommerce implies WordPress');
      }
    }
    
    // Magento/Adobe Commerce - HIGH confidence
    if (html.includes('Magento') || document.querySelector('script[src*="magento"]') ||
        html.includes('/magento/') || cookies.includes('mage-')) {
      addDetection('ecommerce', 'Magento', 'high', 'Magento detected');
    }
    
    // PrestaShop
    if (html.includes('PrestaShop') || document.querySelector('script[src*="prestashop"]') ||
        cookies.includes('PrestaShop')) {
      addDetection('ecommerce', 'PrestaShop', 'high', 'PrestaShop detected');
    }
    
    // ==========================================
    // FRONTEND FRAMEWORKS
    // ==========================================
    
    // Next.js
    if (document.querySelector('[data-reactroot]') || html.includes('__NEXT_DATA__') || 
        document.querySelector('script[src*="_next/"]') || html.includes('/_next/static/')) {
      tech.frameworks.push('Next.js');
      tech.indicators.push('Next.js framework detected');
    }
    
    // Nuxt.js
    if (html.includes('__NUXT__') || document.querySelector('script[src*="_nuxt/"]')) {
      tech.frameworks.push('Nuxt.js');
      tech.indicators.push('Nuxt.js framework detected');
    }
    
    // Vue.js
    if (document.querySelector('[data-v-]') || html.includes('vue-app') || window.Vue) {
      tech.frameworks.push('Vue.js');
    }
    
    // Angular
    if (document.querySelector('[ng-version]') || html.includes('ng-version') ||
        document.querySelector('app-root') || document.querySelector('[ng-app]')) {
      tech.frameworks.push('Angular');
    }
    
    // Gatsby
    if (html.includes('gatsby-image') || document.querySelector('script[src*="gatsby"]') ||
        html.includes('/page-data/') || document.querySelector('[data-gatsby-head]')) {
      tech.frameworks.push('Gatsby');
    }
    
    // Svelte/SvelteKit
    if (html.includes('svelte') || document.querySelector('[class*="svelte-"]')) {
      tech.frameworks.push('Svelte');
    }
    
    // Remix
    if (html.includes('__remixContext') || document.querySelector('script[src*="remix"]')) {
      tech.frameworks.push('Remix');
    }
    
    // Astro
    if (html.includes('astro') && html.includes('astro-slot')) {
      tech.frameworks.push('Astro');
    }
    
    // ==========================================
    // LIBRARIES
    // ==========================================
    
    // jQuery
    if (window.jQuery || html.includes('jquery') || scripts.some(s => s.includes('jquery'))) {
      tech.libraries.push('jQuery');
    }
    
    // React
    if (window.React || document.querySelector('[data-reactroot]') ||
        document.querySelector('[data-reactid]') || html.includes('__REACT')) {
      tech.libraries.push('React');
    }
    
    // Vue
    if (window.Vue || document.querySelector('[data-v-]')) {
      tech.libraries.push('Vue');
    }
    
    // Bootstrap
    if (window.bootstrap || document.querySelector('link[href*="bootstrap"]') ||
        document.querySelector('[class*="container-"]')) {
      tech.libraries.push('Bootstrap');
    }
    
    // Tailwind CSS
    if (window.tailwind || htmlLower.includes('tailwind') || 
        document.querySelector('[class*="tw-"]') || document.querySelector('[class*="text-"]')) {
      // More specific check for Tailwind
      const classes = document.body?.className || '';
      if (classes.includes('bg-') || classes.includes('flex-') || classes.includes('rounded-')) {
        tech.libraries.push('Tailwind CSS');
      }
    }
    
    // ==========================================
    // ANALYTICS
    // ==========================================
    
    if (window.gtag || window.dataLayer || html.includes('googletagmanager') || html.includes('gtag(')) {
      tech.analytics.push('Google Tag Manager');
    }
    if (window.ga || html.includes('google-analytics') || html.includes('ga(') || 
        html.includes('gtag("config")')) {
      tech.analytics.push('Google Analytics');
    }
    if (html.includes('facebook.net/en_US/fbevents') || window.fbq || html.includes('fbq(')) {
      tech.analytics.push('Facebook Pixel');
    }
    if (html.includes('hotjar') || window.hj) {
      tech.analytics.push('Hotjar');
    }
    if (html.includes('mixpanel') || window.mixpanel) {
      tech.analytics.push('Mixpanel');
    }
    if (html.includes('segment.com') || window.analytics) {
      tech.analytics.push('Segment');
    }
    if (html.includes('hubspot') || document.querySelector('script[src*="hs-scripts"]')) {
      tech.analytics.push('HubSpot');
    }
    if (html.includes('plausible') || document.querySelector('script[src*="plausible"]')) {
      tech.analytics.push('Plausible');
    }
    if (html.includes('amplitude') || window.amplitude) {
      tech.analytics.push('Amplitude');
    }
    if (html.includes('heap.io') || window.heap) {
      tech.analytics.push('Heap Analytics');
    }
    if (html.includes('clarity') || document.querySelector('script[src*="clarity.ms"]')) {
      tech.analytics.push('Microsoft Clarity');
    }
    
    // ==========================================
    // ADVERTISING
    // ==========================================
    
    if (html.includes('doubleclick') || html.includes('googlesyndication')) {
      tech.advertising.push('Google Ads (DoubleClick)');
    }
    if (html.includes('google_ads') || html.includes('adsbygoogle') || window.adsbygoogle) {
      tech.advertising.push('Google AdSense');
    }
    if (html.includes('facebook.com/tr') || html.includes('fbq("track"')) {
      tech.advertising.push('Facebook Ads');
    }
    if (html.includes('linkedin.com/insight') || window.lintrk) {
      tech.advertising.push('LinkedIn Insight');
    }
    if (html.includes('pinterest.com/ct') || document.querySelector('script[src*="pinterest"]')) {
      tech.advertising.push('Pinterest Tag');
    }
    if (html.includes('tiktok.com/pixel') || document.querySelector('script[src*="tiktok"]')) {
      tech.advertising.push('TikTok Pixel');
    }
    
    // ==========================================
    // CDN & HOSTING DETECTION
    // ==========================================
    
// Cloudflare (CDN + can indicate hosting)
    if (htmlLower.includes('cloudflare') || document.querySelector('script[src*="cloudflare"]') ||
        html.includes('cf-ray') || scripts.some(s => s.includes('cloudflare'))) {
      tech.cdn.push('Cloudflare');
      if (!tech.hosting) {
        addDetection('hosting', 'Cloudflare', 'low', 'Cloudflare CDN detected');
      }
    }
    
    // AWS
    if (scripts.some(s => s.includes('amazonaws.com') || s.includes('cloudfront.net'))) {
      tech.cdn.push('AWS CloudFront');
      if (!tech.hosting) {
        addDetection('hosting', 'AWS', 'low', 'AWS CloudFront detected');
      }
    }
    if (html.includes('cloudfront://')) {
      tech.cdn.push('AWS CloudFront');
      if (!tech.hosting) {
        addDetection('hosting', 'AWS', 'medium', 'Cloudfront URL detected');
      }
    }
    if (html.includes('aws') && (html.includes('s3') || html.includes('ec2'))) {
      if (!tech.hosting) {
        addDetection('hosting', 'AWS', 'low', 'AWS S3/EC2 references detected');
      }
    }
    
    // Google Cloud
    if (scripts.some(s => s.includes('storage.googleapis.com') || s.includes('gstatic'))) {
      tech.cdn.push('Google Cloud');
      if (!tech.hosting) {
        addDetection('hosting', 'Google Cloud', 'low', 'Google Cloud storage detected');
      }
    }
    
    // Azure
    if (scripts.some(s => s.includes('azure') || s.includes('.blob.core.windows.net'))) {
      tech.cdn.push('Azure CDN');
      if (!tech.hosting) {
        addDetection('hosting', 'Azure', 'low', 'Azure blob storage detected');
      }
    }
    
    // AWS
    if (scripts.some(s => s.includes('amazonaws.com') || s.includes('cloudfront.net')) ||
        links.some(l => l.includes('amazonaws.com') || l.includes('cloudfront.net'))) {
      tech.cdn.push('AWS CloudFront');
      tech.hosting = 'AWS';
      tech.hostingConfidence = 'medium';
    }
    if (html.includes('aws') && (html.includes('s3') || html.includes('ec2'))) {
      tech.hosting = tech.hosting || 'AWS';
      tech.hostingConfidence = 'low';
    }
    
    // Google Cloud
    if (scripts.some(s => s.includes('storage.googleapis.com') || s.includes('gstatic'))) {
      tech.cdn.push('Google Cloud');
      tech.hosting = tech.hosting || 'Google Cloud';
      tech.hostingConfidence = 'low';
    }
    
    // Azure
    if (scripts.some(s => s.includes('azure') || s.includes('.blob.core.windows.net'))) {
      tech.cdn.push('Azure CDN');
      tech.hosting = tech.hosting || 'Azure';
      tech.hostingConfidence = 'low';
    }
    
    // Fastly
    if (html.includes('fastly') || scripts.some(s => s.includes('fastly'))) {
      tech.cdn.push('Fastly');
    }
    
    // Akamai
    if (scripts.some(s => s.includes('akamai') || s.includes('akamaized'))) {
      tech.cdn.push('Akamai');
    }
    
    // Other CDNs
    if (html.includes('cdnjs') || scripts.some(s => s.includes('cdnjs'))) {
      tech.cdn.push('CDNJS');
    }
    if (html.includes('jsdelivr') || scripts.some(s => s.includes('jsdelivr'))) {
      tech.cdn.push('jsDelivr');
    }
    if (scripts.some(s => s.includes('unpkg'))) {
      tech.cdn.push('unpkg');
    }
    if (scripts.some(s => s.includes('stackpath.bootstrapcdn'))) {
      tech.cdn.push('StackPath');
    }
    
    // ==========================================
    // BACKEND DETECTION (hints from page)
    // ==========================================
    
    // PHP indicators
    if (html.includes('.php') || cookies.includes('PHPSESSID')) {
      if (!tech.backend) {
        addDetection('backend', 'PHP', 'low', 'PHP session or files detected');
      }
    }
    
    // ASP.NET indicators
    if (html.includes('__VIEWSTATE') || cookies.includes('ASP.NET') || 
        cookies.includes('.AspNetCore.') || html.includes('.aspx')) {
      addDetection('backend', 'ASP.NET', 'medium', 'ASP.NET ViewState or session detected');
    }
    
    // Node.js indicators
    if (scripts.some(s => s.includes('/node_modules/')) || 
        cookies.includes('connect.sid') || cookies.includes('express')) {
      if (!tech.backend) {
        addDetection('backend', 'Node.js', 'low', 'Node.js/Express session detected');
      }
    }
    
    // Python/Django indicators
    if (cookies.includes('csrftoken') || cookies.includes('sessionid') ||
        html.includes('django') || html.includes('/static/')) {
      if (!tech.backend) {
        addDetection('backend', 'Python (Django)', 'low', 'Django session detected');
      }
    }
    
    // Ruby on Rails indicators
    if (cookies.includes('_session') || html.includes('rails') ||
        document.querySelector('meta[name="csrf-token"]')) {
      if (!tech.backend) {
        addDetection('backend', 'Ruby on Rails', 'low', 'Rails session or CSRF token detected');
      }
    }
    
    // Java indicators
    if (cookies.includes('JSESSIONID') || html.includes('java')) {
      if (!tech.backend) {
        addDetection('backend', 'Java', 'low', 'Java session detected');
      }
    }
    
    // Laravel indicators
    if (cookies.includes('laravel_session') || cookies.includes('XSRF-TOKEN')) {
      addDetection('backend', 'PHP (Laravel)', 'medium', 'Laravel session detected');
    }
    
    // ==========================================
    // SERVER DETECTION
    // ==========================================
    
    const generatorMeta = metas.find(m => m.name.toLowerCase() === 'generator');
    if (generatorMeta) {
      tech.server = generatorMeta.content;
      tech.indicators.push(`Generator: ${generatorMeta.content}`);
    }
    
    // ==========================================
    // PAGE BUILDERS
    // ==========================================
    
    if (html.includes('elementor') || document.querySelector('[class*="elementor"]') ||
        document.querySelector('[data-elementor-type]')) {
      tech.builders.push('Elementor');
    }
    if (html.includes('divi') || document.querySelector('[class*="et_pb"]')) {
      tech.builders.push('Divi');
    }
    if (html.includes('wpbakery') || document.querySelector('[class*="vc_"]') ||
        document.querySelector('[data-vc]')) {
      tech.builders.push('WPBakery');
    }
    if (html.includes('beaver-builder') || document.querySelector('[class*="fl-"]')) {
      tech.builders.push('Beaver Builder');
    }
    if (html.includes('bricks') || document.querySelector('[class*="bricks"]')) {
      tech.builders.push('Bricks');
    }
    if (html.includes('oxygen') || document.querySelector('[class*="ct-"]')) {
      tech.builders.push('Oxygen');
    }
    if (html.includes('genesis') || document.querySelector('[class*="genesis"]')) {
      tech.builders.push('Genesis');
    }
    if (html.includes('thrive') || document.querySelector('[class*="thrive"]')) {
      tech.builders.push('Thrive Architect');
    }
    if (html.includes('seedprod') || document.querySelector('[class*="seedprod"]')) {
      tech.builders.push('SeedProd');
    }
    
    // ==========================================
    // CLEANUP
    // ==========================================
    
    // Clean up empty arrays
    Object.keys(tech).forEach(key => {
      if (Array.isArray(tech[key]) && tech[key].length === 0) {
        tech[key] = null;
      }
    });
    
    // Remove confidence object if empty (use optional chaining since arrays may be null after cleanup)
    if ((!tech.confidence?.cms || tech.confidence.cms.length === 0) && 
        (!tech.confidence?.ecommerce || tech.confidence.ecommerce.length === 0) && 
        (!tech.confidence?.hosting || tech.confidence.hosting.length === 0) &&
        (!tech.confidence?.backend || tech.confidence.backend.length === 0)) {
      delete tech.confidence;
    }
    
return tech;
  });
}

/**
 * Analyze forms on the page for security and functionality
 * Enhanced with: cross-origin detection, file uploads, hidden fields, phone detection, autocomplete analysis
 */
async function analyzeForms(page) {
  return page.evaluate(() => {
    const forms = document.querySelectorAll('form');
    const results = {
      totalForms: forms.length,
      forms: [],
      issues: [],
      secureForms: 0,
      insecureForms: 0,
      crossOriginForms: 0,
      trustedCrossOriginForms: 0,
      untrustedCrossOriginForms: 0,
      fileUploadForms: 0,
      formsWithHiddenFields: 0,
      contactPage: null
    };
    
    const currentHost = window.location.hostname;
    const currentOrigin = window.location.origin;
    const knownSafeCrossOriginTargets = [
      /(^|\.)paypal\.com$/i,
      /(^|\.)stripe\.com$/i,
      /(^|\.)squareup\.com$/i,
      /(^|\.)square\.site$/i,
      /(^|\.)authorize\.net$/i,
      /(^|\.)braintreepayments\.com$/i,
      /(^|\.)formspree\.io$/i,
      /(^|\.)hubspot\.com$/i,
      /(^|\.)hsforms\.com$/i,
      /(^|\.)salesforce\.com$/i,
      /(^|\.)mailchimp\.com$/i,
      /(^|\.)constantcontact\.com$/i,
      /(^|\.)google\.com$/i,
    ];
    const benignPaymentMetadataFields = new Set([
      'card_exp_month',
      'card_exp_year',
      'business',
      'charset',
      'currency_code',
      'cmd',
      'amount',
      'item_name',
      'item_number',
    ]);
    const isLikelyFrameworkProtectedForm = (formInfo) => {
      const action = (formInfo.action || '').toLowerCase();
      const method = (formInfo.method || '').toUpperCase();

      if (method !== 'POST' || formInfo.isCrossOrigin) {
        return false;
      }

      if (
        action.includes('/cart/add') ||
        action.includes('/cart/update') ||
        action.includes('/cart/change') ||
        action.includes('/localization') ||
        action.includes('/contact#newsletterform') ||
        action.includes('/contact#contact_form') ||
        action.includes('/account') ||
        action.includes('/challenge')
      ) {
        return true;
      }

      const hiddenNames = new Set(
        (formInfo.hiddenFields || [])
          .map(field => (field.name || '').toLowerCase())
          .filter(Boolean)
      );

      return (
        hiddenNames.has('form_type') ||
        hiddenNames.has('utf8') ||
        hiddenNames.has('_method') ||
        hiddenNames.has('return_to')
      );
    };
    const isKnownPaymentProcessorForm = (formInfo) => {
      const action = (formInfo.action || '').toLowerCase();
      const hiddenNames = new Set(
        (formInfo.hiddenFields || [])
          .map(field => (field.name || '').toLowerCase())
          .filter(Boolean)
      );
      const hiddenValues = (formInfo.hiddenFields || [])
        .map(field => (field.valuePreview || '').toLowerCase())
        .join(' ');

      return (
        action.includes('paypal') ||
        action.includes('payment-mode=paypal') ||
        hiddenNames.has('give-gateway') ||
        hiddenNames.has('give_action') ||
        hiddenNames.has('give-form-hash') ||
        hiddenValues.includes('paypal-commerce')
      );
    };
    const hasStrongCsrfExpectation = (formInfo) => {
      if ((formInfo.method || '').toUpperCase() !== 'POST' || formInfo.isCrossOrigin) {
        return false;
      }

      const action = (formInfo.action || '').toLowerCase();
      const fieldNames = (formInfo.fields || [])
        .map(field => (field.name || '').toLowerCase())
        .filter(Boolean);
      const hiddenNames = new Set(
        (formInfo.hiddenFields || [])
          .map(field => (field.name || '').toLowerCase())
          .filter(Boolean)
      );
      const hiddenValues = (formInfo.hiddenFields || [])
        .map(field => `${field.name || ''} ${field.valuePreview || ''}`.toLowerCase())
        .join(' ');
      const statefulHiddenMarkers =
        hiddenNames.has('_method') ||
        hiddenNames.has('__viewstate') ||
        hiddenNames.has('__eventvalidation') ||
        hiddenNames.has('return_to') ||
        hiddenNames.has('form_type');
      const accountAction = /(login|signin|sign-in|account|profile|admin|dashboard|password|register|reset|portal|subscription)/i.test(action);
      const paymentAction = /(checkout|cart|billing|payment|donat|order)/i.test(action);
      const authFieldHints = fieldNames.some((name) => /(password|current_password|new_password|confirm_password|login|username|user_name)/i.test(name));
      const statefulFieldHints = fieldNames.some((name) => /(address_id|customer_id|account_id|subscription|plan|return_to|redirect_to)/i.test(name));
      const trustedPaymentWidgetHints =
        /payment-intent|setup-intent|client_secret|payment_method|hosted_fields|paypal|stripe|square|braintree|authorize\.net|klarna|affirm|afterpay/i.test(hiddenValues) ||
        fieldNames.some((name) => /(payment_method|paymentintent|setupintent|nonce|stripe|paypal|square|braintree|authorize|klarna|affirm|afterpay)/i.test(name));

      if (formInfo.hasPasswordField || formInfo.hasSsnField || formInfo.actionType === 'javascript') {
        return true;
      }

      if ((accountAction && (authFieldHints || statefulHiddenMarkers || statefulFieldHints)) || (authFieldHints && statefulHiddenMarkers)) {
        return true;
      }

      if (paymentAction && formInfo.hasCreditCardField && !trustedPaymentWidgetHints && statefulHiddenMarkers) {
        return true;
      }

      if (statefulHiddenMarkers && statefulFieldHints) {
        return true;
      }

      return false;
    };
    const isLikelyUserFacingContactForm = (formInfo) => {
      if (!formInfo) return false;
      if (formInfo.hasPasswordField || formInfo.hasCreditCardField || formInfo.hasSsnField) {
        return false;
      }
      if ((formInfo.method || '').toUpperCase() === 'GET' && !formInfo.hasEmailField && !formInfo.hasPhoneField) {
        return false;
      }
      const fieldNames = (formInfo.fields || [])
        .map((field) => `${field.type || ''} ${field.name || ''}`.toLowerCase())
        .join(' ');
      return (
        formInfo.hasEmailField ||
        formInfo.hasPhoneField ||
        /\b(?:message|subject|comment|textarea|contact|quote|estimate|service)\b/.test(fieldNames)
      );
    };
    const normalizeFormIssue = (issue, formInfo) => {
      if (
        issue === 'MEDIUM: POST form missing CSRF token' &&
        (isLikelyFrameworkProtectedForm(formInfo) || isKnownPaymentProcessorForm(formInfo))
      ) {
        return null;
      }

      if (
        issue === 'MEDIUM: POST form missing CSRF token' &&
        !hasStrongCsrfExpectation(formInfo)
      ) {
        return 'INFO: POST form has no visible CSRF token; authenticated state-changing context not verified';
      }

      return issue;
    };
    const absoluteUrl = (value) => {
      try {
        return new URL(value, window.location.href).toString();
      } catch {
        return null;
      }
    };
    const contactLinkCandidates = [];
    const addContactLinkCandidate = (href, text, score) => {
      const absolute = absoluteUrl(href);
      if (!absolute) return;
      let parsed;
      try {
        parsed = new URL(absolute);
      } catch {
        return;
      }
      const lowerText = String(text || '').toLowerCase();
      const lowerPath = parsed.pathname.toLowerCase();
      if (!/^https?:$/.test(parsed.protocol)) return;
      if (parsed.hostname !== currentHost) return;
      if (
        lowerPath === '/' ||
        /\/(faq|privacy|terms|policy|policies|search|account|login|signin|register|cart|checkout)\b/.test(lowerPath) ||
        /contact\/faq/.test(lowerPath)
      ) {
        return;
      }
      if (
        !/(contact|get in touch|get-in-touch|quote|estimate|consult|request service|request quote|contact us|contact-us|contactus)/.test(`${lowerText} ${lowerPath}`)
      ) {
        return;
      }
      contactLinkCandidates.push({
        url: absolute.split('?')[0].replace(/\/$/, ''),
        score,
      });
    };

    Array.from(document.querySelectorAll('a[href], button[onclick], [role="button"][onclick]')).forEach((node) => {
      const text = `${node.textContent || ''} ${node.getAttribute?.('aria-label') || ''} ${node.getAttribute?.('title') || ''}`.trim();
      const href = node.getAttribute?.('href') || node.getAttribute?.('onclick') || '';
      const lowerText = text.toLowerCase();
      const lowerHref = String(href).toLowerCase();
      let score = 0;
      if (/(contact us|contact|get in touch|get-in-touch)/.test(lowerText)) score += 5;
      if (/(request quote|quote|estimate|consult)/.test(lowerText)) score += 3;
      if (/(contact|contact-us|contactus|get-in-touch|quote|estimate|consult)/.test(lowerHref)) score += 4;
      if (score > 0) {
        addContactLinkCandidate(href, text, score);
      }
    });
    
    forms.forEach((form, index) => {
      const formInfo = {
        index: index + 1,
        action: form.action || form.getAttribute('action') || 'none',
        actionType: 'url', // 'url', 'javascript', 'cross-origin', 'none'
        method: (form.method || 'get').toUpperCase(),
        hasPasswordField: !!form.querySelector('input[type="password"]'),
        hasEmailField: !!form.querySelector('input[type="email"]'),
        hasPhoneField: !!(form.querySelector('input[type="tel"]') ||
                          form.querySelector('input[name*="phone"]') ||
                          form.querySelector('input[name*="mobile"]') ||
                          form.querySelector('input[name*="cell"]') ||
                          form.querySelector('input[name*="fax"]')),
        hasCreditCardField: !!(form.querySelector('input[name*="card"]') || 
                               form.querySelector('input[name*="credit"]') ||
                               form.querySelector('input[name*="cc-"]') ||
                               form.querySelector('input[name*="ccnum"]') ||
                               form.querySelector('input[name*="cardnumber"]') ||
                               form.querySelector('input[autocomplete*="cc-"]')),
        hasSsnField: !!(form.querySelector('input[name*="ssn"]') ||
                        form.querySelector('input[name*="social-security"]') ||
                        form.querySelector('input[name*="social_security"]')),
        hasFileUpload: false,
        fileUploadFields: [],
        hiddenFields: [],
        suspiciousHiddenFields: [],
        fieldsMissingAutocompleteOff: [],
        fields: [],
        hasCaptcha: false,
        hasCSRFToken: false,
        isCrossOrigin: false,
        crossOriginTrusted: false,
        isJavaScriptAction: false,
        isSecureAction: window.location.protocol === 'https:',
        crossOriginTarget: null,
        issues: []
      };
      
      // Check action URL security and type
      if (formInfo.action && formInfo.action !== 'none' && typeof formInfo.action === 'string') {
        const actionLower = formInfo.action.toLowerCase().trim();
        
        // Check for javascript: action
        if (actionLower.startsWith('javascript:')) {
          formInfo.isJavaScriptAction = true;
          formInfo.actionType = 'javascript';
          formInfo.issues.push('HIGH: Form uses javascript: action - potential XSS vector');
        } else {
          try {
            const actionUrl = new URL(formInfo.action, window.location.href);
            formInfo.isSecureAction = actionUrl.protocol === 'https:';
            
            // Check for cross-origin submission
            if (actionUrl.hostname !== currentHost) {
              formInfo.isCrossOrigin = true;
              formInfo.crossOriginTarget = actionUrl.origin;
              formInfo.actionType = 'cross-origin';
              formInfo.crossOriginTrusted = knownSafeCrossOriginTargets.some((pattern) => pattern.test(actionUrl.hostname));
              if (formInfo.crossOriginTrusted) {
                formInfo.issues.push(`INFO: Form submits to known third-party service: ${actionUrl.hostname}`);
                results.trustedCrossOriginForms++;
              } else {
                formInfo.issues.push(`HIGH: Form submits to non-allowlisted cross-origin domain: ${actionUrl.hostname}`);
                results.untrustedCrossOriginForms++;
              }
              results.crossOriginForms++;
            }
            
            if (!formInfo.isSecureAction && !formInfo.isCrossOrigin) {
              formInfo.issues.push('Form submits to insecure HTTP endpoint');
            }
          } catch (e) {
            formInfo.issues.push('Invalid form action URL');
          }
        }
      }
      
      // Collect input fields and analyze them
      const inputs = form.querySelectorAll('input, textarea, select');
      inputs.forEach(input => {
        const inputType = (input.type || input.tagName.toLowerCase()).toLowerCase();
        const inputName = (input.name || '').toLowerCase();
        const inputValue = input.value || '';
        
        const field = {
          type: inputType,
          name: input.name || '',
          required: input.required,
          autocomplete: input.autocomplete || null
        };
        formInfo.fields.push(field);
        
        // File upload detection
        if (inputType === 'file') {
          formInfo.hasFileUpload = true;
          const uploadInfo = {
            name: input.name || 'unnamed',
            accept: input.accept || null,
            multiple: input.multiple
          };
          formInfo.fileUploadFields.push(uploadInfo);
          
          // Check for file type restrictions
          if (!input.accept) {
            formInfo.issues.push('MEDIUM: File upload field has no type restrictions (accept attribute missing)');
          }
        }
        
        // Hidden field analysis
        if (inputType === 'hidden') {
          const hiddenField = {
            name: input.name || 'unnamed',
            valuePreview: inputValue.substring(0, 100)
          };
          formInfo.hiddenFields.push(hiddenField);

          if (
            benignPaymentMetadataFields.has(inputName) ||
            (inputName === 'business' && formInfo.action.toLowerCase().includes('paypal'))
          ) {
            return;
          }
          
          // Detect suspicious hidden fields
          const suspiciousPatterns = [
            { pattern: 'email', reason: 'Hidden field contains email-like value' },
            { pattern: 'password', reason: 'Hidden field with password in name' },
            { pattern: 'token', reason: 'Token exposed in hidden field' },
            { pattern: 'secret', reason: 'Secret exposed in hidden field' },
            { pattern: 'api_key', reason: 'API key in hidden field' },
            { pattern: 'apikey', reason: 'API key in hidden field' },
            { pattern: 'private', reason: 'Private data in hidden field' },
            { pattern: 'credit', reason: 'Credit-related hidden field' },
            { pattern: 'card', reason: 'Card-related hidden field' },
            { pattern: 'ssn', reason: 'SSN-related hidden field' },
            { pattern: 'social', reason: 'Social security related hidden field' },
            { pattern: /@\S+\.\S+/, reason: 'Hidden field contains email address' }
          ];
          
          for (const pat of suspiciousPatterns) {
            const isMatch = typeof pat.pattern === 'string' 
              ? (inputName.includes(pat.pattern) || inputValue.toLowerCase().includes(pat.pattern))
              : pat.pattern.test(inputValue);
            if (isMatch) {
              formInfo.suspiciousHiddenFields.push({
                name: input.name,
                reason: pat.reason
              });
              formInfo.issues.push(`HIGH: ${pat.reason} (field: ${input.name})`);
              break;
            }
          }
        }
        
        // Autocomplete analysis on sensitive fields
        if (['password', 'email', 'tel', 'cc-number', 'cc-csc', 'cc-exp'].includes(inputType) ||
            inputName.includes('password') || inputName.includes('credit') || 
            inputName.includes('card') || inputName.includes('ssn')) {
          if (input.autocomplete !== 'off' && input.autocomplete !== 'new-password') {
            formInfo.fieldsMissingAutocompleteOff.push({
              name: input.name || inputType,
              type: inputType
            });
          }
        }
      });
      
      // Flag if has suspicious hidden fields
      if (formInfo.suspiciousHiddenFields.length > 0) {
        results.formsWithHiddenFields++;
      }
      
      // Flag file upload forms
      if (formInfo.hasFileUpload) {
        results.fileUploadForms++;
      }
      
      // Check enctype for file uploads
      if (formInfo.hasFileUpload) {
        const enctype = form.enctype || form.getAttribute('enctype');
        if (!enctype || !enctype.includes('multipart/form-data')) {
          formInfo.issues.push('MEDIUM: File upload form missing multipart/form-data enctype');
        }
      }
      
      // Check for CSRF protection
      const csrfFields = form.querySelectorAll('input[name*="csrf"], input[name*="token"], input[name*="_token"], input[name*="nonce"], input[name*="hash"]');
      if (csrfFields.length > 0) {
        formInfo.hasCSRFToken = true;
      } else if (formInfo.method === 'POST' && !formInfo.isCrossOrigin) {
        formInfo.issues.push('MEDIUM: POST form missing CSRF token');
      }
      
      // Check for CAPTCHA
      const captchaIndicators = form.innerHTML.toLowerCase();
      if (captchaIndicators.includes('g-recaptcha') || 
          captchaIndicators.includes('h-captcha') ||
          captchaIndicators.includes('cf-turnstile') ||
          captchaIndicators.includes('turnstile') ||
          form.querySelector('[class*="captcha"]') ||
          form.querySelector('[data-sitekey]')) {
        formInfo.hasCaptcha = true;
      }
      
      // Security assessments
      if (formInfo.hasPasswordField && !formInfo.isSecureAction) {
        formInfo.issues.push('CRITICAL: Password form submits over HTTP');
      }
      if (formInfo.hasCreditCardField && !formInfo.isSecureAction) {
        formInfo.issues.push('CRITICAL: Credit card form submits over HTTP');
      }
      if (formInfo.hasSsnField && !formInfo.isSecureAction) {
        formInfo.issues.push('CRITICAL: SSN form submits over HTTP');
      }
      if (formInfo.hasEmailField && !formInfo.isSecureAction) {
        formInfo.issues.push('Email form submits over HTTP');
      }
      
      // Cross-origin with sensitive data
      if (formInfo.isCrossOrigin && !formInfo.crossOriginTrusted && (formInfo.hasPasswordField || formInfo.hasCreditCardField || formInfo.hasSsnField)) {
        formInfo.issues.push('CRITICAL: Sensitive data submitted to non-allowlisted cross-origin domain');
      }
      
      results.forms.push(formInfo);
      
      if (formInfo.issues.some(i => i.includes('CRITICAL') || i.includes('HIGH'))) {
        results.insecureForms++;
      } else {
        results.secureForms++;
      }
      
      for (const issue of formInfo.issues) {
        const normalizedIssue = normalizeFormIssue(issue, formInfo);
        if (!normalizedIssue) {
          continue;
        }
        results.issues.push(`Form ${index + 1}: ${normalizedIssue}`);
      }
    });

    if (contactLinkCandidates.length > 0) {
      contactLinkCandidates.sort((a, b) => b.score - a.score || a.url.length - b.url.length);
      results.contactPage = contactLinkCandidates[0].url;
    } else {
      const likelyContactForm = results.forms.find((formInfo) => isLikelyUserFacingContactForm(formInfo));
      if (likelyContactForm) {
        results.contactPage = window.location.href.split('?')[0].replace(/\/$/, '');
      }
    }
    
    return results;
  });
}

/**
 * Inventory third-party scripts loaded on the page
 */
async function inventoryThirdPartyScripts(page) {
  return page.evaluate(() => {
    const scripts = document.querySelectorAll('script[src]');
    const results = {
      total: scripts.length,
      firstParty: [],
      thirdParty: [],
      categories: {
        analytics: [],
        advertising: [],
        social: [],
        chat: [],
        video: [],
        payment: [],
        cdn: [],
        other: []
      },
      trackers: [],
      potentialRisks: []
    };
    
    // Known script patterns
    const knownPatterns = {
      analytics: [
        { pattern: 'google-analytics', name: 'Google Analytics' },
        { pattern: 'googletagmanager', name: 'Google Tag Manager' },
        { pattern: 'hotjar', name: 'Hotjar' },
        { pattern: 'mixpanel', name: 'Mixpanel' },
        { pattern: 'segment.com', name: 'Segment' },
        { pattern: 'heap.io', name: 'Heap' },
        { pattern: 'amplitude', name: 'Amplitude' },
        { pattern: 'plausible', name: 'Plausible' },
        { pattern: 'matomo', name: 'Matomo' },
        { pattern: 'newrelic', name: 'New Relic' },
        { pattern: 'sentry.io', name: 'Sentry' },
        { pattern: 'rollbar', name: 'Rollbar' },
        { pattern: 'bugsnag', name: 'Bugsnag' }
      ],
      advertising: [
        { pattern: 'doubleclick', name: 'DoubleClick' },
        { pattern: 'googlesyndication', name: 'Google AdSense' },
        { pattern: 'facebook.net', name: 'Facebook SDK' },
        { pattern: 'connect.facebook', name: 'Facebook Connect' },
        { pattern: 'adsrvr', name: 'AdServer' },
        { pattern: 'criteo', name: 'Criteo' },
        { pattern: 'outbrain', name: 'Outbrain' },
        { pattern: 'taboola', name: 'Taboola' },
        { pattern: 'adroll', name: 'AdRoll' }
      ],
      social: [
        { pattern: 'platform.twitter', name: 'Twitter Widgets' },
        { pattern: 'instagram', name: 'Instagram Embed' },
        { pattern: 'linkedin.com/share', name: 'LinkedIn Share' },
        { pattern: 'pinterest', name: 'Pinterest' },
        { pattern: 'addthis', name: 'AddThis' },
        { pattern: 'sharethis', name: 'ShareThis' }
      ],
      chat: [
        { pattern: 'intercom', name: 'Intercom' },
        { pattern: 'zendesk', name: 'Zendesk' },
        { pattern: 'crisp.chat', name: 'Crisp' },
        { pattern: 'drift.com', name: 'Drift' },
        { pattern: 'hubspot', name: 'HubSpot Chat' },
        { pattern: 'livechatinc', name: 'LiveChat' },
        { pattern: 'tidio', name: 'Tidio' },
        { pattern: 'tawk.to', name: 'Tawk.to' },
        { pattern: 'freshchat', name: 'Freshchat' },
        { pattern: 'messenger.com', name: 'Facebook Messenger' },
        { pattern: 'zopim', name: 'Zopim (Zendesk)' }
      ],
      video: [
        { pattern: 'youtube.com/iframe_api', name: 'YouTube' },
        { pattern: 'player.vimeo', name: 'Vimeo' },
        { pattern: 'wistia', name: 'Wistia' },
        { pattern: 'brightcove', name: 'Brightcove' },
        { pattern: 'vidyard', name: 'Vidyard' }
      ],
      payment: [
        { pattern: 'stripe.com', name: 'Stripe' },
        { pattern: 'paypal.com', name: 'PayPal' },
        { pattern: 'square.com', name: 'Square' },
        { pattern: 'braintree', name: 'Braintree' },
        { pattern: 'authorize.net', name: 'Authorize.net' }
      ],
      cdn: [
        { pattern: 'cloudflare.com', name: 'Cloudflare' },
        { pattern: 'cdnjs', name: 'CDNJS' },
        { pattern: 'jsdelivr', name: 'jsDelivr' },
        { pattern: 'unpkg.com', name: 'unpkg' },
        { pattern: 'stackpath.bootstrapcdn', name: 'StackPath Bootstrap' }
      ]
    };
    
    const currentHost = window.location.hostname;
    
    scripts.forEach(script => {
      const src = script.src;
      let url;
      try {
        url = new URL(src);
      } catch (e) {
        return; // Invalid URL, skip
      }
      
      const scriptInfo = {
        src: src,
        domain: url.hostname,
        async: script.async,
        defer: script.defer
      };
      
      // Determine first vs third party
      if (url.hostname === currentHost || url.hostname.endsWith('.' + currentHost)) {
        results.firstParty.push(scriptInfo);
      } else {
        results.thirdParty.push(scriptInfo);
        
        // Categorize
        let categorized = false;
        for (const [category, patterns] of Object.entries(knownPatterns)) {
          for (const { pattern, name } of patterns) {
            if (src.toLowerCase().includes(pattern)) {
              results.categories[category].push({ ...scriptInfo, name });
              categorized = true;
              break;
            }
          }
          if (categorized) break;
        }
        
        if (!categorized) {
          results.categories.other.push(scriptInfo);
        }
      }
    });
    
    // Identify trackers (combining analytics and advertising)
    results.trackers = [
      ...results.categories.analytics.map(s => s.name || s.domain),
      ...results.categories.advertising.map(s => s.name || s.domain)
    ];
    
    // Remove duplicates
    results.trackers = [...new Set(results.trackers)];
    
    // Identify potential risks
    if (results.categories.advertising.length > 5) {
      results.potentialRisks.push('High number of advertising scripts may impact performance and privacy');
    }
    if (results.categories.analytics.length > 3) {
      results.potentialRisks.push('Multiple analytics tools may cause redundant tracking');
    }
    if (results.thirdParty.length > 20) {
      results.potentialRisks.push('High number of third-party scripts may impact page load speed');
    }
    if (results.categories.chat.length > 1) {
      results.potentialRisks.push('Multiple chat widgets detected');
    }
    
    // Clean up empty categories
    Object.keys(results.categories).forEach(key => {
      if (results.categories[key].length === 0) {
        delete results.categories[key];
      }
    });
    
    return results;
  });
}

/**
 * Get DNS records (MX, NS, A) for the domain
 */
async function getDnsRecords(hostname) {
  const dns = require("dns").promises;
  const results = { mx: [], ns: [], a: [] };
  
  // MX records
  try {
    const mxRecords = await dns.resolveMx(hostname).catch(() => []);
    results.mx = mxRecords.map(r => ({ priority: r.priority, exchange: r.exchange }));
  } catch (e) {
    results.mx = [];
  }
  
  // NS records
  try {
    const nsRecords = await dns.resolveNs(hostname).catch(() => []);
    results.ns = nsRecords;
  } catch (e) {
    results.ns = [];
  }
  
  // A records
  try {
    const aRecords = await dns.resolve4(hostname).catch(() => []);
    results.a = aRecords;
  } catch (e) {
    results.a = [];
  }
  
  return results;
}

/**
 * Probe for common admin endpoints (parallel HTTP requests)
 */
async function probeAdminEndpoints(page, baseUrl) {
  const endpoints = [
    "/admin",
    "/administrator",
    "/wp-admin",
    "/wp-login.php",
    "/login",
    "/user/login",
    "/signin",
    "/dashboard",
    "/manage",
    "/controlpanel",
    "/backend",
    "/api/admin",
    "/admin.php",
  ];
  
  const found = [];
  const https = require('https');
  const http = require('http');
  
  // Use HTTP HEAD requests in parallel for speed
  const checkEndpoint = (endpoint) => new Promise((resolve) => {
    const urlStr = `${baseUrl}${endpoint}`;
    let parsed;
    try {
      parsed = new URL(urlStr);
    } catch (e) {
      resolve(null);
      return;
    }
    const client = parsed.protocol === 'https:' ? https : http;
    
    const req = client.request({
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method: 'HEAD',
      timeout: 3000,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
      }
    }, (res) => {
      resolve({ endpoint, status: res.statusCode, headers: res.headers });
    });
    
    req.on('error', () => resolve(null));
    req.on('timeout', () => { req.destroy(); resolve(null); });
    req.end();
  });
  
  // Check all endpoints in parallel
  const results = await Promise.all(endpoints.map(checkEndpoint));
  
  for (const result of results) {
    if (result && result.status !== 404) {
      const accessState =
        result.status >= 200 && result.status < 300 ? "responds" :
        result.status >= 300 && result.status < 400 ? "redirects" :
        result.status === 401 || result.status === 403 ? "protected" :
        "observed";
      found.push({
        path: result.endpoint,
        status: result.status,
        accessible: result.status < 400,
        accessState,
        verified: false, // Not verified via browser
      });
    }
  }
  
  return found;
}

/**
 * Detect tech stack from page content
 */
function detectTechStack(pageContent, headers) {
  const detected = { cms: null, frameworks: [], analytics: [], hosting: [] };
  
  // Check CMS
  for (const [name, patterns] of Object.entries(TECH_SIGNATURES.cms)) {
    for (const pattern of patterns) {
      if (pattern.test(pageContent)) {
        detected.cms = name;
        break;
      }
    }
    if (detected.cms) break;
  }
  
  // Check frameworks
  for (const [name, patterns] of Object.entries(TECH_SIGNATURES.frameworks)) {
    for (const pattern of patterns) {
      if (pattern.test(pageContent)) {
        if (!detected.frameworks.includes(name)) {
          detected.frameworks.push(name);
        }
      }
    }
  }
  
  // Check analytics
  for (const [name, patterns] of Object.entries(TECH_SIGNATURES.analytics)) {
    for (const pattern of patterns) {
      if (pattern.test(pageContent)) {
        if (!detected.analytics.includes(name)) {
          detected.analytics.push(name);
        }
      }
    }
  }
  
  // Check hosting from headers
  const serverHeader = headers["server"] || "";
  const viaHeader = headers["via"] || "";
  const cfRay = headers["cf-ray"];
  const headerStr = `${serverHeader} ${viaHeader} ${cfRay || ""}`.toLowerCase();
  
  for (const [name, patterns] of Object.entries(TECH_SIGNATURES.hosting)) {
    for (const pattern of patterns) {
      if (pattern.test(headerStr) || pattern.test(pageContent)) {
        if (!detected.hosting.includes(name)) {
          detected.hosting.push(name);
        }
      }
    }
  }
  
  return detected;
}

/**
 * Calculate audit score based on findings
 */
function calculateAuditScore(result) {
  let score = 100;
  
  // SSL issues (-25 for invalid or missing)
  if (!result.ssl.valid) {
    score -= 30;
    result.criticalIssues.push("TLS certificate validation failed");
  } else if (result.ssl.daysUntilExpiry !== null && result.ssl.daysUntilExpiry < 30) {
    score -= 8;
    result.warnings.push(`SSL certificate expires in ${result.ssl.daysUntilExpiry} days`);
  }
  
  // HTTPS redirect (-8 if no redirect)
  if (result.https.redirects === false) {
    score -= 8;
    result.warnings.push("HTTP does not redirect to HTTPS");
  }
  
  // Security headers: keep conservative and skip deprecated X-XSS-Protection
  for (const [header, status] of Object.entries(result.securityHeaders)) {
    if (status.present === false && header !== "x-xss-protection") {
      const severity = getMissingHeaderSeverity(header, result);
      if (severity === "warning") {
        if (header === "strict-transport-security") score -= 6;
        else if (header === "content-security-policy") score -= 4;
        else if (header === "x-frame-options" || header === "x-content-type-options") score -= 3;
        else score -= 1;
      } else {
        score -= 1;
      }
    }
  }
  
  // Mixed content (-10)
  if (result.mixedContent?.found) {
    score -= 10;
    result.warnings.push(`Mixed content: ${result.mixedContent.resources?.length || 0} HTTP resources on HTTPS page`);
  }

  // Missing email auth matters more when the domain actually appears to send mail
  const hasMailSurface = (result.dnsRecords?.mx?.length || 0) > 0 ||
    (result.contacts?.emails || []).some((email) => String(email).toLowerCase().endsWith(`@${result.domain}`));
  if (hasMailSurface && !result.emailAuth.spf) {
    score -= 4;
    result.warnings.push("Missing SPF record");
  }
  if (hasMailSurface && !result.emailAuth.dmarc) {
    score -= 4;
    result.warnings.push("Missing DMARC record");
  }
  
  // Sensitive exposures (CRITICAL)
  if (result.sensitiveExposures) {
    const riskyEndpoints = result.sensitiveExposures.riskyEndpoints || [];
    const apiKeys = result.sensitiveExposures.apiKeys || [];
    
    // Critical exposures (git, env, config)
    if (result.sensitiveExposures.exposedGit) {
      score -= 30;
      result.criticalIssues.push("Exposed .git directory");
    }
    if (result.sensitiveExposures.exposedEnv) {
      score -= 30;
      result.criticalIssues.push("Exposed .env file");
    }
    if (result.sensitiveExposures.exposedConfig) {
      score -= 30;
      result.criticalIssues.push("Exposed config file");
    }
    
    // Other risky endpoints
    const criticalEndpoints = riskyEndpoints.filter(e => e.severity === "critical" && !e.reportOnly);
    const highEndpoints = riskyEndpoints.filter(e => e.severity === "high");
    const mediumEndpoints = riskyEndpoints.filter(e => e.severity === "medium");
    
    if (criticalEndpoints.length > 0) {
      score -= Math.min(30, 20 * criticalEndpoints.length);
      result.criticalIssues.push(`${criticalEndpoints.length} critical endpoint(s) exposed: ${criticalEndpoints.map(e => e.path).join(", ")}`);
    }
    if (highEndpoints.length > 0) {
      score -= Math.min(20, 10 * highEndpoints.length);
      result.warnings.push(`${highEndpoints.length} high-severity endpoint(s) exposed: ${highEndpoints.map(e => e.path).join(", ")}`);
    }
    if (mediumEndpoints.length > 0) {
      score -= Math.min(8, 4 * mediumEndpoints.length);
      result.warnings.push(`${mediumEndpoints.length} medium-severity endpoint(s) exposed`);
    }
    
    // API keys in page source
    const criticalKeys = apiKeys.filter(k => k.severity === "critical");
    const highKeys = apiKeys.filter(k => k.severity === "high");
    
    if (criticalKeys.length > 0) {
      score -= 20;
      result.criticalIssues.push(`${criticalKeys.length} exposed API key(s) in page source: ${criticalKeys.map(k => k.type).join(", ")}`);
    }
    if (highKeys.length > 0) {
      score -= 8;
      result.warnings.push(`${highKeys.length} exposed key(s) in page source: ${highKeys.map(k => k.type).join(", ")}`);
    }
  }

  // Form security: only score concrete risky transport/exposure cases
  const formIssues = result.forms?.issues || [];
  const criticalFormIssues = formIssues.filter((issue) =>
    /CRITICAL: (Password|Credit card|SSN).*HTTP/i.test(issue) ||
    /Sensitive data submitted to non-allowlisted cross-origin domain/i.test(issue)
  );
  if (criticalFormIssues.length > 0) {
    score -= Math.min(25, 12 * criticalFormIssues.length);
    result.criticalIssues.push(...criticalFormIssues);
  }

  const cookieFindings = result.cookieSecurity?.findings || [];
  const criticalCookieFindings = cookieFindings.filter((finding) => finding.severity === "critical");
  const warningCookieFindings = cookieFindings.filter((finding) => finding.severity === "warning");
  if (criticalCookieFindings.length > 0) {
    score -= Math.min(18, 8 * criticalCookieFindings.length);
    result.criticalIssues.push(...criticalCookieFindings.map((finding) => finding.message));
  }
  if (warningCookieFindings.length > 0) {
    score -= Math.min(10, 4 * warningCookieFindings.length);
    result.warnings.push(...warningCookieFindings.map((finding) => finding.message));
  }
  
  // Ensure score is 0-100
  result.auditScore = Math.max(0, Math.min(100, score));
  
  return result.auditScore;
}

/**
 * Generate profile markdown section
 */
function generateProfileSection(result) {
  const lines = [];
  const tierLabels = [
    ["verified", "Verified"],
    ["probable", "Probable"],
    ["observedUnderInstrumentation", "Observed Under Instrumentation"],
    ["unverified", "Unverified"],
  ];
  
  lines.push(`## Technical Audit (${new Date().toISOString().split("T")[0]})`);
  lines.push("");
  lines.push(`**Audit Score: ${result.auditScore}/100**`);
  lines.push("");

  if (result.findingConfidence) {
    lines.push("### Finding Confidence");
    for (const [key, label] of tierLabels) {
      const items = result.findingConfidence[key] || [];
      lines.push(`- **${label}:** ${items.length}`);
    }
    lines.push("");
  }

  const reviewQueue = result.enrichment?.securityAutofill?.reviewQueue || [];
  if (reviewQueue.length > 0) {
    lines.push("### Review Queue Highlights");
    lines.push(`- **Review Items:** ${reviewQueue.length}`);
    for (const line of buildReviewQueueHighlights(reviewQueue)) {
      lines.push(line);
    }

    lines.push("");
  }
  
  // SSL/TLS
  lines.push("### SSL/TLS Certificate");
  if (result.ssl.valid) {
    lines.push(`- **Status:** Valid`);
    lines.push(`- **Issuer:** ${result.ssl.issuer}`);
    lines.push(`- **Expires:** ${result.ssl.expires ? new Date(result.ssl.expires).toLocaleDateString() : "Unknown"}`);
    lines.push(`- **Days Until Expiry:** ${result.ssl.daysUntilExpiry}`);
  } else {
    lines.push(`- **Status:** Invalid or Missing`);
    lines.push(`- **Error:** ${result.ssl.error || "Could not verify certificate"}`);
  }
  lines.push("");
  
  // HTTPS
  lines.push("### HTTPS Configuration");
  lines.push(`- **HTTPS Enabled:** ${result.https.enabled ? "Yes" : "No"}`);
  lines.push(`- **HTTP Redirects to HTTPS:** ${result.https.redirects === null ? "Unverified" : result.https.redirects ? "Yes" : "No"}`);
  lines.push("");
  
  // Security Headers
  lines.push("### Security Headers");
  for (const [header, status] of Object.entries(result.securityHeaders)) {
    const icon = status.present ? "✓" : "✗";
    const desc = SECURITY_HEADERS[header]?.description || "";
    lines.push(`- ${icon} **${header}:** ${status.present ? "Present" : "Missing"} — ${desc}`);
  }
  lines.push("");
  
  // Cookies
  if (result.cookies && result.cookies.length > 0) {
    lines.push("### Cookies");
    for (const cookie of result.cookies) {
      const flags = [];
      if (cookie.secure) flags.push("Secure");
      if (cookie.httpOnly) flags.push("HttpOnly");
      if (cookie.sameSite) flags.push(`SameSite=${cookie.sameSite}`);
      lines.push(`- **${cookie.name}:** ${flags.length > 0 ? flags.join(", ") : "No security flags"}`);
    }
    lines.push("");
  }

  if (result.cookieSecurity?.findings?.length > 0) {
    lines.push("### Cookie Security");
    lines.push(`- **Session-like Cookies:** ${(result.cookieSecurity.sessionCookies || []).length}`);
    lines.push(`- **Auth-like Cookies:** ${(result.cookieSecurity.authCookies || []).length}`);
    for (const finding of result.cookieSecurity.findings.slice(0, 8)) {
      lines.push(`- [${finding.severity.toUpperCase()}] ${finding.message}`);
    }
    lines.push("");
  }
  
  // Mixed Content
  if (result.mixedContent && result.mixedContent.found && result.mixedContent.resources) {
    lines.push("### Mixed Content (HTTP on HTTPS)");
    lines.push(`- **Found:** ${result.mixedContent.resources.length} insecure resources`);
    for (const resource of result.mixedContent.resources.slice(0, 5)) {
      lines.push(`  - ${resource}`);
    }
    if (result.mixedContent.resources.length > 5) {
      lines.push(`  - ... and ${result.mixedContent.resources.length - 5} more`);
    }
    lines.push("");
  }
  
  // Tech Stack
  lines.push("### Technology Stack");
  const cmsDisplay = result.techStack.cms || "Not detected";
  const cmsConfidence = result.techStack.cmsConfidence ? ` (${result.techStack.cmsConfidence} confidence)` : "";
  lines.push(`- **CMS:** ${cmsDisplay}${cmsConfidence}`);

  if (result.techStack.ecommerce) {
    const ecomConfidence = result.techStack.ecommerceConfidence ? ` (${result.techStack.ecommerceConfidence} confidence)` : "";
    lines.push(`- **E-Commerce:** ${result.techStack.ecommerce}${ecomConfidence}`);
  }

  if (result.techStack.frameworks && result.techStack.frameworks.length > 0) {
    lines.push(`- **Frameworks:** ${result.techStack.frameworks.join(", ")}`);
  }

  if (result.techStack.backend) {
    const backendConfidence = result.techStack.backendConfidence ? ` (${result.techStack.backendConfidence} confidence)` : "";
    lines.push(`- **Backend:** ${result.techStack.backend}${backendConfidence}`);
  }

  if (result.techStack.hosting) {
    const hostingConfidence = result.techStack.hostingConfidence ? ` (${result.techStack.hostingConfidence} confidence)` : "";
    lines.push(`- **Hosting:** ${result.techStack.hosting}${hostingConfidence}`);
  }

  if (result.techStack.cdn && result.techStack.cdn.length > 0) {
    lines.push(`- **CDN:** ${result.techStack.cdn.join(", ")}`);
  }

  if (result.techStack.analytics && result.techStack.analytics.length > 0) {
    lines.push(`- **Analytics:** ${result.techStack.analytics.join(", ")}`);
  }

  if (result.techStack.builders && result.techStack.builders.length > 0) {
    lines.push(`- **Page Builders:** ${result.techStack.builders.join(", ")}`);
  }

  if (result.techStack.indicators && result.techStack.indicators.length > 0 && result.techStack.indicators.length <= 5) {
    lines.push(`- **Detection Indicators:** ${result.techStack.indicators.slice(0, 5).join("; ")}`);
  }
  lines.push("");
  
  // Performance
  lines.push("### Performance");
  lines.push(`- **Page Load Time:** ${result.performance.loadTime ? `${result.performance.loadTime}ms` : "Not measured"}`);
  lines.push(`- **DOM Content Loaded:** ${result.performance.domContentLoaded ? `${result.performance.domContentLoaded}ms` : "Not measured"}`);
  lines.push(`- **First Paint:** ${result.performance.firstPaint ? `${result.performance.firstPaint.toFixed(0)}ms` : "Not measured"}`);
  lines.push(`- **First Contentful Paint:** ${result.performance.firstContentfulPaint ? `${result.performance.firstContentfulPaint.toFixed(0)}ms` : "Not measured"}`);
  lines.push(`- **Largest Contentful Paint (LCP):** ${result.performance.largestContentfulPaint ? `${result.performance.largestContentfulPaint.toFixed(0)}ms` : "Not measured"}`);
  lines.push(`- **Cumulative Layout Shift (CLS):** ${result.performance.cumulativeLayoutShift !== null ? result.performance.cumulativeLayoutShift.toFixed(3) : "Not measured"}`);
  lines.push(`- **Interaction to Next Paint (INP):** ${result.performance.interactionToNextPaint ? `${result.performance.interactionToNextPaint.toFixed(0)}ms` : "Not measured"}`);
  lines.push("");
  
  // SEO
  lines.push("### SEO Basics");
  lines.push(`- **Title:** ${result.seo.title || "Missing"}`);
  lines.push(`- **Meta Description:** ${result.seo.metaDescription ? "Present" : "Missing"}`);
  lines.push(`- **H1 Count:** ${result.seo.h1Count}`);
  lines.push(`- **Images:** ${result.seo.images} (${result.seo.imagesWithoutAlt} without alt text)`);
  lines.push(`- **Canonical URL:** ${result.seo.canonical || "Not set"}`);
  lines.push("");
  
  // Mobile
  lines.push("### Mobile");
  lines.push(`- **Mobile-Friendly:** ${result.mobile.friendly ? "Yes" : "No"}`);
  lines.push(`- **Viewport Meta Tag:** ${result.mobile.viewport || "Missing"}`);
  lines.push("");
  
  // Forms
  lines.push("### Forms");
  if (result.forms && result.forms.found) {
    lines.push(`- **Forms Found:** ${result.forms.forms ? result.forms.forms.length : 0}`);
    if (result.forms.forms) {
      for (const form of result.forms.forms) {
        lines.push(`  - ${form.action || "No action"} (${form.method || "unknown method"}) — Fields: ${(form.fields || []).join(", ") || "none detected"}`);
      }
    }
    if (result.forms.contactPage) {
      lines.push(`- **Contact Page:** ${result.forms.contactPage}`);
    }
  } else {
    lines.push("- **No forms detected**");
  }
  lines.push("");
  
  // Broken Images
  if (result.brokenImages && result.brokenImages.length > 0) {
    lines.push("### Broken Images");
    for (const img of result.brokenImages.slice(0, 5)) {
      lines.push(`- ${img}`);
    }
    if (result.brokenImages.length > 5) {
      lines.push(`- ... and ${result.brokenImages.length - 5} more`);
    }
    lines.push("");
  }
  
  // Admin Endpoints
  if (result.adminEndpoints && result.adminEndpoints.found && result.adminEndpoints.found.length > 0) {
    lines.push("### Observed Admin/Login Routes");
    for (const ep of result.adminEndpoints.found) {
      lines.push(`- **${ep.path}:** ${ep.status} (${ep.accessState || (ep.accessible ? "responds" : "protected")})`);
    }
    lines.push("");
  }
  
  // Email Authentication
  lines.push("### Email Authentication");
  lines.push(`- **SPF Record:** ${result.emailAuth.spf ? "Present" : "Missing"}`);
  lines.push(`- **DMARC Record:** ${result.emailAuth.dmarc ? "Present" : "Missing"}`);
  lines.push(`- **DKIM Record:** ${result.emailAuth.dkim ? `Present (${result.emailAuth.dkim.selector})` : "Not verified (common selector guess only)"}`);
  lines.push("");
  
  // DNS Records
  if (result.dnsRecords) {
    lines.push("### DNS Records");
    if (result.dnsRecords.mx?.length > 0) {
      lines.push(`- **MX Records:** ${result.dnsRecords.mx.map(m => m.exchange).join(", ")}`);
    } else {
      lines.push("- **MX Records:** None found");
    }
    if (result.dnsRecords.ns?.length > 0) {
      lines.push(`- **NS Records:** ${result.dnsRecords.ns.slice(0, 3).join(", ")}`);
    }
    if (result.dnsRecords.a?.length > 0) {
      lines.push(`- **A Records:** ${result.dnsRecords.a.slice(0, 2).join(", ")}`);
    }
    lines.push("");
  }
  
  // Libraries (additional tech stack details)
  if (result.techStack?.libraries?.length > 0) {
    lines.push("### Libraries Detected");
    lines.push(`- ${result.techStack.libraries.slice(0, 10).join(", ")}${result.techStack.libraries.length > 10 ? ` (+${result.techStack.libraries.length - 10} more)` : ''}`);
    lines.push("");
  }
  
  // Third-Party Scripts
  if (result.thirdPartyScripts) {
    lines.push("### Third-Party Scripts");
    const tps = result.thirdPartyScripts;
    lines.push(`- **Total Scripts:** ${tps.total}`);
    lines.push(`- **First-Party:** ${tps.firstParty?.length || 0}`);
    lines.push(`- **Third-Party:** ${tps.thirdParty?.length || 0}`);
    
    if (tps.categories) {
      const activeCats = Object.entries(tps.categories)
        .filter(([_, items]) => items?.length > 0)
        .map(([cat, items]) => `${cat}: ${items.map(i => i.name || i).join(", ")}`);
      
      if (activeCats.length > 0) {
        lines.push("**Categories:**");
        for (const cat of activeCats.slice(0, 5)) {
          lines.push(`- ${cat}`);
        }
      }
    }
    
    if (tps.trackers?.length > 0) {
      lines.push(`- **Known Trackers:** ${tps.trackers.length}`);
    }
    if (tps.potentialRisks?.length > 0) {
      lines.push(`- **Potential Risks:** ${tps.potentialRisks.length}`);
    }
    lines.push("");
  }
  
  // Form Security (enhanced)
  if (result.forms && result.forms.totalForms > 0) {
    lines.push("### Form Security");
    lines.push(`- **Total Forms:** ${result.forms.totalForms}`);
    lines.push(`- **Secure Forms:** ${result.forms.secureForms || 0}`);
    lines.push(`- **Insecure Forms:** ${result.forms.insecureForms || 0}`);
    
    // Cross-origin forms (HIGH priority gap fix)
    if (result.forms.crossOriginForms > 0) {
      lines.push(`- **Cross-Origin Forms:** ${result.forms.crossOriginForms} (${result.forms.untrustedCrossOriginForms || 0} untrusted, ${result.forms.trustedCrossOriginForms || 0} known third-party)`);
    }
    
    // File upload forms (HIGH priority gap fix)
    if (result.forms.fileUploadForms > 0) {
      lines.push(`- **File Upload Forms:** ${result.forms.fileUploadForms}`);
    }
    
    // Forms with hidden fields (HIGH priority gap fix)
    if (result.forms.formsWithHiddenFields > 0) {
      lines.push(`- **Forms with Hidden Fields:** ${result.forms.formsWithHiddenFields}`);
    }
    
    // Phone fields in sensitive forms (MEDIUM priority gap fix)
    const formsWithPhone = result.forms.forms?.filter(f => f.hasPhoneField && (f.hasPasswordField || f.hasCreditCardField || f.hasEmailField));
    if (formsWithPhone?.length > 0) {
      lines.push(`- **Sensitive Forms with Phone:** ${formsWithPhone.length}`);
    }
    
    if (result.forms.issues?.length > 0) {
      lines.push("**Security Issues:**");
      for (const issue of result.forms.issues.slice(0, 8)) {
        lines.push(`- ⚠️ ${issue}`);
      }
    }
    
    // Highlight forms with sensitive data
    const sensitiveForms = result.forms.forms?.filter(f => f.hasPasswordField || f.hasCreditCardField || f.hasSsnField);
    if (sensitiveForms?.length > 0) {
      lines.push("**Sensitive Data Forms:**");
      for (const form of sensitiveForms) {
        const flags = [];
        if (form.hasPasswordField) flags.push("password");
        if (form.hasCreditCardField) flags.push("credit card");
        if (form.hasSsnField) flags.push("SSN");
        if (form.hasPhoneField) flags.push("phone");
        if (form.hasEmailField) flags.push("email");
        const crossOrigin = form.isCrossOrigin ? " ❌ CROSS-ORIGIN" : "";
        lines.push(`- Form #${form.index}: ${flags.join(", ")} - ${form.isSecureAction !== false ? "✅ HTTPS" : "❌ HTTP"}${crossOrigin}`);
      }
    }
    
    // Forms with file uploads - check accept attribute
    const uploadForms = result.forms.forms?.filter(f => f.hasFileUpload);
    if (uploadForms?.length > 0) {
      lines.push("**File Upload Forms:**");
      for (const form of uploadForms) {
        const acceptTypes = form.fileUploadFields?.map(f => f.accept || "unrestricted").join(", ") || "unknown";
        const hasRestriction = form.fileUploadFields?.some(f => f.accept);
        lines.push(`- Form #${form.index}: ${hasRestriction ? "✅ restricted" : "⚠️ unrestricted"} (${acceptTypes})`);
      }
    }
    
    // Suspicious hidden fields
    const formsWithSuspiciousHidden = result.forms.forms?.filter(f => f.suspiciousHiddenFields?.length > 0);
    if (formsWithSuspiciousHidden?.length > 0) {
      lines.push("**⚠️ Suspicious Hidden Fields:**");
      for (const form of formsWithSuspiciousHidden) {
        lines.push(`- Form #${form.index}: ${form.suspiciousHiddenFields.map(field => `${field.name || "unnamed"} (${field.reason})`).join(", ")}`);
      }
    }
    
    lines.push("");
  }

  if (result.paymentSecurity?.hasPaymentSurface) {
    lines.push("### Payment Security Signals");
    lines.push(`- **Hosted Third-Party Checkout:** ${result.paymentSecurity.hostedThirdPartyCheckout ? "Yes" : "No"}`);
    lines.push(`- **On-Site Card Collection Forms:** ${result.paymentSecurity.onSiteCardCollectionForms || 0}`);
    if ((result.paymentSecurity.providers || []).length > 0) {
      lines.push(`- **Providers Observed:** ${result.paymentSecurity.providers.join(", ")}`);
    }
    for (const finding of result.paymentSecurity.findings.slice(0, 5)) {
      lines.push(`- [${finding.severity.toUpperCase()}] ${finding.message}`);
    }
    lines.push("");
  }
  
  // Contacts Extracted
  if (result.contacts) {
    const hasContacts = (result.contacts.emails?.length > 0) || 
                        (result.contacts.phones?.length > 0) ||
                        (result.contacts.socials?.length > 0);
    if (hasContacts) {
      lines.push("### Contacts Found");
      if (result.contacts.emails?.length > 0) {
        lines.push("**Emails:**");
        for (const email of result.contacts.emails.slice(0, 5)) {
          lines.push(`- ${email}`);
        }
        if (result.contacts.emails.length > 5) {
          lines.push(`- ... and ${result.contacts.emails.length - 5} more`);
        }
      }
      if (result.contacts.phones?.length > 0) {
        lines.push("**Phones:**");
        for (const phone of result.contacts.phones.slice(0, 5)) {
          lines.push(`- ${phone}`);
        }
      }
      if (result.contacts.socials?.length > 0) {
        lines.push("**Social Media:**");
        for (const social of result.contacts.socials) {
          lines.push(`- ${social.platform}: ${social.url}`);
        }
      }
      lines.push("");
    }
  }
  
  // Address/Location
  if (result.location && (result.location.address || result.location.serviceAreas?.length > 0)) {
    lines.push("### Location");
    if (result.location.address) {
      lines.push(`- **Address:** ${result.location.address}`);
    }
    if (result.location.serviceAreas?.length > 0) {
      lines.push(`- **Service Areas:** ${result.location.serviceAreas.slice(0, 5).join(", ")}`);
    }
    if (result.location.hasMapEmbed) {
      lines.push(`- **Google Maps Embed:** Yes`);
    }
    lines.push("");
  }
  
  // Business Info
  if (result.businessInfo) {
    const hasInfo = result.businessInfo.hours || 
                    result.businessInfo.services?.length > 0 ||
                    result.businessInfo.aboutText;
    if (hasInfo) {
      lines.push("### Business Information");
      if (result.businessInfo.hours) {
        lines.push(`- **Hours:** ${result.businessInfo.hours}`);
      }
      if (result.businessInfo.services?.length > 0) {
        lines.push(`- **Services:** ${result.businessInfo.services.slice(0, 5).join(", ")}`);
        if (result.businessInfo.services.length > 5) {
          lines.push(`  - ... and ${result.businessInfo.services.length - 5} more`);
        }
      }
      if (result.businessInfo.aboutText) {
        lines.push(`- **About:** ${result.businessInfo.aboutText.substring(0, 300)}...`);
      }
      lines.push("");
    }
  }
  
  // Lead Intelligence
  if (result.leadIntelligence) {
    const li = result.leadIntelligence;
    lines.push("### Lead Intelligence");
    
    // Social Media
    if (li.socialMedia && Object.values(li.socialMedia).some(v => v)) {
      lines.push("**Social Media:**");
      for (const [platform, url] of Object.entries(li.socialMedia)) {
        if (url) {
          lines.push(`- ${platform}: ${url}`);
        }
      }
    }
    
    // E-commerce
    if (li.ecommerce?.detected) {
      lines.push(`**E-commerce:** ${li.ecommerce.platforms?.join(", ") || "Detected"}`);
      if (li.ecommerce.hasCart) lines.push("- Has shopping cart");
      if (li.ecommerce.hasCheckout) lines.push("- Has checkout flow");
      if (li.ecommerce.paymentMethods?.length > 0) {
        lines.push(`- Payment methods: ${li.ecommerce.paymentMethods.join(", ")}`);
      }
    }
    
    // Growth Signals
    if (li.growthSignals?.length > 0) {
      lines.push("**Growth Signals:**");
      for (const signal of li.growthSignals) {
        lines.push(`- ${signal}`);
      }
    }
    
    // Employee Count
    if (li.employees?.estimated) {
      lines.push(`**Estimated Employees:** ${li.employees.estimated}`);
      if (li.employees.teamPage) lines.push(`- Team page: ${li.employees.teamPage}`);
    }
    
    // Reviews
    if (li.reviews?.length > 0) {
      lines.push("**Reviews/Reputation:**");
      for (const review of li.reviews) {
        lines.push(`- ${review.platform}${review.rating ? ` (${review.rating})` : ""}`);
      }
    }
    
    // Years in Business
    if (li.yearsInBusiness) {
      lines.push(`**Years in Business:** ~${li.yearsInBusiness} (based on ${li.yearsSource || "copyright"})`);
    }
    
    // Service Areas
    if (li.serviceAreas?.length > 0) {
      lines.push(`**Service Areas:** ${li.serviceAreas.slice(0, 5).join(", ")}`);
    }
    
    // Industry
    if (li.industry) {
      lines.push(`**Industry:** ${li.industry}`);
    }
    
    lines.push("");
  }
  
  // Sensitive Exposures
  if (result.sensitiveExposures?.length > 0) {
    lines.push("### ⚠️ Sensitive Exposures");
    for (const exposure of result.sensitiveExposures) {
      const severityIcon = exposure.severity === "critical" ? "🔴" : 
                           exposure.severity === "high" ? "🟠" : 
                           exposure.severity === "medium" ? "🟡" : "⚪";
      lines.push(`- ${severityIcon} **${exposure.type}** (${exposure.severity}): ${exposure.url}`);
      if (exposure.details) {
        lines.push(`  - ${exposure.details.substring(0, 200)}`);
      }
    }
    lines.push("");
  }
  
  // Broken Links
  const brokenLinks = getActionableBrokenLinks(result);
  if (brokenLinks.length > 0) {
    lines.push("### Broken Links");
    for (const link of brokenLinks.slice(0, 10)) {
      lines.push(`- [${link.status}] ${link.url}`);
    }
    if (brokenLinks.length > 10) {
      lines.push(`- ... and ${brokenLinks.length - 10} more`);
    }
    lines.push("");
  }
  
  // SEO Files
  if (result.seoFiles) {
    lines.push("### SEO Files");
    lines.push(`- **robots.txt:** ${result.seoFiles.robotsTxt ? "Present" : "Missing"}`);
    lines.push(`- **sitemap.xml:** ${result.seoFiles.sitemapXml ? "Present" : "Missing"}`);
    lines.push("");
  }
  
  // Cookie Consent
  if (result.cookieConsent?.detected) {
    lines.push("### Cookie Consent");
    lines.push(`- **Detected:** Yes`);
    lines.push(`- **Type:** ${result.cookieConsent.type || "Unknown"}`);
    lines.push("");
  }
  
  // Console Errors
  const rawJsErrorCount =
    (result.jsErrorAnalysis?.rawPageErrors?.length || 0) +
    (result.jsErrorAnalysis?.rawConsoleErrors?.length || 0);
  if (result.consoleErrors.length > 0 || result.pageErrors.length > 0 || rawJsErrorCount > 0) {
    lines.push("### JavaScript Errors");
    if (result.pageErrors.length > 0) {
      lines.push("**Verified Page Errors:**");
      for (const err of result.pageErrors.slice(0, 3)) {
        lines.push(`- ${err.substring(0, 200)}`);
      }
    }
    if (result.consoleErrors.length > 0) {
      lines.push("**Verified Console Errors:**");
      for (const err of result.consoleErrors.slice(0, 5)) {
        lines.push(`- ${err.substring(0, 200)}`);
      }
    }
    if (result.jsErrorAnalysis?.scannerInducedPageErrors?.length > 0 || result.jsErrorAnalysis?.scannerInducedConsoleErrors?.length > 0) {
      lines.push(`- Filtered likely scanner-induced patterns: ${(result.jsErrorAnalysis.scannerInducedPageErrors?.length || 0) + (result.jsErrorAnalysis.scannerInducedConsoleErrors?.length || 0)}`);
    }
    if (result.jsErrorAnalysis?.provisionalPageErrors?.length > 0 || result.jsErrorAnalysis?.provisionalConsoleErrors?.length > 0) {
      lines.push(`- Observed only under audit instrumentation: ${(result.jsErrorAnalysis.provisionalPageErrors?.length || 0) + (result.jsErrorAnalysis.provisionalConsoleErrors?.length || 0)}`);
    }
    lines.push("");
  }

  if (result.findingConfidence) {
    for (const [key, label] of tierLabels) {
      const items = result.findingConfidence[key] || [];
      if (items.length === 0) continue;
      lines.push(`### ${label} Findings`);
      for (const item of items.slice(0, 8)) {
        lines.push(`- **${item.severity.toUpperCase()}** ${item.message}`);
      }
      if (items.length > 8) {
        lines.push(`- ... and ${items.length - 8} more`);
      }
      lines.push("");
    }
  }

  if (result.securityOutreach?.primaryHook || (result.securityOutreach?.verifiedHooks || []).length > 0 || (result.securityOutreach?.probableHooks || []).length > 0) {
    lines.push("### Security Outreach Hooks");
    lines.push(`- **Primary Hook:** ${result.securityOutreach.primaryHook || "None selected"}`);
    if ((result.securityOutreach.verifiedHooks || []).length > 0) {
      lines.push(`- **Verified Hooks:** ${result.securityOutreach.verifiedHooks.join(" | ")}`);
    }
    if ((result.securityOutreach.probableHooks || []).length > 0) {
      lines.push(`- **Probable Hooks:** ${result.securityOutreach.probableHooks.join(" | ")}`);
    }
    lines.push("");
  }
  
  // Critical Issues
  if (result.criticalIssues.length > 0) {
    lines.push("### Critical Issues");
    for (const issue of result.criticalIssues) {
      lines.push(`- **${issue}**`);
    }
    lines.push("");
  }
  
  // Warnings
  if (result.warnings.length > 0) {
    lines.push("### Warnings");
    for (const warning of result.warnings) {
      lines.push(`- ${warning}`);
    }
    lines.push("");
  }
  
  // Screenshots
  lines.push("### Screenshots");
  if (result.screenshots.desktop) {
    lines.push(`- **Desktop:** \`${path.basename(result.screenshots.desktop)}\``);
  }
  if (result.screenshots.mobile) {
    lines.push(`- **Mobile:** \`${path.basename(result.screenshots.mobile)}\``);
  }
  lines.push("");
  
  return lines.join("\n");
}

/**
 * Extract contact information from page
 */
async function extractContacts(page) {
  return await page.evaluate(() => {
    const contacts = {
      emails: [],
      phones: [],
      socials: {
        facebook: null,
        instagram: null,
        twitter: null,
        linkedin: null,
        youtube: null,
        tiktok: null,
        yelp: null,
        google_business: null,
        other: []
      }
    };

    const pageHost = window.location.hostname.toLowerCase();
    const vendorSocialHandles = new Set(['wix', 'wix-com', 'wixstudio', 'shopify', 'wordpress', 'elementor', 'angi', 'angi_home']);
    const vendorSocialUrls = [
      'facebook.com/wix',
      'linkedin.com/company/wix-com',
      'instagram.com/wix',
      'twitter.com/wix',
      'x.com/wix',
      'youtube.com/wix',
      'tiktok.com/@wix',
      'facebook.com/angi',
      'instagram.com/angi',
      'x.com/angi_home',
      'youtube.com/channel/uczcjolzxhdi6vu77vi2cndg',
      'facebook.com/conroedirect',
      'instagram.com/citydirect',
      'twitter.com/conroedirect',
      'youtube.com/user/citydirect'
    ];
    const cleanUrl = (value) => {
      try {
        const parsed = new URL(value);
        return parsed.toString().split('?')[0].replace(/\/$/, '');
      } catch {
        return null;
      }
    };
    const isGenericSocial = (platform, value) => {
      try {
        const parsed = new URL(value);
        const path = parsed.pathname.toLowerCase();
        if (platform === 'facebook') {
          return /(^|\/)profile\.php$/.test(path) || path === '/' || path === '';
        }
        if (platform === 'instagram') {
          return path === '/' || path === '';
        }
        if (platform === 'twitter') {
          return path === '/' || path === '' || /\/(home|search|explore|intent)\b/.test(path);
        }
        if (platform === 'youtube') {
          return path === '/' || path === '' || /\.js$/i.test(path);
        }
        if (platform === 'yelp') {
          return path === '/' || path === '' || path.startsWith('/search');
        }
        return false;
      } catch {
        return true;
      }
    };
    const hasExpectedSocialHost = (platform, value) => {
      try {
        const parsed = new URL(value);
        const host = parsed.hostname.toLowerCase();
        const hostChecks = {
          facebook: ['facebook.com', 'fb.com'],
          instagram: ['instagram.com'],
          twitter: ['twitter.com', 'x.com'],
          linkedin: ['linkedin.com'],
          youtube: ['youtube.com', 'youtu.be'],
          tiktok: ['tiktok.com'],
          yelp: ['yelp.com'],
          google_business: ['google.com', 'g.page']
        };
        const allowedHosts = hostChecks[platform] || [];
        return allowedHosts.some((candidate) => host === candidate || host.endsWith(`.${candidate}`));
      } catch {
        return false;
      }
    };
    const isVendorSocialLink = (platform, linkEl, value) => {
      try {
        const parsed = new URL(value);
        const normalizedValue = value.toLowerCase();
        const pathParts = parsed.pathname.toLowerCase().split('/').filter(Boolean);
        const handle = pathParts[pathParts.length - 1] || '';
        const label = [
          linkEl?.textContent || '',
          linkEl?.getAttribute?.('aria-label') || '',
          linkEl?.getAttribute?.('title') || '',
          linkEl?.className || ''
        ].join(' ').toLowerCase();
        const allSegments = new Set(pathParts);

        if (vendorSocialUrls.some((snippet) => normalizedValue.includes(snippet))) return true;
        if (/(?:citydirect|conroedirect|condroedirect)/.test(normalizedValue)) return true;
        if (vendorSocialHandles.has(handle)) return true;
        if ([...allSegments].some((segment) => vendorSocialHandles.has(segment))) return true;
        if (/\b(?:powered by wix|wix|website builder|create your website|made with wix|angi)\b/.test(label)) {
          return true;
        }
        if (pageHost.endsWith('wixsite.com') && /\b(?:wix|powered by wix)\b/.test(label)) {
          return true;
        }
        if (pageHost.endsWith('angi.com') && /\/companylist\//.test(window.location.pathname.toLowerCase()) && /\bangi\b/.test(label)) {
          return true;
        }
        return false;
      } catch {
        return false;
      }
    };
    
    // Email regex - matches most common email patterns
    const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/gi;
    
    // Phone regex - matches various US formats
    const phoneRegex = /(?:\+?1[-.\s]?)?(?:\(?[0-9]{3}\)?[-.\s]?)?[0-9]{3}[-.\s]?[0-9]{4}/g;
    
    // Get all text content
    const bodyText = document.body.innerText || "";
    const htmlContent = document.body.innerHTML || "";
    
    // Extract emails from visible text
    const textEmails = bodyText.match(emailRegex) || [];
    
    // Extract emails from href="mailto:" links
    const mailtoLinks = Array.from(document.querySelectorAll('a[href^="mailto:"]'))
      .map(a => a.href.replace("mailto:", "").split("?")[0]);
    
    // Combine and dedupe emails
    const allEmails = [...new Set([...textEmails, ...mailtoLinks])];
    
    const visibleTextLower = bodyText.toLowerCase();
    const htmlLower = htmlContent.toLowerCase();
    const licenseContextTerms = [
      "license", "copyright", "reserved font name", "fontsquirrel", "font software",
      "sil open font license", "vendor", "cdn", "asset", "sprite", "stylesheet",
      ".woff", ".woff2", ".ttf", ".otf", ".svg", ".png", ".jpg", ".jpeg", ".gif", ".webp"
    ];
    const positiveContactTerms = [
      "mailto:", "contact", "email us", "get in touch", "call us", "phone", "visit us"
    ];
    
    function hasLicenseLikeContext(email) {
      const lowerEmail = String(email || "").toLowerCase();
      if (!lowerEmail) return false;
      const idx = htmlLower.indexOf(lowerEmail);
      if (idx === -1) return false;
      const start = Math.max(0, idx - 220);
      const end = Math.min(htmlLower.length, idx + lowerEmail.length + 220);
      const snippet = htmlLower.slice(start, end);
      return licenseContextTerms.some(term => snippet.includes(term))
        && !positiveContactTerms.some(term => snippet.includes(term));
    }

    function isLikelyRealContactEmail(email) {
      const lowerEmail = String(email || "").toLowerCase().trim();
      if (!lowerEmail) return false;
      const localPart = lowerEmail.split("@")[0] || "";

      // Common false positives from placeholders, telemetry, and vendor/system addresses.
      const excludePatterns = [
        /example\.com/i, /test\.com/i, /domain\.com/i, /email\.com/i,
        /yourname@/i, /youremail@/i, /user@/i, /name@/i,
        /@sentry\./i, /@wixpress\./i, /@wordpress\./i,
        /noreply@/i, /no-reply@/i, /donotreply@/i
      ];
      if (excludePatterns.some(p => p.test(lowerEmail))) return false;

      // Reject obvious asset/file-like pseudo-emails such as logo@2x.png or icon@3x.svg.
      if (/\.(png|jpe?g|gif|svg|webp|ico|avif|css|js|woff2?|ttf|otf)$/i.test(lowerEmail)) return false;
      if (/@\d+x\.(png|jpe?g|gif|svg|webp|ico|avif)$/i.test(lowerEmail)) return false;
      if (/^[0-9a-f]{16,}$/i.test(localPart)) return false;

      // Prefer explicitly-linked contacts, then visible text that is not surrounded by license/vendor chatter.
      if (mailtoLinks.some(link => String(link).toLowerCase() === lowerEmail)) return true;
      if (!visibleTextLower.includes(lowerEmail)) return false;
      if (hasLicenseLikeContext(lowerEmail)) return false;
      return true;
    }
    
    contacts.emails = allEmails
      .filter(isLikelyRealContactEmail)
      .slice(0, 10); // Limit to 10
    
    const formatPhone = (value) => {
      const cleaned = String(value || "").replace(/[^\d+]/g, "");
      const digitsOnly = cleaned.replace(/[^\d]/g, "");
      if (digitsOnly.length === 10) return `(${digitsOnly.slice(0,3)}) ${digitsOnly.slice(3,6)}-${digitsOnly.slice(6)}`;
      if (digitsOnly.length === 11 && digitsOnly.startsWith("1")) return `+1 (${digitsOnly.slice(1,4)}) ${digitsOnly.slice(4,7)}-${digitsOnly.slice(7)}`;
      return cleaned;
    };
    const normalizedPhoneKey = (value) => {
      const digitsOnly = String(value || "").replace(/[^\d]/g, "");
      if (digitsOnly.length === 11 && digitsOnly.startsWith("1")) return digitsOnly.slice(1);
      return digitsOnly;
    };
    const phoneCandidates = new Map();
    const addPhoneCandidate = (value, weight, source) => {
      const key = normalizedPhoneKey(value);
      if (!key || key.length < 10 || key.length > 11) return;
      const existing = phoneCandidates.get(key);
      if (existing) {
        existing.score += weight;
        existing.sources.add(source);
        existing.rawValues.add(String(value));
      } else {
        phoneCandidates.set(key, {
          key,
          score: weight,
          sources: new Set([source]),
          rawValues: new Set([String(value)]),
        });
      }
    };

    // Extract phone numbers from visible text
    const textPhones = bodyText.match(phoneRegex) || [];
    textPhones.forEach((phone) => addPhoneCandidate(phone, 1, 'body-text'));

    // Extract from tel: links
    const telLinks = Array.from(document.querySelectorAll('a[href^="tel:"]'))
      .map(a => a.href.replace("tel:", ""));
    telLinks.forEach((phone) => addPhoneCandidate(phone, 6, 'tel-link'));

    const headSources = [
      document.title,
      document.querySelector('meta[name="description"]')?.content,
      document.querySelector('meta[property="og:description"]')?.content,
      document.querySelector('meta[property="og:title"]')?.content,
    ].filter(Boolean);
    headSources.forEach((text) => {
      (String(text).match(phoneRegex) || []).forEach((phone) => addPhoneCandidate(phone, 5, 'head-meta'));
    });

    const schemaScripts = Array.from(document.querySelectorAll('script[type="application/ld+json"]'));
    schemaScripts.forEach((script) => {
      try {
        const parsed = JSON.parse(script.textContent);
        const items = Array.isArray(parsed)
          ? parsed
          : parsed && Array.isArray(parsed['@graph'])
            ? parsed['@graph']
            : [parsed];
        items.forEach((item) => {
          const phones = [];
          if (typeof item?.telephone === 'string') phones.push(item.telephone);
          if (Array.isArray(item?.telephone)) phones.push(...item.telephone);
          phones.forEach((phone) => addPhoneCandidate(phone, 5, 'schema'));
        });
      } catch {}
    });

    contacts.phones = Array.from(phoneCandidates.values())
      .sort((a, b) => b.score - a.score || b.sources.size - a.sources.size || a.key.localeCompare(b.key))
      .map((entry) => formatPhone(Array.from(entry.rawValues)[0]))
      .filter(p => p.length >= 10)
      .slice(0, 5);
    
    // Extract social media links
    const allLinks = Array.from(document.querySelectorAll('a[href]'));
    
    // Social patterns
    const socialPatterns = {
      facebook: /(?:facebook\.com|fb\.com)\/(?!sharer|sharer\.php|share\.php|dialog|plugins|help|business)[^"'\s]+/i,
      instagram: /instagram\.com\/(?!p\/|reel\/|explore\/|accounts\/|directory\/)[^"'\s]+/i,
      twitter: /(?:twitter\.com|x\.com)\/(?!status\/|intent\/|home|search|explore|i\/)[^"'\s]+/i,
      linkedin: /linkedin\.com\/(company|in|school)\/[^"'\s]+/i,
      youtube: /youtube\.com\/(channel\/|user\/|c\/|@)[^"'\s]+/i,
      tiktok: /tiktok\.com\/@[^"'\s]+/i,
      yelp: /yelp\.com\/biz\/[^"'\s]+/i,
      google_business: /business\.google\.com\/[^"'\s]+|g\.page\/[^"'\s]+/i
    };
    
    for (const anchor of allLinks) {
      const link = String(anchor.href || '').toLowerCase();
      for (const [platform, pattern] of Object.entries(socialPatterns)) {
        if (pattern.test(link) && !contacts.socials[platform]) {
          const normalized = cleanUrl(link);
          if (
            !normalized ||
            !hasExpectedSocialHost(platform, normalized) ||
            isGenericSocial(platform, normalized) ||
            isVendorSocialLink(platform, anchor, normalized)
          ) {
            continue;
          }
          contacts.socials[platform] = normalized;
        }
      }
    }
    
    // Clean up other socials
    for (const [platform, url] of Object.entries(contacts.socials)) {
      if (url && typeof url === 'string') {
        contacts.socials[platform] = cleanUrl(url);
      }
    }
    
    return contacts;
  });
}

/**
 * Extract address/location from page
 */
async function extractAddress(page) {
  return await page.evaluate(() => {
    const address = {
      raw: null,
      street: null,
      city: null,
      state: null,
      zip: null,
      country: null,
      coordinates: null
    };

    const normalizeText = (text) => (text || '').replace(/\s+/g, ' ').trim();
    const isPoBox = (text) => /\bP\.?\s*O\.?\s*Box\b/i.test(text || '');
    const isJunkAddressText = (text) => {
      const normalized = normalizeText(text);
      if (!normalized) return true;
      return (
        /looks like this domain isn't connected to a website yet/i.test(normalized) ||
        /need more help\?? please contact our support team/i.test(normalized) ||
        /\b(?:wordpress theme|website template|website builder|made with wix|powered by wix|powered by webador|support team|skip to main|load more content)\b/i.test(normalized) ||
        /\b(?:login|cart|search|menu|gift cards?|hiring|contact\/faq)\b/i.test(normalized) ||
        /copyright/i.test(normalized)
      );
    };
    const hasVisibleAddressSupport = (raw) => {
      const normalized = normalizeText(raw);
      if (!normalized) return false;
      if (bodyText.includes(normalized)) return true;
      const fragments = normalized
        .split(',')
        .map((part) => normalizeText(part))
        .filter(Boolean);
      if (fragments.length === 0) return false;
      let hits = 0;
      for (const fragment of fragments) {
        if (fragment.length < 4) continue;
        if (bodyText.includes(fragment)) {
          hits += 1;
        }
      }
      return hits >= Math.min(2, fragments.length);
    };
    const scoreCandidate = (text) => {
      const normalized = normalizeText(text);
      if (!normalized) return -1;
      if (isJunkAddressText(normalized)) return -1;
      let score = 0;
      if (/\d{1,6}\s+[A-Za-z0-9.#'\- ]+/.test(normalized)) score += 3;
      if (/\b(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Way|Court|Ct|Place|Pl|Circle|Cir|Parkway|Pkwy|Highway|Hwy|Route|Rt|Suite|Ste|Unit|FM|Interstate|I-\d+)/i.test(normalized)) score += 3;
      if (/[A-Za-z .'-]+,\s*[A-Z]{2}\s+\d{5}(?:-\d{4})?/.test(normalized)) score += 3;
      if (/\b(?:TX|Texas|CA|FL|LA|OK|US|USA)\b/.test(normalized)) score += 1;
      if (normalized.length > 140) score -= 2;
      return score;
    };

    const candidateSet = new Map();
    const addCandidate = (text, source) => {
      const normalized = normalizeText(text);
      if (!normalized) return;
      if (isJunkAddressText(normalized)) return;
      const score = scoreCandidate(normalized);
      if (score < 2) return;
      const existing = candidateSet.get(normalized);
      if (existing) {
        existing.score = Math.max(existing.score, score);
        existing.sources.add(source);
      } else {
        candidateSet.set(normalized, { text: normalized, score, sources: new Set([source]) });
      }
    };

    const addressSelectors = [
      'address',
      '[itemprop="address"]',
      '.contact-address',
      '.address',
      '[class*="address"]',
      '[class*="location"]',
      '[class*="contact"]',
      'footer',
      '.footer',
      '[data-location]',
      '[data-address]'
    ];

    for (const selector of addressSelectors) {
      for (const el of document.querySelectorAll(selector)) {
        const text = normalizeText(el.innerText);
        if (!text || text.length < 10) continue;
        addCandidate(text, `selector:${selector}`);
      }
    }

    const bodyText = normalizeText(document.body.innerText);
    const usAddressPattern = /\b(\d{1,6}\s+[A-Za-z0-9.#'\- ]+?\s+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Way|Court|Ct|Place|Pl|Circle|Cir|Parkway|Pkwy|Highway|Hwy|Route|Rt|Suite|Ste|Unit|FM|Interstate|I-\d+)[^,\n]{0,40},?\s+[A-Za-z .'-]+,\s*[A-Z]{2}\s+\d{5}(?:-\d{4})?)/g;
    const poBoxPattern = /\b(P\.?\s*O\.?\s*Box\s+\d+[A-Za-z0-9\- ]*,?\s+[A-Za-z .'-]+,\s*[A-Z]{2}\s+\d{5}(?:-\d{4})?)/gi;

    for (const match of bodyText.matchAll(usAddressPattern)) {
      addCandidate(match[1], 'body-regex');
    }
    for (const match of bodyText.matchAll(poBoxPattern)) {
      addCandidate(match[1], 'body-regex');
    }

    // Check for schema.org address
    const schemaScripts = document.querySelectorAll('script[type="application/ld+json"]');
    for (const script of schemaScripts) {
      try {
        const parsed = JSON.parse(script.textContent);
        const items = Array.isArray(parsed)
          ? parsed
          : parsed && Array.isArray(parsed['@graph'])
            ? parsed['@graph']
            : [parsed];

        for (const json of items) {
          if (json.address || json.location) {
            const addr = json.address || json.location;
            if (typeof addr === 'object') {
              const raw = [
                addr.streetAddress || addr.street || null,
                addr.addressLocality || addr.city || null,
                addr.addressRegion || addr.state || null,
                addr.postalCode || addr.zip || null,
                addr.addressCountry || addr.country || null,
              ].filter(Boolean).join(', ');
              if (raw && hasVisibleAddressSupport(raw)) {
                addCandidate(raw, 'schema');
              }
              if (!address.street && raw && hasVisibleAddressSupport(raw)) {
                address.street = addr.streetAddress || addr.street || null;
                address.city = addr.addressLocality || addr.city || null;
                address.state = addr.addressRegion || addr.state || null;
                address.zip = addr.postalCode || addr.zip || null;
                address.country = addr.addressCountry || addr.country || null;
                if (address.street && address.city) {
                  address.raw = raw;
                }
              }
            }
          }
          // Check for geo coordinates
          if (json.geo && !address.coordinates) {
            address.coordinates = {
              lat: json.geo.latitude || json.geo.lat,
              lng: json.geo.longitude || json.geo.lng
            };
          }
        }
      } catch (e) {}
    }

    const bestCandidate = Array.from(candidateSet.values())
      .sort((a, b) => b.score - a.score || a.text.length - b.text.length)[0];

    if (!address.raw && bestCandidate) {
      address.raw = bestCandidate.text;
    }

    if (address.raw) {
      if (isJunkAddressText(address.raw)) {
        address.raw = null;
        address.street = null;
        address.city = null;
        address.state = null;
        address.zip = null;
        address.country = null;
      }
    }

    if (address.raw) {
      if (!isPoBox(address.raw) && !/\bLocation\s*#?\d+\b/i.test(address.raw)) {
        const parsed = address.raw.match(/\b(?<street>\d{1,6}\s+[A-Za-z0-9.#'\- ]+?)\s*,?\s+(?<city>[A-Za-z .'-]+),\s*(?<state>[A-Z]{2})\s+(?<zip>\d{5}(?:-\d{4})?)(?:,\s*(?<country>USA?|United States))?/i);
        if (parsed && parsed.groups) {
          address.street = address.street || normalizeText(parsed.groups.street);
          address.city = address.city || normalizeText(parsed.groups.city);
          address.state = address.state || normalizeText(parsed.groups.state).toUpperCase();
          address.zip = address.zip || normalizeText(parsed.groups.zip);
          if (parsed.groups.country) {
            address.country = address.country || "US";
          }
        } else {
          const cityStateZip = address.raw.match(/([A-Z][a-zA-Z .'-]+),\s*([A-Z]{2})\s+(\d{5}(?:-\d{4})?)/);
          if (cityStateZip) {
            address.city = address.city || normalizeText(cityStateZip[1]);
            address.state = address.state || normalizeText(cityStateZip[2]).toUpperCase();
            address.zip = address.zip || normalizeText(cityStateZip[3]);
          }
        }
      } else {
        const cityStateZip = address.raw.match(/([A-Z][a-zA-Z .'-]+),\s*([A-Z]{2})\s+(\d{5}(?:-\d{4})?)/);
        if (cityStateZip) {
          address.city = address.city || normalizeText(cityStateZip[1]);
          address.state = address.state || normalizeText(cityStateZip[2]).toUpperCase();
          address.zip = address.zip || normalizeText(cityStateZip[3]);
        }
      }
    }

    // Google Maps embed check
    const mapsIframe = document.querySelector('iframe[src*="google.com/maps"], iframe[src*="maps.google"]');
    if (mapsIframe && !address.coordinates) {
      address.coordinates = { source: 'google_maps_embed' };
    }

    return address;
  });
}

/**
 * Extract business info from page
 */
async function extractBusinessInfo(page) {
  return await page.evaluate(() => {
    const info = {
      name: null,
      tagline: null,
      description: null,
      hours: null,
      services: [],
      founded: null,
      employeeCount: null,
      hasReviews: false,
      hasTestimonials: false,
      isUnderConstruction: false
    };

    const compact = (value) => {
      if (typeof value !== 'string') return null;
      const trimmed = value.replace(/\s+/g, ' ').trim();
      return trimmed.length > 0 ? trimmed : null;
    };
    const pageHost = window.location.hostname.toLowerCase();
    const pagePath = window.location.pathname.toLowerCase();
    const isAngiListingPage = pageHost.endsWith('angi.com') && /\/companylist\//.test(pagePath);
    const domainBrandKey = pageHost
      .replace(/^www\./, '')
      .split('.')[0]
      .replace(/[^a-z0-9]+/g, '')
      .trim();
    const titleParts = (value) => {
      const normalized = compact(value);
      if (!normalized) return [];
      return normalized
        .split(/[|\-–—]+/)
        .map((part) => compact(part))
        .filter(Boolean);
    };
    const descriptionNameParts = (value) => {
      return titleParts(value)
        .filter((part) => part.length <= 60)
        .filter((part) => !/\b(?:guaranteeing|maximizing|serving|trusted|experience|experts|power|partnerships|growth)\b/i.test(part));
    };
    const normalizeNameCandidate = (value) => {
      const normalized = compact(value);
      if (!normalized) return null;
      return normalized
        .replace(/(?<=[A-Za-z])\d{1,2}$/, '')
        .replace(/\s*[-–—]\s*logo$/i, '')
        .replace(/\b-logo\b/gi, '')
        .replace(/\s{2,}/g, ' ')
        .trim();
    };
    const badBusinessPhrases = [
      /looks like this domain isn't connected to a website yet/i,
      /need more help\?? please contact our support team/i,
      /wordpress theme/i,
      /website builder/i,
      /made with wix/i,
      /powered by wix/i,
      /under construction/i,
      /coming soon/i,
      /page not found/i,
      /sign in/i,
      /log in/i,
      /\blogin\b/i,
      /\bregister\b/i,
      /\bcheckout\b/i,
      /\bcart\b/i,
      /\bsearch\b/i,
      /\bmenu\b/i,
      /\border now\b/i,
      /\bskip to main content\b/i,
      /\bload more content\b/i,
      /\bhiring\b/i,
      /\bgift cards?\b/i,
      /\bcontact\/faq\b/i,
      /\bopen navigation\b/i,
      /\bhow to build your own website\b/i,
    ];
    const isJunkName = (value) => {
      const normalized = normalizeNameCandidate(value);
      if (!normalized) return true;
      const lowered = normalized.toLowerCase();
      const junkPatterns = [
        /^thank you!?$/,
        /^thanks!?$/,
        /^welcome!?$/,
        /^home$/,
        /^homepage$/,
        /^contact us$/,
        /^about us$/,
        /^our team$/,
        /^our staff$/,
        /^submit$/,
        /^success$/,
        /^loading$/,
        /^error$/,
        /^page not found$/,
        /^coming soon$/,
        /^under construction$/,
        /^json$/,
        /^login$/,
        /^sign in$/,
        /^log in$/,
        /^cart$/,
        /^search$/,
        /^menu$/,
        /^order now$/,
        /^logo$/,
        /^open navigation$/,
        /^how to build your own website$/,
        /^.+\s+»\s+feed$/,
        /^.+\s+rss$/,
        /^[a-z0-9-]+\.(?:com|net|org|co|io|biz|us)$/,
      ];
      if (junkPatterns.some((pattern) => pattern.test(lowered))) {
        return true;
      }
      if (badBusinessPhrases.some((pattern) => pattern.test(normalized))) {
        return true;
      }
      if (!/[a-z]/i.test(normalized)) {
        return true;
      }
      if (normalized.length < 3 || normalized.length > 80) {
        return true;
      }
      if (isAngiListingPage && /^(?:angi|angi\s*\(formerly angie'?s list\):\s*home service pros)$/i.test(normalized)) {
        return true;
      }
      if (/\b(?:logo|theme|template|support team|website builder|open navigation|how to build your own website|rss|atom)\b/i.test(normalized) || /\b»\s*feed\b/i.test(normalized)) {
        return true;
      }
      return false;
    };
    const scoreNameCandidate = (candidate, source) => {
      const normalized = normalizeNameCandidate(candidate);
      if (isJunkName(normalized)) return -999;
      let score = 0;
      if (source === 'og:site_name') score += 8;
      if (source === 'brand-selector') score += 6;
      if (source === 'meta-description') score += 6;
      if (source === 'og:title') score += 5;
      if (source === 'h1') score += 3;
      if (source === 'title') score += 2;
      if (source === 'visible-brand-text') score += 4;
      const candidateKey = normalized.toLowerCase().replace(/[^a-z0-9]+/g, '');
      if (
        domainBrandKey &&
        candidateKey &&
        candidateKey === domainBrandKey
      ) {
        score += 10;
      } else if (
        domainBrandKey &&
        candidateKey &&
        (domainBrandKey.includes(candidateKey) || candidateKey.includes(domainBrandKey))
      ) {
        score += 3;
      }
      if (/\b(?:llc|inc|co\.?|company|restaurant|grill|clinic|studio|services?|supply|group|machine|medical)\b/i.test(normalized)) {
        score += 3;
      }
      if (/^[A-Z0-9 .&'/-]{4,}$/.test(normalized)) {
        score += 1;
      }
      if (/\b(?:home|contact|about|products|services|locations|faq|hiring)\b/i.test(normalized)) {
        score -= 3;
      }
      if (/[-–—]/.test(normalized)) {
        score -= 1;
      }
      if (/\b(?:logo|theme|template)\b/i.test(normalized)) {
        score -= 8;
      }
      return score;
    };
    const cleanDescription = (value) => {
      const normalized = compact(value);
      if (!normalized) return null;
      if (
        badBusinessPhrases.some((pattern) => pattern.test(normalized)) ||
        /\b(?:wordpress theme|website template|website builder|made with wix|powered by wix|powered by webador|support team|parked free courtesy)\b/i.test(normalized)
      ) {
        return null;
      }
      if (
        isAngiListingPage &&
        /\b(?:read real local reviews|book a pro|neighbors so you can pick the right pro|home service pros|from angi members|join today to leave your own review)\b/i.test(normalized)
      ) {
        return null;
      }
      return normalized;
    };
    
    // Business name - prefer stable brand signals over page-level success headings.
    const metaOgSiteName = document.querySelector('meta[property="og:site_name"]');
    const metaOgTitle = document.querySelector('meta[property="og:title"]');
    const metaDesc = document.querySelector('meta[name="description"]');
    const metaOgDesc = document.querySelector('meta[property="og:description"]');
    const h1 = document.querySelector('h1');
    const brandSelectors = [
      '.site-title',
      '.navbar-brand',
      '.brand',
      '.logo-text',
      'header .logo',
      'header [class*="brand"]',
      'a[rel="home"]',
      'a[href="/"]',
      'a[href="./"]'
    ];
    const visibleBrandCandidates = Array.from(document.querySelectorAll('img[alt], [aria-label], [title]'))
      .map((node) => node.getAttribute('alt') || node.getAttribute('aria-label') || node.getAttribute('title'))
      .filter(Boolean)
      .slice(0, 12);
    const nameCandidates = [
      { value: metaOgSiteName?.content, source: 'og:site_name' },
      ...titleParts(metaOgTitle?.content).map((value) => ({ value, source: 'og:title' })),
      ...descriptionNameParts(metaDesc?.content).map((value) => ({ value, source: 'meta-description' })),
      ...descriptionNameParts(metaOgDesc?.content).map((value) => ({ value, source: 'meta-description' })),
      ...brandSelectors.map((selector) => ({ value: document.querySelector(selector)?.innerText, source: 'brand-selector' })),
      { value: h1?.innerText, source: 'h1' },
      ...titleParts(document.title).map((value) => ({ value, source: 'title' })),
      ...visibleBrandCandidates.map((value) => ({ value, source: 'visible-brand-text' }))
    ];
    const scoredNameCandidates = nameCandidates
      .map((candidate) => {
        const normalized = normalizeNameCandidate(candidate.value);
        return {
          value: normalized,
          source: candidate.source,
          score: scoreNameCandidate(normalized, candidate.source)
        };
      })
      .filter((candidate) => candidate.value && candidate.score > 0)
      .sort((a, b) => b.score - a.score || a.value.length - b.value.length);
    let bestNameCandidate = scoredNameCandidates[0] || null;
    if (
      bestNameCandidate &&
      bestNameCandidate.source === 'og:site_name' &&
      /\b\d$/.test(bestNameCandidate.value)
    ) {
      const basePrefix = bestNameCandidate.value.replace(/\s+\d+$/, '').toLowerCase().replace(/[^a-z0-9]+/g, '');
      const cleanerAlternate = scoredNameCandidates.find((candidate) => (
        candidate !== bestNameCandidate &&
        (candidate.source === 'title' || candidate.source === 'h1' || candidate.source === 'brand-selector') &&
        candidate.value.toLowerCase().replace(/[^a-z0-9]+/g, '').startsWith(basePrefix) &&
        !/\b\d$/.test(candidate.value)
      ));
      if (cleanerAlternate) {
        bestNameCandidate = cleanerAlternate;
      }
    }
    if (bestNameCandidate && domainBrandKey) {
      const exactDomainPart = titleParts(bestNameCandidate.value).find((part) => (
        part.toLowerCase().replace(/[^a-z0-9]+/g, '') === domainBrandKey
      ));
      if (exactDomainPart) {
        const cleanerAlternate = scoredNameCandidates.find((candidate) => (
          candidate.value.toLowerCase().replace(/[^a-z0-9]+/g, '') === domainBrandKey
        ));
        bestNameCandidate = cleanerAlternate || { ...bestNameCandidate, value: exactDomainPart };
      }
    }
    if (isAngiListingPage && bestNameCandidate && /\s+reviews$/i.test(bestNameCandidate.value)) {
      const strippedValue = bestNameCandidate.value.replace(/\s+reviews$/i, '').trim();
      const cleanerAlternate = scoredNameCandidates.find((candidate) => candidate.value.toLowerCase() === strippedValue.toLowerCase());
      bestNameCandidate = cleanerAlternate || { ...bestNameCandidate, value: strippedValue };
    }
    info.name = bestNameCandidate?.value || null;
    
    // Tagline/subtitle
    const subtitle = document.querySelector('h1 + p, .tagline, .subtitle, [class*="tagline"], [class*="subtitle"]');
    if (subtitle && subtitle.innerText.length < 200) {
      info.tagline = cleanDescription(subtitle.innerText.trim());
    }
    
    // Description - from meta or page
    info.description = cleanDescription(metaDesc?.content) || cleanDescription(metaOgDesc?.content) || null;
    
    // Business hours - look for common patterns
    const bodyText = document.body.innerText;
    const hoursPatterns = [
      /(?:hours|open)[:\s]*([^\n]+)/i,
      /(?:mon|tue|wed|thu|fri|sat|sun)[a-z]*[\s:]+[\d]+\s*(?:am|pm|a\.m\.|p\.m\.)?[\s\-–to]+[\d]+\s*(?:am|pm|a\.m\.|p\.m\.)?/gi
    ];
    
    const hoursMatch = bodyText.match(hoursPatterns[1]);
    if (hoursMatch && hoursMatch.length > 0) {
      info.hours = hoursMatch.slice(0, 7); // Limit to 7 days
    }
    
    // Services - look for service listings
    const serviceSelectors = [
      '.services li', '.service-list li', '[class*="service"] li',
      '#services li', '.services-list li'
    ];
    for (const selector of serviceSelectors) {
      const items = document.querySelectorAll(selector);
      if (items.length > 0) {
        info.services = Array.from(items).map(i => i.innerText.trim()).filter(s => s.length < 100).slice(0, 10);
        if (info.services.length > 0) break;
      }
    }
    
    // Founded / years in business
    const foundedMatch = bodyText.match(/(?:founded|established|since|in business)[\s:]*((?:19|20)\d{2})/i);
    if (foundedMatch) {
      info.founded = parseInt(foundedMatch[1]);
    }
    
    // Employee count hints
    const employeeMatch = bodyText.match(/(?:team of|staff of|over)\s*(\d+)(?:\+)?\s*(?:employees|staff|team members|professionals)/i);
    if (employeeMatch) {
      info.employeeCount = parseInt(employeeMatch[1]);
    }
    
    // Reviews / testimonials
    info.hasReviews = !!document.querySelector('[class*="review"], [itemprop="review"], .rating, .stars');
    info.hasTestimonials = !!document.querySelector('[class*="testimonial"], .quote, blockquote');
    
    // Under construction
    info.isUnderConstruction = 
      bodyText.toLowerCase().includes('under construction') ||
      bodyText.toLowerCase().includes('coming soon') ||
      bodyText.toLowerCase().includes('website under') ||
      !!document.querySelector('.coming-soon, .under-construction, [class*="maintenance"]');
    
    return info;
  });
}

/**
 * Check for broken links
 */
async function checkBrokenLinks(page, baseUrl) {
  const links = await page.evaluate(() => {
    return Array.from(document.querySelectorAll('a[href]')).map(a => ({
      href: a.href,
      text: a.innerText.trim().slice(0, 50),
      internal: a.hostname === window.location.hostname
    })).filter(l => l.href && !l.href.startsWith('javascript:') && !l.href.startsWith('mailto:') && !l.href.startsWith('tel:'));
  });
  
  const broken = [];
  const checked = new Set();
  const requestContext = page.context().request;
  
  // Only check first 30 links to avoid timeout
  for (const link of links.slice(0, 30)) {
    if (checked.has(link.href)) continue;
    checked.add(link.href);
    
    try {
      const response = await requestContext.fetch(link.href, {
        method: 'GET',
        timeout: 10000,
        failOnStatusCode: false,
        maxRedirects: 5,
      });
      
      if (response && response.status() >= 400) {
        broken.push({
          url: link.href,
          text: link.text,
          status: response.status(),
          internal: link.internal
        });
      }
    } catch (e) {
      // Only promote explicit network failures, not slow navigations.
      const errorMessage = e.message || String(e);
      const isLikelyNetworkFailure =
        /ERR_NAME_NOT_RESOLVED|ECONNREFUSED|ENOTFOUND|ERR_CONNECTION|ERR_CERT|ETIMEDOUT/i.test(errorMessage);
      if (link.internal && isLikelyNetworkFailure) {
        broken.push({
          url: link.href,
          text: link.text,
          status: 0,
          error: errorMessage,
          internal: link.internal
        });
      }
    }
  }
  
  return {
    checked: links.length,
    broken: broken,
    internal: broken.filter(b => b.internal),
    external: broken.filter(b => !b.internal)
  };
}

/**
 * ============================================
 * LEAD INTELLIGENCE EXTRACTION FUNCTIONS
 * ============================================
 */

/**
 * Detect e-commerce platform and capabilities
 */
async function detectEcommerce(page) {
  return await page.evaluate(() => {
    const result = {
      detected: false,
      platform: null,
      hasCart: false,
      hasCheckout: false,
      products: 0,
      paymentMethods: [],
      confidence: 'low'
    };

    // Platform detection patterns
    const platformSignals = {
      shopify: {
        patterns: [
          'Shopify',
          'shopify',
          'cdn.shopify.com',
          'myshopify.com',
          'Shopify.theme',
          'window.Shopify'
        ],
        weight: 0
      },
      woocommerce: {
        patterns: [
          'woocommerce',
          'wc-add-to-cart',
          'wc-block',
          '/wp-content/plugins/woocommerce',
          'wc-store',
          'wc-blocks'
        ],
        weight: 0
      },
      magento: {
        patterns: [
          'Magento',
          'magento',
          '/mage/',
          'Mage.Cookies',
          'Magento_'
        ],
        weight: 0
      },
      bigcommerce: {
        patterns: [
          'BigCommerce',
          'bigcommerce',
          'cdn11.bigcommerce.com',
          'BCData'
        ],
        weight: 0
      },
      squarespace_commerce: {
        patterns: [
          'squarespace',
          'static.squarespace.com',
          'sqs-block-commerce'
        ],
        weight: 0
      },
      wix_stores: {
        patterns: [
          'wix.com',
          'wixstores',
          'wix-code',
          '_wix_browser_sess'
        ],
        weight: 0
      },
      ecwid: {
        patterns: [
          'ecwid',
          'ecwid-storefront'
        ],
        weight: 0
      },
      shopware: {
        patterns: [
          'shopware',
          'Shopware'
        ],
        weight: 0
      }
    };

    const html = document.documentElement.outerHTML;
    const scripts = Array.from(document.querySelectorAll('script')).map(s => s.src).join(' ');
    const fullContent = html + ' ' + scripts;

    // Check each platform
    for (const [platform, data] of Object.entries(platformSignals)) {
      for (const pattern of data.patterns) {
        if (fullContent.includes(pattern)) {
          data.weight++;
        }
      }
      if (data.weight >= 2) {
        result.detected = true;
        result.platform = platform;
        result.confidence = data.weight >= 3 ? 'high' : 'medium';
        break;
      }
    }

    // Detect cart functionality
    const cartIndicators = [
      '[class*="cart"]',
      '[id*="cart"]',
      '.shopping-cart',
      '.mini-cart',
      '[data-cart]',
      'a[href*="cart"]',
      'a[href*="checkout"]',
      '.add-to-cart',
      '[data-add-to-cart]'
    ];

    for (const selector of cartIndicators) {
      if (document.querySelector(selector)) {
        result.hasCart = true;
        break;
      }
    }

    // Detect checkout
    const checkoutIndicators = [
      'form[action*="checkout"]',
      'a[href*="checkout"]',
      '[class*="checkout"]',
      '[id*="checkout"]',
      '.checkout-button',
      '[data-checkout]'
    ];

    for (const selector of checkoutIndicators) {
      if (document.querySelector(selector)) {
        result.hasCheckout = true;
        break;
      }
    }

    // Count products
    const productSelectors = [
      '.product',
      '[class*="product-item"]',
      '[class*="product-card"]',
      '.woocommerce-product',
      '.shopify-product',
      '[data-product-id]'
    ];

    for (const selector of productSelectors) {
      const products = document.querySelectorAll(selector);
      if (products.length > result.products) {
        result.products = products.length;
      }
    }

    // Detect payment methods
    const paymentPatterns = {
      stripe: ['stripe', 'Stripe'],
      paypal: ['paypal', 'PayPal', 'paypay'],
      applepay: ['apple-pay', 'Apple Pay'],
      googlepay: ['google-pay', 'Google Pay', 'gpay'],
      afterpay: ['afterpay', 'Afterpay'],
      klarna: ['klarna', 'Klarna'],
      affirm: ['affirm', 'Affirm'],
      square: ['square', 'Square'],
      venmo: ['venmo', 'Venmo']
    };

    for (const [method, patterns] of Object.entries(paymentPatterns)) {
      for (const pattern of patterns) {
        if (fullContent.includes(pattern)) {
          result.paymentMethods.push(method);
          break;
        }
      }
    }

    return result;
  });
}

/**
 * Extract social media profiles with follower counts when available
 */
async function extractSocialProfiles(page, baseUrl) {
  const result = {
    linkedin: null,
    facebook: null,
    instagram: null,
    twitter: null,
    youtube: null,
    tiktok: null,
    yelp: null,
    gmb: null,
    other: []
  };

  try {
    const socialData = await page.evaluate(() => {
      const profiles = {};
      const links = Array.from(document.querySelectorAll('a[href]'));
      const pageHost = window.location.hostname.toLowerCase();
      const vendorSocialHandles = new Set(['wix', 'wix-com', 'wixstudio', 'shopify', 'wordpress', 'elementor', 'angi', 'angi_home']);
      const vendorSocialUrls = [
        'facebook.com/wix',
        'linkedin.com/company/wix-com',
        'instagram.com/wix',
        'twitter.com/wix',
        'x.com/wix',
        'youtube.com/wix',
        'tiktok.com/@wix',
        'facebook.com/angi',
        'instagram.com/angi',
        'x.com/angi_home',
        'youtube.com/channel/uczcjolzxhdi6vu77vi2cndg'
      ];
      const cleanUrl = (value) => {
        try {
          const parsed = new URL(value);
          return parsed.toString().split('?')[0].replace(/\/$/, '');
        } catch {
          return null;
        }
      };
      const isGenericSocial = (platform, value) => {
        try {
          const parsed = new URL(value);
          const path = parsed.pathname.toLowerCase();
          if (platform === 'facebook') {
            return /(^|\/)profile\.php$/.test(path) || path === '/' || path === '';
          }
          if (platform === 'instagram') {
            return path === '/' || path === '';
          }
          if (platform === 'twitter') {
            return path === '/' || path === '' || /\/(home|search|explore|intent)\b/.test(path);
          }
          if (platform === 'youtube') {
            return path === '/' || path === '' || /\.js$/i.test(path);
          }
          if (platform === 'yelp') {
            return path === '/' || path === '' || path.startsWith('/search');
          }
          return false;
        } catch {
          return true;
        }
      };
      const hasExpectedSocialHost = (platform, value) => {
        try {
          const parsed = new URL(value);
          const host = parsed.hostname.toLowerCase();
          const hostChecks = {
            linkedin: ['linkedin.com'],
            facebook: ['facebook.com', 'fb.com'],
            instagram: ['instagram.com', 'instagr.am'],
            twitter: ['twitter.com', 'x.com'],
            youtube: ['youtube.com', 'youtu.be'],
            tiktok: ['tiktok.com'],
            yelp: ['yelp.com'],
            gmb: ['google.com', 'maps.google.com', 'g.page']
          };
          const allowedHosts = hostChecks[platform] || [];
          return allowedHosts.some((candidate) => host === candidate || host.endsWith(`.${candidate}`));
        } catch {
          return false;
        }
      };
      const isVendorSocialLink = (platform, linkEl, value) => {
        try {
          const parsed = new URL(value);
          const normalizedValue = value.toLowerCase();
          const pathParts = parsed.pathname.toLowerCase().split('/').filter(Boolean);
          const handle = pathParts[pathParts.length - 1] || '';
          const label = [
            linkEl?.textContent || '',
            linkEl?.getAttribute?.('aria-label') || '',
            linkEl?.getAttribute?.('title') || '',
            linkEl?.className || ''
          ].join(' ').toLowerCase();
          const allSegments = new Set(pathParts);

          if (vendorSocialUrls.some((snippet) => normalizedValue.includes(snippet))) return true;
          if (vendorSocialHandles.has(handle)) return true;
          if ([...allSegments].some((segment) => vendorSocialHandles.has(segment))) return true;
          if (/\b(?:powered by wix|wix|website builder|create your website|made with wix|angi)\b/.test(label)) {
            return true;
          }
          if (pageHost.endsWith('wixsite.com') && /\b(?:wix|powered by wix)\b/.test(label)) {
            return true;
          }
          if (pageHost.endsWith('angi.com') && /\/companylist\//.test(window.location.pathname.toLowerCase()) && /\bangi\b/.test(label)) {
            return true;
          }
          return false;
        } catch {
          return false;
        }
      };
      
      const patterns = {
        linkedin: /(?:linkedin\.com\/(?:company|in|school)\/|linkedin\.com\/companies\/)([^\/\?]+)/i,
        facebook: /(?:facebook\.com|fb\.com)\/(?:pages\/)?([^\/\?]+)(?!.*\/posts\/)/i,
        instagram: /(?:instagram\.com|instagr\.am)\/([^\/\?]+)(?!.*\/p\/)/i,
        twitter: /(?:twitter\.com|x\.com)\/([^\/\?]+)/i,
        youtube: /(?:youtube\.com\/(?:channel|user|c)\/|youtu\.be\/)([^\/\?]+)/i,
        tiktok: /(?:tiktok\.com)\/@?([^\/\?]+)/i,
        yelp: /yelp\.com\/biz\/([^\/\?]+)/i,
        gmb: /maps\.google\.com\/maps\?[^"]*cid=(\d+)/i
      };

      for (const [platform, regex] of Object.entries(patterns)) {
        for (const link of links) {
          const href = link.href;
          const match = href.match(regex);
          if (match && match[1] && !href.includes('share') && !href.includes('intent')) {
            const normalized = cleanUrl(href);
            if (
              !normalized ||
              !hasExpectedSocialHost(platform, normalized) ||
              isGenericSocial(platform, normalized) ||
              isVendorSocialLink(platform, link, normalized)
            ) {
              continue;
            }
            profiles[platform] = {
              url: normalized,
              handle: match[1],
              linkText: link.textContent?.trim() || null
            };
            break;
          }
        }
      }

      return profiles;
    });

    Object.assign(result, socialData);
  } catch (e) {
    console.error(`[LEAD-INT] Social extraction error: ${e.message}`);
  }

  return result;
}

/**
 * Detect team information and employee count indicators
 */
async function detectTeamInfo(page, baseUrl) {
  const result = {
    hasTeamPage: false,
    teamPageUrl: null,
    employeeCount: null,
    keyPeople: [],
    teamPageLinks: []
  };

  try {
    // Look for team/about pages
    const teamData = await page.evaluate(() => {
      const data = {
        hasTeamPage: false,
        teamPageUrl: null,
        employeeCount: null,
        keyPeople: [],
        teamPageLinks: []
      };
      const currentHost = window.location.hostname.toLowerCase();
      const socialHosts = ['facebook.com', 'instagram.com', 'linkedin.com', 'x.com', 'twitter.com', 'youtube.com', 'tiktok.com'];
      const scoreTeamLink = (href, text) => {
        let parsed;
        try {
          parsed = new URL(href, window.location.origin);
        } catch {
          return -1;
        }

        const host = parsed.hostname.toLowerCase();
        const path = parsed.pathname.toLowerCase();
        const textLower = (text || '').toLowerCase();

        if (!/^https?:$/.test(parsed.protocol)) return -1;
        if (host !== currentHost) return -1;
        if (socialHosts.some((socialHost) => host.includes(socialHost))) return -1;
        if (path === '/' || path === '') return -1;

        let score = 0;
        const strongTeamPath = /\/(team|our-team|staff|leadership|people|meet-the-team)(\/|$)/i.test(path);
        const genericAboutPath = /\/(about-us|about|company|management)(\/|$)/i.test(path);
        const strongTeamText = /(team|staff|leadership|people|meet the team)/i.test(textLower);

        if (strongTeamPath) score += 5;
        if (genericAboutPath) score += 1;
        if (strongTeamText) score += 4;
        if (/(about us|company)/i.test(textLower)) score += 1;

        if (genericAboutPath && !strongTeamPath && !strongTeamText) {
          score -= 3;
        }

        return score;
      };

      const teamLinkPatterns = [
        /\/about[-_]?us/i,
        /\/team/i,
        /\/our[-_]?team/i,
        /\/staff/i,
        /\/people/i,
        /\/meet[-_]?the[-_]?team/i,
        /\/leadership/i,
        /\/management/i,
        /\/company/i
      ];

      const links = Array.from(document.querySelectorAll('a[href]'));
      const candidates = [];
      for (const link of links) {
        const href = link.href;
        const text = link.textContent?.toLowerCase() || '';
        
        for (const pattern of teamLinkPatterns) {
          if (pattern.test(href) || pattern.test(text)) {
            const score = scoreTeamLink(href, link.textContent || '');
            if (score < 4) {
              break;
            }
            candidates.push({
              url: href,
              text: link.textContent?.trim(),
              score
            });
            break;
          }
        }
      }

      candidates.sort((a, b) => b.score - a.score);
      data.teamPageLinks = candidates.map(({ url, text }) => ({ url, text }));
      if (candidates.length > 0) {
        data.hasTeamPage = true;
        data.teamPageUrl = candidates[0].url;
      }

      // Look for employee count indicators on current page
      const bodyText = document.body.innerText;
      
      // Employee count patterns
      const employeePatterns = [
        /(\d+)\+?\s*(?:employees?|team members?|staff)/i,
        /team of (\d+)/i,
        /(\d+)\s*people/i,
        /employing over (\d+)/i
      ];

      for (const pattern of employeePatterns) {
        const match = bodyText.match(pattern);
        if (match) {
          data.employeeCount = parseInt(match[1]);
          break;
        }
      }

      // Extract key people (CEO, founder, etc.)
      const peoplePatterns = [
        /(?:CEO|Chief Executive Officer)[:\s]+([A-Z][a-z]+ [A-Z][a-z]+)/g,
        /(?:Founder|Co-Founder)[:\s]+([A-Z][a-z]+ [A-Z][a-z]+)/g,
        /(?:Owner|President|Director)[:\s]+([A-Z][a-z]+ [A-Z][a-z]+)/g
      ];

      for (const pattern of peoplePatterns) {
        let match;
        while ((match = pattern.exec(bodyText)) !== null) {
          if (!data.keyPeople.includes(match[1])) {
            data.keyPeople.push({
              name: match[1],
              title: match[0].split(':')[0].trim()
            });
          }
        }
      }

      // Also check meta tags for founder/author
      const authorMeta = document.querySelector('meta[name="author"]');
      if (authorMeta) {
        const author = authorMeta.content;
        if (author && !data.keyPeople.find(p => p.name === author)) {
          data.keyPeople.push({ name: author, title: 'Author' });
        }
      }

      return data;
    });

    Object.assign(result, teamData);
  } catch (e) {
    console.error(`[LEAD-INT] Team detection error: ${e.message}`);
  }

  return result;
}

/**
 * Detect growth signals (hiring, expansion, funding)
 */
async function detectGrowthSignals(page, baseUrl) {
  const result = {
    hiring: false,
    jobListings: [],
    expansion: false,
    expansionSignals: [],
    fundingStage: null,
    lastUpdated: null
  };

  try {
    const growthData = await page.evaluate(() => {
      const data = {
        hiring: false,
        jobListings: [],
        expansion: false,
        expansionSignals: [],
        fundingStage: null
      };

      const bodyText = document.body.innerText.toLowerCase();
      const html = document.documentElement.outerHTML.toLowerCase();

      // Hiring detection
      const hiringKeywords = [
        'we\'re hiring', 'we are hiring', 'join our team', 'join the team',
        'now hiring', 'careers', 'job opening', 'job opportunity',
        'open position', 'current opening', 'apply now'
      ];

      for (const keyword of hiringKeywords) {
        if (bodyText.includes(keyword)) {
          data.hiring = true;
          break;
        }
      }

      // Look for careers/job links
      const jobLinkPatterns = [
        /\/careers?/i,
        /\/jobs?/i,
        /\/join[-_]?us/i,
        /\/work[-_]?with[-_]?us/i,
        /\/employment/i
      ];

      const links = Array.from(document.querySelectorAll('a[href]'));
      for (const link of links) {
        const href = link.href;
        for (const pattern of jobLinkPatterns) {
          if (pattern.test(href)) {
            data.hiring = true;
            data.jobListings.push({
              url: href,
              text: link.textContent?.trim() || 'Careers page'
            });
            break;
          }
        }
      }

      // Expansion signals
      const expansionKeywords = [
        'new location', 'expanding', 'expansion', 'now open',
        'opening soon', 'grand opening', 'new office', 'new store',
        'coming soon', 'new branch'
      ];

      for (const keyword of expansionKeywords) {
        if (bodyText.includes(keyword)) {
          data.expansion = true;
          data.expansionSignals.push(keyword);
        }
      }

      // Funding stage indicators
      const fundingPatterns = [
        { pattern: /series [a-d]/i, stage: 'venture funded' },
        { pattern: /seed funding|seed round/i, stage: 'seed' },
        { pattern: /series a/i, stage: 'Series A' },
        { pattern: /series b/i, stage: 'Series B' },
        { pattern: /series c/i, stage: 'Series C' },
        { pattern: /angel investment|angel investor/i, stage: 'angel' },
        { pattern: /venture capital|vc backed/i, stage: 'venture funded' }
      ];

      for (const { pattern, stage } of fundingPatterns) {
        if (bodyText.match(pattern)) {
          data.fundingStage = stage;
          break;
        }
      }

      return data;
    });

    Object.assign(result, growthData);
  } catch (e) {
    console.error(`[LEAD-INT] Growth detection error: ${e.message}`);
  }

  return result;
}

/**
 * Detect reputation signals (reviews, ratings)
 */
async function detectReputation(page, baseUrl) {
  const result = {
    hasReviews: false,
    reviewPlatforms: [],
    rating: null,
    reviewCount: 0,
    hasTestimonials: false,
    testimonialCount: 0
  };

  try {
    const repData = await page.evaluate(() => {
      const data = {
        hasReviews: false,
        reviewPlatforms: [],
        rating: null,
        reviewCount: 0,
        hasTestimonials: false,
        testimonialCount: 0
      };

      const html = document.documentElement.outerHTML;
      const bodyText = document.body.innerText;

      // Check for testimonial sections
      const testimonialSelectors = [
        '.testimonial',
        '[class*="testimonial"]',
        '.review',
        '[class*="review"]',
        '.customer-quote',
        '[class*="customer-story"]',
        '.client-feedback'
      ];

      for (const selector of testimonialSelectors) {
        const elements = document.querySelectorAll(selector);
        if (elements.length > 0) {
          data.hasTestimonials = true;
          data.testimonialCount = Math.max(data.testimonialCount, elements.length);
        }
      }

      // Look for review platform integrations
      const reviewPlatformPatterns = [
        { name: 'Google', pattern: /google.*review|reviewed on google/i },
        { name: 'Yelp', pattern: /yelp.*review|reviewed on yelp/i },
        { name: 'Facebook', pattern: /facebook.*review|fb.*review/i },
        { name: 'TrustPilot', pattern: /trustpilot|trust pilot/i },
        { name: 'BBB', pattern: /better business bureau|bbb\.org/i },
        { name: 'Glassdoor', pattern: /glassdoor/i },
        { name: 'G2', pattern: /g2\.com|g2 crowd/i },
        { name: 'Capterra', pattern: /capterra/i },
        { name: 'Clutch', pattern: /clutch\.co/i },
        { name: 'Houzz', pattern: /houzz/i },
        { name: 'Angi', pattern: /angi|angieslist/i },
        { name: 'HomeAdvisor', pattern: /homeadvisor/i }
      ];

      for (const { name, pattern } of reviewPlatformPatterns) {
        if (pattern.test(html)) {
          data.hasReviews = true;
          data.reviewPlatforms.push(name);
        }
      }

      // Extract star rating if visible
      const starSelectors = [
        '.star-rating',
        '[class*="star-rating"]',
        '.rating',
        '[class*="rating"]',
        '[itemprop="ratingValue"]',
        '[data-rating]'
      ];

      for (const selector of starSelectors) {
        const el = document.querySelector(selector);
        if (el) {
          const text = el.textContent || el.getAttribute('data-rating') || '';
          const ratingMatch = text.match(/(\d(?:\.\d)?)\s*(?:out of|\/)\s*5|(\d(?:\.\d)?)\s*stars?/i);
          if (ratingMatch) {
            data.rating = parseFloat(ratingMatch[1] || ratingMatch[2]);
            break;
          }
          // Check for filled stars
          const filledStars = el.querySelectorAll('[class*="filled"], [class*="active"], [class*="on"]');
          if (filledStars.length > 0 && filledStars.length <= 5) {
            data.rating = filledStars.length;
            break;
          }
        }
      }

      // Count reviews
      const reviewCountMatch = bodyText.match(/(\d[\d,]*)\s*reviews?/i);
      if (reviewCountMatch) {
        data.reviewCount = parseInt(reviewCountMatch[1].replace(/,/g, ''));
        data.hasReviews = true;
      }

      return data;
    });

    Object.assign(result, repData);
  } catch (e) {
    console.error(`[LEAD-INT] Reputation detection error: ${e.message}`);
  }

  return result;
}

/**
 * Detect newsletter/email signup
 */
async function detectNewsletter(page) {
  const result = {
    detected: false,
    provider: null,
    formUrl: null
  };

  try {
    const newsletterData = await page.evaluate(() => {
      const data = {
        detected: false,
        provider: null,
        formUrl: null
      };

      const html = document.documentElement.outerHTML.toLowerCase();

      // Newsletter keywords
      const newsletterKeywords = [
        'newsletter',
        'subscribe',
        'mailing list',
        'email list',
        'stay updated',
        'stay in touch',
        'get updates',
        'sign up'
      ];

      // Check for newsletter forms
      const forms = document.querySelectorAll('form');
      const emailInputs = document.querySelectorAll('input[type="email"], input[name*="email"]');

      for (const form of forms) {
        const formText = form.textContent?.toLowerCase() || '';
        const formHtml = form.outerHTML.toLowerCase();

        // Check if form has email input and newsletter keywords
        const hasEmailInput = form.querySelector('input[type="email"], input[name*="email"]');
        
        for (const keyword of newsletterKeywords) {
          if ((formText.includes(keyword) || formHtml.includes(keyword)) && hasEmailInput) {
            data.detected = true;
            data.formUrl = form.action || null;
            break;
          }
        }
        if (data.detected) break;
      }

      // Check for email input near newsletter keywords (not in form)
      if (!data.detected && emailInputs.length > 0) {
        const bodyText = document.body.innerText.toLowerCase();
        for (const keyword of newsletterKeywords) {
          if (bodyText.includes(keyword)) {
            data.detected = true;
            break;
          }
        }
      }

      // Detect provider
      const providerPatterns = [
        { name: 'Mailchimp', pattern: /mailchimp|mc\.us\d+\.list-manage|campaign-archive/i },
        { name: 'ConvertKit', pattern: /convertkit|ck\.page/i },
        { name: 'Klaviyo', pattern: /klaviyo|klaviyo\.com/i },
        { name: 'Constant Contact', pattern: /constantcontact|ctct/i },
        { name: 'AWeber', pattern: /aweber/i },
        { name: 'GetResponse', pattern: /getresponse/i },
        { name: 'ActiveCampaign', pattern: /activecampaign/i },
        { name: 'HubSpot', pattern: /hubspot|hubs\.ly/i },
        { name: 'Beehiiv', pattern: /beehiiv/i },
        { name: 'Substack', pattern: /substack/i },
        { name: 'Buttondown', pattern: /buttondown/i }
      ];

      for (const { name, pattern } of providerPatterns) {
        if (pattern.test(html)) {
          data.provider = name;
          break;
        }
      }

      return data;
    });

    Object.assign(result, newsletterData);
  } catch (e) {
    console.error(`[LEAD-INT] Newsletter detection error: ${e.message}`);
  }

  return result;
}

/**
 * Estimate years in business
 */
async function estimateYearsInBusiness(page) {
  const result = {
    estimated: null,
    source: null,
    foundedYear: null
  };

  try {
    const yearsData = await page.evaluate(() => {
      const data = {
        estimated: null,
        source: null,
        foundedYear: null
      };

      const bodyText = document.body.innerText;
      const currentYear = new Date().getFullYear();

      // Look for founding year patterns
      const foundingPatterns = [
        /(?:founded|established|since|in business since)\s*(\d{4})/i,
        /(\d{4)\s*(?:founded|established)/i,
        /over (\d+)\s*(?:years?|decades?)\s*(?:in business|of experience|serving)/i,
        /serving.*for (\d+)\s*years?/i,
        /(\d+)\+?\s*years?\s*(?:in business|of experience|serving)/i
      ];

      for (const pattern of foundingPatterns) {
        const match = bodyText.match(pattern);
        if (match) {
          const num = parseInt(match[1]);
          // If it's a year (1900-current)
          if (num >= 1900 && num <= currentYear) {
            data.foundedYear = num;
            data.estimated = currentYear - num;
            data.source = 'Founded year mentioned';
          } else if (num > 0 && num < 200) {
            // It's years in business
            data.estimated = num;
            data.foundedYear = currentYear - num;
            data.source = 'Years mentioned';
          }
          if (data.estimated) break;
        }
      }

      // Check copyright footer for earliest year
      if (!data.estimated) {
        const copyrightMatch = bodyText.match(/copyright\s*©?\s*(\d{4})(?:\s*[-–]\s*(\d{4}))?/i);
        if (copyrightMatch) {
          const startYear = parseInt(copyrightMatch[1]);
          if (startYear >= 1990 && startYear < currentYear) {
            data.foundedYear = startYear;
            data.estimated = currentYear - startYear;
            data.source = 'Copyright year (estimate)';
          }
        }
      }

      // Check meta tags
      const dateCreated = document.querySelector('meta[property="article:published_time"], meta[name="date"]');
      if (dateCreated && !data.estimated) {
        const date = new Date(dateCreated.content);
        if (!isNaN(date.getTime())) {
          const year = date.getFullYear();
          if (year >= 1990 && year < currentYear) {
            data.foundedYear = year;
            data.estimated = currentYear - year;
            data.source = 'Meta date (estimate)';
          }
        }
      }

      return data;
    });

    Object.assign(result, yearsData);
  } catch (e) {
    console.error(`[LEAD-INT] Years estimation error: ${e.message}`);
  }

  return result;
}

/**
 * Classify industry
 */
async function classifyIndustry(page) {
  const result = {
    primary: null,
    secondary: [],
    naics: null
  };

  try {
    const industryData = await page.evaluate(() => {
      const data = {
        primary: null,
        secondary: [],
        naics: null
      };

      // Industry keywords mapping
      const industryPatterns = [
        { industry: 'Construction', keywords: ['construction', 'contractor', 'builder', 'building', 'renovation', 'remodeling'] },
        { industry: 'Manufacturing', keywords: ['manufacturing', 'manufacturer', 'fabrication', 'industrial', 'production'] },
        { industry: 'Healthcare', keywords: ['healthcare', 'medical', 'hospital', 'clinic', 'health', 'dental', 'physician', 'doctor'] },
        { industry: 'Technology', keywords: ['software', 'technology', 'it services', 'saas', 'tech', 'digital', 'cyber'] },
        { industry: 'Retail', keywords: ['retail', 'store', 'shop', 'e-commerce', 'ecommerce', 'shopify'] },
        { industry: 'Restaurant/Food Service', keywords: ['restaurant', 'food', 'cafe', 'catering', 'bakery', 'bar', 'dining'] },
        { industry: 'Automotive', keywords: ['automotive', 'auto', 'car', 'vehicle', 'mechanic', 'dealership'] },
        { industry: 'Real Estate', keywords: ['real estate', 'realtor', 'property', 'housing', 'brokerage'] },
        { industry: 'Legal Services', keywords: ['law', 'legal', 'attorney', 'lawyer', 'law firm'] },
        { industry: 'Financial Services', keywords: ['financial', 'banking', 'accounting', 'cpa', 'tax', 'insurance'] },
        { industry: 'Education', keywords: ['education', 'school', 'training', 'academy', 'learning', 'university'] },
        { industry: 'Hospitality', keywords: ['hotel', 'hospitality', 'resort', 'lodging', 'travel'] },
        { industry: 'Professional Services', keywords: ['consulting', 'professional services', 'agency', 'firm'] },
        { industry: 'Energy/Utilities', keywords: ['energy', 'oil', 'gas', 'solar', 'utilities', 'power'] },
        { industry: 'Transportation/Logistics', keywords: ['transportation', 'logistics', 'shipping', 'freight', 'trucking'] },
        { industry: 'Agriculture', keywords: ['agriculture', 'farming', 'farm', 'agricultural'] },
        { industry: 'Nonprofit', keywords: ['nonprofit', 'non-profit', 'charity', 'foundation', 'organization'] }
      ];

      const bodyText = document.body.innerText.toLowerCase();
      const matches = [];

      for (const { industry, keywords } of industryPatterns) {
        let matchCount = 0;
        for (const keyword of keywords) {
          const regex = new RegExp(`\\b${keyword}\\b`, 'gi');
          const matchesFound = bodyText.match(regex);
          if (matchesFound) {
            matchCount += matchesFound.length;
          }
        }
        if (matchCount > 0) {
          matches.push({ industry, count: matchCount });
        }
      }

      // Sort by match count
      matches.sort((a, b) => b.count - a.count);

      if (matches.length > 0) {
        data.primary = matches[0].industry;
        data.secondary = matches.slice(1, 3).map(m => m.industry);
      }

      return data;
    });

    Object.assign(result, industryData);
  } catch (e) {
    console.error(`[LEAD-INT] Industry classification error: ${e.message}`);
  }

  return result;
}

/**
 * Detect service area / geographic reach
 */
async function detectServiceArea(page) {
  const result = {
    type: null,
    regions: [],
    hasServiceAreaPage: false
  };

  try {
    const areaData = await page.evaluate(() => {
      const data = {
        type: null,
        regions: [],
        hasServiceAreaPage: false
      };

      const bodyText = document.body.innerText;
      const html = document.documentElement.outerHTML;

      // Look for service area pages
      const serviceAreaPatterns = [
        /\/service[-_]?area/i,
        /\/areas[-_]?we[-_]?serve/i,
        /\/locations/i,
        /\/service[-_]?location/i
      ];

      const links = Array.from(document.querySelectorAll('a[href]'));
      for (const link of links) {
        const href = link.href;
        for (const pattern of serviceAreaPatterns) {
          if (pattern.test(href)) {
            data.hasServiceAreaPage = true;
            break;
          }
        }
      }

      // Detect service area type
      const nationalKeywords = ['nationwide', 'across the country', 'all 50 states', 'nationwide service'];
      const regionalKeywords = ['serving', 'service area', 'areas we serve', 'coverage area'];
      const localKeywords = ['locally owned', 'locally operated', 'your local', 'serving the'];

      const lowerText = bodyText.toLowerCase();

      for (const keyword of nationalKeywords) {
        if (lowerText.includes(keyword)) {
          data.type = 'national';
          break;
        }
      }

      if (!data.type) {
        for (const keyword of regionalKeywords) {
          if (lowerText.includes(keyword)) {
            data.type = 'regional';
            break;
          }
        }
      }

      if (!data.type) {
        for (const keyword of localKeywords) {
          if (lowerText.includes(keyword)) {
            data.type = 'local';
            break;
          }
        }
      }

      // Extract regions/cities mentioned
      const cityPatterns = [
        /serving\s+([A-Z][a-z]+(?:,\s*[A-Z][a-z]+)*)/g,
        /service[s]?\s+(?:the\s+)?([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?(?:,\s*[A-Z][a-z]+)*)/g,
        /locations?\s*(?:in|:)\s*([A-Z][a-z]+(?:,\s*[A-Z][a-z]+)*)/g
      ];

      const foundRegions = new Set();
      for (const pattern of cityPatterns) {
        let match;
        while ((match = pattern.exec(bodyText)) !== null) {
          const cities = match[1].split(',').map(c => c.trim());
          cities.forEach(city => {
            if (city.length > 2 && city.length < 30) {
              foundRegions.add(city);
            }
          });
        }
      }

      data.regions = Array.from(foundRegions).slice(0, 10);

      return data;
    });

    Object.assign(result, areaData);
  } catch (e) {
    console.error(`[LEAD-INT] Service area detection error: ${e.message}`);
  }

  return result;
}

/**
 * Run all lead intelligence extraction
 */
async function extractLeadIntelligence(page, baseUrl) {
  console.error("[LEAD-INT] Starting lead intelligence extraction...");
  
  const intelligence = {
    ecommerce: { detected: false, platform: null, hasCart: false, hasCheckout: false, products: 0, paymentMethods: [] },
    socialProfiles: { linkedin: null, facebook: null, instagram: null, twitter: null, youtube: null, tiktok: null, yelp: null, gmb: null },
    teamInfo: { hasTeamPage: false, teamPageUrl: null, employeeCount: null, keyPeople: [] },
    growthSignals: { hiring: false, jobListings: [], expansion: false, expansionSignals: [], fundingStage: null },
    reputation: { hasReviews: false, reviewPlatforms: [], rating: null, reviewCount: 0, hasTestimonials: false },
    newsletter: { detected: false, provider: null, formUrl: null },
    yearsInBusiness: { estimated: null, source: null, foundedYear: null },
    industryClassification: { primary: null, secondary: [], naics: null },
    serviceArea: { type: null, regions: [], hasServiceAreaPage: false }
  };

  try {
    // E-commerce detection
    console.error("[LEAD-INT] Detecting e-commerce...");
    intelligence.ecommerce = await detectEcommerce(page);

    // Social profiles
    console.error("[LEAD-INT] Extracting social profiles...");
    intelligence.socialProfiles = await extractSocialProfiles(page, baseUrl);

    // Team info
    console.error("[LEAD-INT] Detecting team information...");
    intelligence.teamInfo = await detectTeamInfo(page, baseUrl);

    // Growth signals
    console.error("[LEAD-INT] Detecting growth signals...");
    intelligence.growthSignals = await detectGrowthSignals(page, baseUrl);

    // Reputation
    console.error("[LEAD-INT] Analyzing reputation...");
    intelligence.reputation = await detectReputation(page, baseUrl);

    // Newsletter
    console.error("[LEAD-INT] Detecting newsletter...");
    intelligence.newsletter = await detectNewsletter(page);

    // Years in business
    console.error("[LEAD-INT] Estimating years in business...");
    intelligence.yearsInBusiness = await estimateYearsInBusiness(page);

    // Industry classification
    console.error("[LEAD-INT] Classifying industry...");
    intelligence.industryClassification = await classifyIndustry(page);

    // Service area
    console.error("[LEAD-INT] Detecting service area...");
    intelligence.serviceArea = await detectServiceArea(page);

  } catch (e) {
    console.error(`[LEAD-INT] Error in lead intelligence extraction: ${e.message}`);
  }

  return intelligence;
}

/**
 * Check for exposed sensitive files and API keys
 * Uses HTTP requests in parallel for speed, with global timeout
 */
async function checkSensitiveExposures(page, baseUrl, normalizedDomain) {
  const exposures = {
    sensitiveFiles: [],
    exposedGit: false,
    exposedEnv: false,
    exposedConfig: false,
    apiKeys: [],
    riskyEndpoints: []
  };
  
  const https = require('https');
  const http = require('http');
  
  // Helper to make HTTP request with timeout
  const fetchUrl = (url, timeoutMs = 3000) => {
    return new Promise((resolve) => {
      const client = url.startsWith('https') ? https : http;
      const req = client.get(url, { timeout: timeoutMs }, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => resolve({ status: res.statusCode, body: data, headers: res.headers }));
      });
      req.on('error', () => resolve(null));
      req.on('timeout', () => { req.destroy(); resolve(null); });
    });
  };
  
  // Check sensitive files in parallel with Promise.allSettled
  const sensitivePaths = Object.keys(SENSITIVE_FILES);
  const fileChecks = sensitivePaths.map(async (filePath) => {
    try {
      const result = await fetchUrl(`${baseUrl}${filePath}`, 3000);
      if (!result || result.status !== 200) return null;
      
      const content = result.body;
      const bodyText = content.toLowerCase();
      
      // Skip if this looks like an HTML page (SPA catch-all or custom 404)
      const isHtmlPage = bodyText.includes('<!doctype') || 
                        bodyText.includes('<html') ||
                        bodyText.includes('<head>') ||
                        bodyText.includes('<body>');
      
      if (isHtmlPage) return null;
      
      // Verify it's actually sensitive content
      const fileConfig = SENSITIVE_FILES[filePath];
      let isSensitive = false;
      
      if (fileConfig.indicators && fileConfig.indicators.length > 0) {
        isSensitive = fileConfig.indicators.some(ind => 
          content.includes(ind) || bodyText.includes(ind.toLowerCase())
        );
      } else if (fileConfig.htpasswd) {
        const htpasswdPattern = /^[a-zA-Z0-9_-]+:\$[apr]?1\$[^\s]+$/m;
        isSensitive = htpasswdPattern.test(content) || 
                      /^[a-zA-Z0-9_-]+:\{SHA\}[a-zA-Z0-9+\/=]+$/m.test(content);
      } else {
        isSensitive = content.length > 10 && content.length < 100000;
      }
      
      if (isSensitive) {
        return {
          path: filePath,
          type: fileConfig.type,
          severity: fileConfig.severity,
          description: fileConfig.description,
          reportOnly: !!fileConfig.reportOnly,
        };
      }
    } catch (e) {}
    return null;
  });
  
  // Wait for all file checks with global timeout
  const fileResults = await Promise.race([
    Promise.allSettled(fileChecks),
    new Promise(resolve => setTimeout(() => resolve([]), 30000)) // 30s global timeout
  ]);
  
  // Process results
  if (Array.isArray(fileResults)) {
    for (const result of fileResults) {
      if (result?.status === 'fulfilled' && result.value) {
        exposures.sensitiveFiles.push(result.value);
        if (result.value.type === 'git') exposures.exposedGit = true;
        if (result.value.type === 'env') exposures.exposedEnv = true;
        if (result.value.type === 'config') exposures.exposedConfig = true;
      }
    }
  }
  
  // Check for API keys in the page source (use current page, no new navigation)
  const pageContent = await page.content();
  exposures.apiKeys = extractApiKeysFromPageContent(pageContent);
  
  // Check for risky endpoints in parallel
  const endpointChecks = RISKY_ENDPOINTS.map(async (endpoint) => {
    try {
      const result = await fetchUrl(`${baseUrl}${endpoint.path}`, 3000);
      if (!result || result.status >= 400 || result.status === 404) return null;
      
      const content = result.body;
      const bodyText = content.toLowerCase();
      let confirmed = false;
      
      // Check for required indicators count
      if (endpoint.indicators && endpoint.requiredCount) {
        const matchCount = endpoint.indicators.filter(ind => bodyText.includes(ind.toLowerCase())).length;
        confirmed = matchCount >= endpoint.requiredCount;
      } else if (endpoint.indicators) {
        confirmed = endpoint.indicators.some(ind => bodyText.includes(ind.toLowerCase()));
      }
      
      // Check for content pattern (regex)
      if (endpoint.contentPattern && !confirmed) {
        confirmed = endpoint.contentPattern.test(content);
      }
      
      // Binary check (for compressed files)
      if (endpoint.binaryCheck && !confirmed) {
        const contentType = result.headers?.['content-type'] || '';
        confirmed = contentType.includes('application/') || contentType.includes('octet-stream');
      }
      
      if (confirmed) {
        return {
          path: endpoint.path,
          type: endpoint.type,
          severity: endpoint.reportOnly ? 'info' : endpoint.severity,
          description: endpoint.description,
          status: result.status,
          reportOnly: endpoint.reportOnly || false,
          endpointType: endpoint.type,
          reportOnly: endpoint.reportOnly
        };
      }
    } catch (e) {}
    return null;
  });
  
  // Wait for all endpoint checks with global timeout
  const endpointResults = await Promise.race([
    Promise.allSettled(endpointChecks),
    new Promise(resolve => setTimeout(() => resolve([]), 15000)) // 15s global timeout
  ]);
  
  // Process results
  if (Array.isArray(endpointResults)) {
    for (const result of endpointResults) {
      if (result?.status === 'fulfilled' && result.value) {
        const ep = result.value;
        if (ep.endpointType === 'git' && !ep.reportOnly) exposures.exposedGit = true;
        if (ep.endpointType === 'env' && !ep.reportOnly) exposures.exposedEnv = true;
        if (ep.endpointType === 'config' && !ep.reportOnly) exposures.exposedConfig = true;
        exposures.riskyEndpoints.push({
          path: ep.path,
          type: ep.type,
          severity: ep.severity,
          description: ep.description,
          status: ep.status,
          reportOnly: ep.reportOnly
        });
      }
    }
  }
  
  return exposures;
}

/**
 * Check robots.txt and sitemap
 */
async function checkSeoFiles(baseUrl) {
  const https = require('https');
  const http = require('http');
  
  const results = {
    robotsTxt: null,
    sitemap: null,
    noIndex: false
  };
  
  // Check robots.txt
  try {
    const robotsContent = await new Promise((resolve, reject) => {
      const req = https.request(`${baseUrl}/robots.txt`, { timeout: 5000 }, (res) => {
        if (res.statusCode === 200) {
          let data = '';
          res.on('data', chunk => data += chunk);
          res.on('end', () => resolve(data));
        } else {
          resolve(null);
        }
      });
      req.on('error', () => resolve(null));
      req.setTimeout(5000, () => { req.destroy(); resolve(null); });
      req.end();
    });
    
    if (robotsContent) {
      results.robotsTxt = {
        exists: true,
        disallowAll: /user-agent:\s*\*\s*disallow:\s*\/\s*$/im.test(robotsContent),
        sitemapUrl: robotsContent.match(/sitemap:\s*(.+)/i)?.[1]?.trim() || null,
        content: robotsContent.split('\n').slice(0, 20).join('\n') // First 20 lines
      };
      
      // Check if sitemap is referenced
      if (results.robotsTxt.sitemapUrl) {
        results.sitemap = { referenced: true, url: results.robotsTxt.sitemapUrl };
      }
    }
  } catch (e) {}
  
  // Check sitemap.xml
  try {
    const sitemapContent = await new Promise((resolve, reject) => {
      const req = https.request(`${baseUrl}/sitemap.xml`, { timeout: 5000 }, (res) => {
        if (res.statusCode === 200) {
          let data = '';
          res.on('data', chunk => data += chunk);
          res.on('end', () => resolve(data));
        } else {
          resolve(null);
        }
      });
      req.on('error', () => resolve(null));
      req.setTimeout(5000, () => { req.destroy(); resolve(null); });
      req.end();
    });
    
    if (sitemapContent) {
      results.sitemap = {
        exists: true,
        referenced: results.sitemap?.referenced || false,
        url: `${baseUrl}/sitemap.xml`,
        urlCount: (sitemapContent.match(/<url>/g) || []).length
      };
    }
  } catch (e) {}
  
  return results;
}

/**
 * Save evidence files to profile evidence folder
 */
function saveEvidence(evidenceDir, result) {
  if (!fs.existsSync(evidenceDir)) {
    fs.mkdirSync(evidenceDir, { recursive: true });
  }
  
  // Save security headers
  const headersPath = path.join(evidenceDir, 'headers.txt');
  const headersContent = Object.entries(result.securityHeaders)
    .map(([k, v]) => `${k}: ${v.present ? v.value || 'present' : 'MISSING'}`)
    .join('\n');
  fs.writeFileSync(headersPath, headersContent, 'utf8');
  
  // Save cookies
  const cookiesPath = path.join(evidenceDir, 'cookies.json');
  fs.writeFileSync(cookiesPath, JSON.stringify(result.cookies, null, 2), 'utf8');

  const cookieSecurityPath = path.join(evidenceDir, 'cookie-security.json');
  fs.writeFileSync(cookieSecurityPath, JSON.stringify(result.cookieSecurity, null, 2), 'utf8');
  
  // Save security findings
  const securityPath = path.join(evidenceDir, 'security-findings.md');
  const securityLines = [];
  securityLines.push(`# Security Findings - ${result.domain}`);
  securityLines.push(`Date: ${result.timestamp}`);
  securityLines.push(``);
  securityLines.push(`## SSL/TLS`);
  securityLines.push(`- Valid: ${result.ssl.valid}`);
  if (result.ssl.issuer) securityLines.push(`- Issuer: ${result.ssl.issuer}`);
  if (result.ssl.authorized !== undefined) securityLines.push(`- Chain trusted: ${result.ssl.authorized}`);
  if (result.ssl.authorizationError) securityLines.push(`- Authorization error: ${result.ssl.authorizationError}`);
  if (result.ssl.hostnameError) securityLines.push(`- Hostname error: ${result.ssl.hostnameError}`);
  if (result.ssl.daysUntilExpiry !== null) securityLines.push(`- Days until expiry: ${result.ssl.daysUntilExpiry}`);
  securityLines.push(``);
  securityLines.push(`## HTTPS`);
  securityLines.push(`- Enabled: ${result.https.enabled}`);
  securityLines.push(`- Redirects: ${result.https.redirects === null ? "unverified" : result.https.redirects}`);
  securityLines.push(``);
  securityLines.push(`## Security Headers`);
  for (const [header, status] of Object.entries(result.securityHeaders)) {
    securityLines.push(`- ${header}: ${status.present ? 'Present' : 'Missing'}`);
  }
  securityLines.push(``);
  securityLines.push(`## Email Auth`);
  securityLines.push(`- SPF: ${result.emailAuth.spf ? 'Present' : 'Missing'}`);
  securityLines.push(`- DMARC: ${result.emailAuth.dmarc ? 'Present' : 'Missing'}`);
  securityLines.push(`- DKIM: ${result.emailAuth.dkim ? `Present (${result.emailAuth.dkim.selector})` : 'Not verified (common selector guess only)'}`);
  securityLines.push(``);
  if (result.sensitiveExposures?.sensitiveFiles?.length > 0) {
    securityLines.push(`## Sensitive Exposures`);
    for (const exp of result.sensitiveExposures.sensitiveFiles) {
      securityLines.push(`- [${exp.severity.toUpperCase()}] ${exp.path}: ${exp.description}`);
    }
  }
  if (result.sensitiveExposures?.apiKeys?.length > 0) {
    securityLines.push(``);
    securityLines.push(`## API Keys Detected`);
    for (const key of result.sensitiveExposures.apiKeys) {
      securityLines.push(`- [${key.severity.toUpperCase()}] ${key.type} (${key.count} found)`);
    }
  }
  if (result.jsErrorAnalysis) {
    securityLines.push(``);
    securityLines.push(`## JavaScript Verification`);
    securityLines.push(`- Clean verification attempted: ${result.jsErrorAnalysis.cleanPass?.attempted ? 'Yes' : 'No'}`);
    securityLines.push(`- Clean verification succeeded: ${result.jsErrorAnalysis.cleanPass?.succeeded ? 'Yes' : 'No'}`);
    securityLines.push(`- Verified page errors: ${result.jsErrorAnalysis.verifiedPageErrors?.length || 0}`);
    securityLines.push(`- Verified console errors: ${result.jsErrorAnalysis.verifiedConsoleErrors?.length || 0}`);
    securityLines.push(`- Filtered scanner-induced patterns: ${(result.jsErrorAnalysis.scannerInducedPageErrors?.length || 0) + (result.jsErrorAnalysis.scannerInducedConsoleErrors?.length || 0)}`);
    securityLines.push(`- Instrumentation-only observations: ${(result.jsErrorAnalysis.provisionalPageErrors?.length || 0) + (result.jsErrorAnalysis.provisionalConsoleErrors?.length || 0)}`);
  }
  if (result.findingConfidence) {
    securityLines.push(``);
    securityLines.push(`## Finding Confidence`);
    const tiers = [
      ['verified', 'Verified'],
      ['probable', 'Probable'],
      ['observedUnderInstrumentation', 'Observed Under Instrumentation'],
      ['unverified', 'Unverified'],
    ];
    for (const [key, label] of tiers) {
      const items = result.findingConfidence[key] || [];
      securityLines.push(`### ${label} (${items.length})`);
      for (const item of items.slice(0, 10)) {
        securityLines.push(`- [${item.severity.toUpperCase()}] ${item.message}`);
      }
    }
  }
  if (result.securityOutreach) {
    securityLines.push(``);
    securityLines.push(`## Outreach-Safe Hooks`);
    securityLines.push(`- Primary Hook: ${result.securityOutreach.primaryHook || 'None selected'}`);
    if ((result.securityOutreach.verifiedHooks || []).length > 0) {
      securityLines.push(`- Verified Hooks: ${result.securityOutreach.verifiedHooks.join(' | ')}`);
    }
    if ((result.securityOutreach.probableHooks || []).length > 0) {
      securityLines.push(`- Probable Hooks: ${result.securityOutreach.probableHooks.join(' | ')}`);
    }
  }
  fs.writeFileSync(securityPath, securityLines.join('\n'), 'utf8');
  
  // Save contacts
  if ((result.contacts?.emails?.length > 0) || (result.contacts?.phones?.length > 0)) {
    const contactsPath = path.join(evidenceDir, 'contacts.json');
    fs.writeFileSync(contactsPath, JSON.stringify(result.contacts, null, 2), 'utf8');
  }
  
  // Save address if found
  if (result.address?.raw || result.address?.street) {
    const addressPath = path.join(evidenceDir, 'address.json');
    fs.writeFileSync(addressPath, JSON.stringify(result.address, null, 2), 'utf8');
  }
  
  // Save business info if found
  if (result.businessInfo?.hours || result.businessInfo?.services?.length > 0) {
    const bizPath = path.join(evidenceDir, 'business-info.json');
    fs.writeFileSync(bizPath, JSON.stringify(result.businessInfo, null, 2), 'utf8');
  }
  
  // Save tech stack if found
  if (result.techStack && (result.techStack.cms || result.techStack.framework || 
      result.techStack.indicators?.length > 0)) {
    const techPath = path.join(evidenceDir, 'tech-stack.json');
    fs.writeFileSync(techPath, JSON.stringify(result.techStack, null, 2), 'utf8');
  }
  
  // Save third-party scripts if found
  if (result.thirdPartyScripts && result.thirdPartyScripts.total > 0) {
    const scriptsPath = path.join(evidenceDir, 'third-party-scripts.json');
    fs.writeFileSync(scriptsPath, JSON.stringify(result.thirdPartyScripts, null, 2), 'utf8');
  }
  
  // Save form analysis if forms found
  if (result.forms && result.forms.totalForms > 0) {
    const formsPath = path.join(evidenceDir, 'forms.json');
    fs.writeFileSync(formsPath, JSON.stringify(result.forms, null, 2), 'utf8');
  }
  
  // Save lead intelligence if found
  if (result.leadIntelligence) {
    const intelPath = path.join(evidenceDir, 'lead-intelligence.json');
    fs.writeFileSync(intelPath, JSON.stringify(result.leadIntelligence, null, 2), 'utf8');
  }

  if (result.enrichment) {
    const enrichmentPath = path.join(evidenceDir, 'enrichment.json');
    fs.writeFileSync(enrichmentPath, JSON.stringify(result.enrichment, null, 2), 'utf8');
  }
  
  return evidenceDir;
}

/**
 * Check for cookie consent / GDPR banner
 */
async function checkCookieConsent(page) {
  return await page.evaluate(() => {
    const consent = {
      detected: false,
      type: null,
      blocked: false
    };
    
    // Common cookie consent selectors
    const consentSelectors = [
      // Generic patterns
      '[class*="cookie-consent"]', '[class*="cookie-banner"]', '[class*="cookie-notice"]',
      '[class*="gdpr"]', '[class*="privacy-banner"]', '[class*="consent-banner"]',
      '[id*="cookie-consent"]', '[id*="cookie-banner"]', '[id*="gdpr"]',
      // Specific providers
      '#onetrust-banner-sdk', '.cc-banner', '#ccc', '#cookie-law-info-bar',
      '[data-testid="cookie-banner"]', '[data-cookie-banner]',
      // EU compliant patterns
      '.cc-window', '.cc-banner', '.cc_float', '#cmplz-cookiebanner',
      // Quantcast
      '.qc-cmp2-container', '[class*="quantcast"]',
      // Cookiebot
      '#CybotCookiebotDialog', '#Cookiebot',
      // OneTrust
      '#onetrust-consent-sdk', '.ot-sdk-container',
      // Didomi
      '#didomi-host', '.didomi-popup'
    ];
    
    for (const selector of consentSelectors) {
      const el = document.querySelector(selector);
      if (el && el.offsetHeight > 0) {
        consent.detected = true;
        
        // Try to identify type
        const className = el.className.toLowerCase();
        const id = el.id.toLowerCase();
        
        if (className.includes('gdpr') || id.includes('gdpr')) consent.type = 'GDPR';
        else if (className.includes('cookie') || id.includes('cookie')) consent.type = 'Cookie';
        else consent.type = 'Unknown';
        
        break;
      }
    }
    
    return consent;
  });
}

/**
 * Main audit function
 */
async function audit() {
  const startTime = Date.now();
  console.error(`[AUDIT] Starting audit for ${normalizedDomain} (Lead ${leadId})`);
  
  let browser;
  let profileTarget = null;
  result._observedConsoleErrors = new Map();
  result._observedConsoleWarnings = new Map();
  result._observedPageErrors = new Map();
  try {
    profileTarget = ensureProfileTarget(profileRange, leadId, normalizedDomain);

    // Launch with detection-aware settings to avoid bot detection
    browser = await chromium.launch({ 
      headless: true,
      args: [
        '--disable-blink-features=AutomationControlled',
        '--disable-features=IsolateOrigins,site-per-process',
        '--disable-site-isolation-trials',
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-web-security',
        '--disable-features=VizDisplayCompositor',
      ]
    });
    
    // --- EARLY Site Availability Check (BEFORE browser launch) ---
    // This helps us distinguish between "site truly down" vs "bot blocking"
    // and allows us to adjust browser strategy accordingly
    console.error("[AUDIT] Checking site availability (early detection for bot blocking)...");
    const earlyAvailability = await checkSiteAvailability(normalizedDomain);
    result.siteAvailability = earlyAvailability;
    console.error(`[AUDIT] Early availability: ${JSON.stringify(earlyAvailability)}`);
    
    // If site is completely unreachable (DNS fails), skip browser entirely
    let skipBrowser = false;
    let browserTimeout = 60000; // Default 60s
    let userAgentOverride = null;
    
    if (!earlyAvailability.reachable && earlyAvailability.method === 'dns') {
      console.error("[AUDIT] DNS resolution failed - site does not exist. Skipping browser audit.");
      result.criticalIssues.push("Domain does not resolve (DNS failure)");
      result.renderTimeout = true;
      skipBrowser = true;
    } else if (earlyAvailability.blockerHint) {
      console.error(`[AUDIT] Bot blocker detected: ${earlyAvailability.blockerHint}`);
      // If Googlebot UA worked, use it in the browser
      if (earlyAvailability.method === 'https-googlebot') {
        console.error("[AUDIT] Using Googlebot UA for browser to bypass bot detection...");
        userAgentOverride = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";
        browserTimeout = 45000; // Reduce timeout since we know the site responds
      } else if (earlyAvailability.method === 'https-curl' && earlyAvailability.statusCode === 403) {
        console.error("[AUDIT] Site blocks automated requests. Will try alternative strategies.");
        // Still try browser with enhanced evasion
        browserTimeout = 45000;
      }
    } else if (earlyAvailability.reachable) {
      console.error(`[AUDIT] Site reachable via ${earlyAvailability.method}. Proceeding with browser audit.`);
      // Site is reachable, we can use a shorter timeout
      browserTimeout = 45000;
    }
    
    // --- SSL/TLS Check ---
    console.error("[AUDIT] Checking SSL certificate...");
    result.ssl = await checkSSLCertificate(normalizedDomain);
    
    // --- HTTPS Redirect Check ---
    console.error("[AUDIT] Checking HTTPS redirect...");
    result.https = await checkHTTPSRedirect(normalizedDomain);
    
    // --- Email Auth Check ---
    console.error("[AUDIT] Checking email authentication (SPF/DMARC)...");
    result.emailAuth = await checkEmailAuth(normalizedDomain);
    
    // --- DNS Records ---
    console.error("[AUDIT] Checking DNS records (MX, NS, A)...");
    result.dnsRecords = await getDnsRecords(normalizedDomain);
    
    // --- Desktop Audit with Playwright ---
    let context = null;
    let page = null;
    let response;
    let pageLoadFailed = skipBrowser;
    let usedAlternativeUrl = false;
    let finalUrl = testUrl;
    let effectiveUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36";

    if (skipBrowser) {
      console.error("[AUDIT] Skipping browser audit due to early availability check.");
      await browser.close();
      browser = null;
    } else {
      console.error("[AUDIT] Launching browser for desktop audit...");
      effectiveUserAgent = userAgentOverride || effectiveUserAgent;
      if (userAgentOverride) {
        console.error(`[AUDIT] Using custom User-Agent: ${userAgentOverride.substring(0, 50)}...`);
      }
      context = await browser.newContext({
        viewport: { width: 1920, height: 1080 },
        userAgent: effectiveUserAgent,
        ignoreHTTPSErrors: true,
        // Additional detection-aware settings
        locale: 'en-US',
        timezoneId: 'America/New_York',
        colorScheme: 'light',
      });
      page = await context.newPage();
    
      // Use the light-touch script on the normal path so the audit does not create its own JS breakage.
      await page.addInitScript(LIGHT_HEAVY_DETECTION_BYPASS_SCRIPT);
    
      // Block tracking/analytics scripts to reduce fingerprint surface
      await setupTrackingBlocker(page);
    
      attachErrorObservers(page, {
        consoleErrors: result._observedConsoleErrors,
        consoleWarnings: result._observedConsoleWarnings,
        pageErrors: result._observedPageErrors,
      });
    
      // Collect performance metrics
      const perfTiming = {};
      page.on("requestfinished", async (request) => {
        // Track resource timing if needed
      });
    
      // Navigate to homepage with bot blocker circumvention
      console.error(`[AUDIT] Navigating to ${testUrl}...`);
      const navigationStart = Date.now();
    
    try {
      // First attempt with detection-aware settings
      response = await page.goto(testUrl, {
        waitUntil: "domcontentloaded",
        timeout: browserTimeout,
      });
      
      // Wait for initial page load
      await page.waitForTimeout(2000);
      
      // Check for bot blocker
      const blocker = await detectBotBlocker(page);
      if (blocker.challengeDetected) {
        console.error(`[EVASION] Bot blocker detected: ${JSON.stringify(blocker)}`);
        
        // If Cloudflare, try to wait it out
        if (blocker.cloudflare) {
          const passed = await waitForCloudflareChallenge(page, 20000);
          if (passed) {
            console.error("[EVASION] Cloudflare challenge passed!");
            result.botBlocker = { detected: true, name: 'cloudflare', blocked: false, bypassed: true };
          } else {
            if (hasExplicitPathTarget) {
              console.error("[EVASION] Explicit path target blocked; skipping root URL fallbacks.");
              result.botBlocker = { detected: true, name: 'cloudflare', blocked: true, bypassed: false };
              result.renderTimeout = true;
              result.criticalIssues.push("Site blocked by Cloudflare (explicit path target could not bypass)");
              pageLoadFailed = true;
            } else {
              // Try alternative URLs
              console.error("[EVASION] Cloudflare still blocking, trying alternative URLs...");
              const altResult = await tryAlternativeUrls(page, normalizedDomain, 30000);
              if (altResult.passed) {
                response = altResult.response;
                finalUrl = altResult.url;
                usedAlternativeUrl = true;
                result.botBlocker = { detected: true, name: 'cloudflare', blocked: false, bypassed: true, alternativeUrl: altResult.url };
              } else {
                console.error("[EVASION] All URLs blocked by Cloudflare");
                result.botBlocker = { detected: true, name: 'cloudflare', blocked: true, bypassed: false };
                // Still continue with non-browser tests
                result.renderTimeout = true;
                result.criticalIssues.push("Site blocked by Cloudflare (could not bypass)");
                pageLoadFailed = true;
              }
            }
          }
        } else {
          // Non-Cloudflare blocker - try alternatives
          if (hasExplicitPathTarget) {
            console.error("[EVASION] Explicit path target blocked; skipping root URL fallbacks.");
            result.botBlocker = { detected: true, name: blocker.cloudflare ? 'cloudflare' : blocker.akamai ? 'akamai' : blocker.incapsula ? 'incapsula' : 'generic', blocked: true, bypassed: false };
            result.renderTimeout = true;
            result.criticalIssues.push(`Site blocked by ${blocker.cloudflare ? 'Cloudflare' : blocker.akamai ? 'Akamai' : blocker.incapsula ? 'Incapsula' : 'bot blocker'} (explicit path target could not bypass)`);
            pageLoadFailed = true;
          } else {
            console.error(`[EVASION] ${blocker.cloudflare ? 'Cloudflare' : blocker.akamai ? 'Akamai' : blocker.incapsula ? 'Incapsula' : 'Generic'} blocker detected, trying alternatives...`);
            const altResult = await tryAlternativeUrls(page, normalizedDomain, 30000);
            if (altResult.passed) {
              response = altResult.response;
              finalUrl = altResult.url;
              usedAlternativeUrl = true;
              result.botBlocker = { detected: true, name: blocker.cloudflare ? 'cloudflare' : blocker.akamai ? 'akamai' : blocker.incapsula ? 'incapsula' : 'generic', blocked: false, bypassed: true, alternativeUrl: altResult.url };
            } else {
              console.error("[EVASION] Could not bypass bot blocker");
              result.botBlocker = { detected: true, name: blocker.cloudflare ? 'cloudflare' : blocker.akamai ? 'akamai' : blocker.incapsula ? 'incapsula' : 'generic', blocked: true, bypassed: false };
              result.renderTimeout = true;
              result.criticalIssues.push(`Site blocked by ${blocker.cloudflare ? 'Cloudflare' : blocker.akamai ? 'Akamai' : blocker.incapsula ? 'Incapsula' : 'bot blocker'} (could not bypass)`);
              pageLoadFailed = true;
            }
          }
        }
      } else {
        // No blocker detected - wait for network idle
        try {
          await page.waitForLoadState("networkidle", { timeout: 30000 });
        } catch (e) {
          // Network idle timeout is okay - page may have ongoing connections
        }
      }
      
    } catch (e) {
      // Navigation failed - try alternatives
      console.error(`[AUDIT] Primary navigation failed: ${e.message}`);

      if (hasExplicitPathTarget) {
        console.error("[AUDIT] Explicit path target failed; skipping root URL and UA fallbacks.");
        result.renderTimeout = true;
        pageLoadFailed = true;
        result.criticalIssues.push("Explicit path target failed to load");
      } else {
        // First try alternative URLs with same UA
        const altResult = await tryAlternativeUrls(page, normalizedDomain, 45000);
        if (altResult.passed) {
          response = altResult.response;
          finalUrl = altResult.url;
          usedAlternativeUrl = true;
          console.error(`[EVASION] Successfully loaded via alternative: ${altResult.url}`);
        } else {
          // URL alternatives failed - check if site is actually reachable
          console.error("[AUDIT] Running site availability check before UA rotation...");
          const availability = await checkSiteAvailability(normalizedDomain);
          result.siteAvailability = availability;
          console.error(`[AUDIT] Site availability: ${JSON.stringify(availability)}`);
          
          if (availability.reachable) {
            // Site is reachable via HTTP but browser failed - try alternative User-Agents
            console.error("[EVASION] Site is reachable but browser blocked - trying alternative User-Agents...");
            const uaResult = await tryAlternativeUserAgents(browser, normalizedDomain, 30000);
            
            if (uaResult.passed) {
              // Success with alternative UA! Replace the page and continue
              console.error(`[EVASION] SUCCESS with ${uaResult.userAgent.desc} User-Agent!`);
              
              // Close old page/context and use new one
              try { await page.close(); } catch (e) {}
              try { await context.close(); } catch (e) {}
              
              // Use the successful page/context
              page = uaResult.page;
              context = uaResult.context;
              response = uaResult.response;
              finalUrl = uaResult.url;
              pageLoadFailed = false;
              result.botBlocker = { detected: true, name: 'circumvented', blocked: false, bypassed: true, method: `Alternative UA: ${uaResult.userAgent.desc}` };
              result.warnings.push(`Bot blocker bypassed using ${uaResult.userAgent.desc} User-Agent`);
              
            } else {
              // All UA alternatives failed
              console.error("[AUDIT] All User-Agent alternatives failed");
              result.renderTimeout = true;
              pageLoadFailed = true;
              result.warnings.push(`Site reachable via ${availability.method} (status ${availability.statusCode}) but all browser attempts blocked - bot protection active`);
            }
          } else {
            // Site is actually down
            console.error(`[AUDIT] Site is not reachable: ${availability.error || 'unknown error'}`);
            result.renderTimeout = true;
            pageLoadFailed = true;
            result.criticalIssues.push(`Site not reachable: ${availability.error || availability.blockerHint || 'unknown'}`);
          }
        }
      }
    }
    
      if (!response && !pageLoadFailed) {
        console.error("[AUDIT] No response from server");
        result.renderTimeout = true;
        result.criticalIssues.push("No response from server");
        pageLoadFailed = true;
        
        // Run site availability check
        console.error("[AUDIT] Running site availability check...");
        result.siteAvailability = await checkSiteAvailability(normalizedDomain);
        console.error(`[AUDIT] Site availability: ${JSON.stringify(result.siteAvailability)}`);
      }
      
      // Record which URL we actually used
      if (usedAlternativeUrl) {
        result.actualUrl = finalUrl;
        console.error(`[AUDIT] Using alternative URL: ${finalUrl}`);
      }
      
      // --- Browser-dependent tests (skip if page load failed) ---
      if (!pageLoadFailed) {
      // Add human-like delays and interactions to avoid bot detection
      await randomDelay(500, 1500);
      
      // Simulate human-like mouse movements (helps bypass some bot detection)
      try {
        await page.mouse.move(Math.random() * 500, Math.random() * 500);
        await randomDelay(200, 500);
        await page.mouse.move(Math.random() * 800, Math.random() * 600);
        await randomDelay(200, 500);
      } catch (e) {
        // Mouse movement failed - not critical
      }
      
      // Scroll down a bit (common human behavior, triggers lazy-loaded content)
      try {
        await page.evaluate(() => window.scrollBy(0, 300));
        await randomDelay(500, 1000);
      } catch (e) {
        // Scroll failed - not critical
      }
      
      // Capture response headers
      const headers = response.headers();
      
      // --- Bot Blocker Detection ---
      console.error("[AUDIT] Checking for bot blockers...");
      result.botBlocker = await detectBotBlocker(page);
      if (result.botBlocker.detected) {
        console.error(`[AUDIT] Bot blocker detected: ${result.botBlocker.name}`);
      }
      
      // --- Security Headers Analysis ---
      console.error("[AUDIT] Analyzing security headers...");
      for (const header of Object.keys(SECURITY_HEADERS)) {
        const value = headers[header];
        result.securityHeaders[header] = {
          present: !!value,
          value: value || null,
        };
      }
    
    // --- Performance Metrics & Core Web Vitals ---
    // Wait a bit for LCP to be captured
    await page.waitForTimeout(2000);
    
    const perfMetrics = await page.evaluate(() => {
      const timing = performance.timing || performance.getEntriesByType("navigation")[0] || {};
      const paintEntries = performance.getEntriesByType("paint");
      
      // Core Web Vitals
      let lcp = null;
      let cls = null;
      let inp = null;
      
      // LCP - Largest Contentful Paint
      // Try PerformanceObserver entries first
      try {
        const lcpEntries = performance.getEntriesByType("largest-contentful-paint");
        if (lcpEntries.length > 0) {
          lcp = lcpEntries[lcpEntries.length - 1].startTime;
        }
      } catch (e) {}
      
      // CLS - Cumulative Layout Shift
      try {
        const clsEntries = performance.getEntriesByType("layout-shift");
        if (clsEntries.length > 0) {
          cls = clsEntries.filter(e => !e.hadRecentInput).reduce((sum, e) => sum + e.value, 0);
        }
      } catch (e) {}
      
      // INP - Interaction to Next Paint (if available)
      try {
        const inpEntries = performance.getEntriesByType("event");
        if (inpEntries.length > 0) {
          // Approximate INP as the max interaction delay
          const interactionDelays = inpEntries.filter(e => e.interactionId).map(e => e.duration);
          if (interactionDelays.length > 0) {
            inp = Math.max(...interactionDelays);
          }
        }
      } catch (e) {}
      
      return {
        loadTime: timing.loadEventEnd ? timing.loadEventEnd - timing.navigationStart : null,
        domContentLoaded: timing.domContentLoadedEventEnd ? timing.domContentLoadedEventEnd - timing.navigationStart : null,
        firstPaint: paintEntries.find(e => e.name === "first-paint")?.startTime || null,
        firstContentfulPaint: paintEntries.find(e => e.name === "first-contentful-paint")?.startTime || null,
        largestContentfulPaint: lcp,
        cumulativeLayoutShift: cls,
        interactionToNextPaint: inp,
      };
    });
    result.performance = perfMetrics;
    
    // --- Cookies Analysis ---
    const cookies = await context.cookies();
    for (const cookie of cookies) {
      result.cookies.push({
        name: cookie.name,
        domain: cookie.domain,
        secure: cookie.secure,
        httpOnly: cookie.httpOnly,
        sameSite: cookie.sameSite,
      });
    }
    result.cookieSecurity = analyzeCookieSecurity(result.cookies, result);
    
    // --- Mixed Content Check ---
    console.error("[AUDIT] Checking for mixed content...");
    const mixedContent = await page.evaluate(() => {
      const resources = [];
      // Check for HTTP resources in the page
      const imgs = Array.from(document.querySelectorAll('img[src^="http:"]'));
      const scripts = Array.from(document.querySelectorAll('script[src^="http:"]'));
      const links = Array.from(document.querySelectorAll('link[href^="http:"]'));
      const iframes = Array.from(document.querySelectorAll('iframe[src^="http:"]'));
      
      imgs.forEach(el => resources.push(el.src));
      scripts.forEach(el => resources.push(el.src));
      links.forEach(el => resources.push(el.href));
      iframes.forEach(el => resources.push(el.src));
      
      return resources;
    });
    if (mixedContent.length > 0) {
      result.mixedContent = { found: true, resources: mixedContent };
    }
    
    // --- Tech Stack Detection ---
    console.error("[AUDIT] Detecting technology stack...");
    const pageContent = await page.content();
    result.techStack = detectTechStack(pageContent, headers);
    
    // --- SEO Analysis ---
    console.error("[AUDIT] Analyzing SEO basics...");
    const seoData = await page.evaluate(() => {
      const title = document.title || null;
      const metaDesc = document.querySelector('meta[name="description"]')?.content || null;
      const h1s = Array.from(document.querySelectorAll("h1"));
      const images = Array.from(document.querySelectorAll("img"));
      const imagesWithoutAlt = images.filter(img => !img.alt).length;
      const links = document.querySelectorAll("a[href]").length;
      const canonical = document.querySelector('link[rel="canonical"]')?.href || null;
      
      return {
        title,
        metaDescription: metaDesc,
        h1Count: h1s.length,
        h1Text: h1s[0]?.textContent?.trim() || null,
        images: images.length,
        imagesWithoutAlt,
        links,
        canonical,
      };
    });
    result.seo = seoData;
    
    // --- Contact Extraction ---
    console.error("[AUDIT] Extracting contact information...");
    result.contacts = await extractContacts(page);
    
    // --- Address/Location Detection ---
    console.error("[AUDIT] Detecting address/location...");
    result.address = await extractAddress(page);
    
    // --- Business Intelligence ---
    console.error("[AUDIT] Analyzing business information...");
    result.businessInfo = await extractBusinessInfo(page);
    
    // --- Lead Intelligence Extraction ---
    console.error("[AUDIT] Extracting lead intelligence...");
    result.leadIntelligence = await extractLeadIntelligence(page, testUrl);
    
    // --- Broken Links Check ---
    console.error("[AUDIT] Checking broken links...");
    result.brokenLinks = await checkBrokenLinks(page, testUrl);
    
    // --- Sensitive Exposure Probe ---
    console.error("[AUDIT] Probing for sensitive exposures...");
    result.sensitiveExposures = await checkSensitiveExposures(page, testUrl, normalizedDomain);
    
    // --- SEO Files Check ---
    console.error("[AUDIT] Checking robots.txt and sitemap...");
    result.seoFiles = await checkSeoFiles(testUrl);
    
    // --- Cookie Consent Detection ---
    console.error("[AUDIT] Detecting cookie consent...");
    result.cookieConsent = await checkCookieConsent(page);
    
    // --- Tech Stack Fingerprinting ---
    console.error("[AUDIT] Fingerprinting tech stack...");
    result.techStack = await fingerprintTechStack(page);
    
    // --- Third-Party Script Inventory ---
    console.error("[AUDIT] Inventorying third-party scripts...");
    result.thirdPartyScripts = await inventoryThirdPartyScripts(page);
    
    // --- Mobile Viewport Check ---
    const viewportMeta = await page.$eval('meta[name="viewport"]', (el) => el.content).catch(() => null);
    result.mobile.viewport = viewportMeta;
    result.mobile.friendly = !!viewportMeta;
    
    // --- Form Security Analysis ---
    console.error("[AUDIT] Analyzing form security...");
    result.formAnalysis = await analyzeForms(page);
    if (result.formAnalysis?.issues?.length > 0) {
      result.criticalIssues.push(...result.formAnalysis.issues.filter(i => i.includes('CRITICAL')));
      result.warnings.push(...result.formAnalysis.issues.filter(i => !i.includes('CRITICAL')));
    }
    // Copy all form analysis data to result.forms for profile output
    result.forms = {
      found: result.formAnalysis.totalForms > 0,
      totalForms: result.formAnalysis.totalForms,
      forms: result.formAnalysis.forms,
      secureForms: result.formAnalysis.secureForms,
      insecureForms: result.formAnalysis.insecureForms,
      issues: result.formAnalysis.issues,
      crossOriginForms: result.formAnalysis.crossOriginForms,
      trustedCrossOriginForms: result.formAnalysis.trustedCrossOriginForms,
      untrustedCrossOriginForms: result.formAnalysis.untrustedCrossOriginForms,
      fileUploadForms: result.formAnalysis.fileUploadForms,
      formsWithHiddenFields: result.formAnalysis.formsWithHiddenFields,
      contactPage: result.formAnalysis.contactPage,
    };
    result.paymentSecurity = analyzePaymentSecurity(result);
    
    // --- Broken Image Detection ---
    console.error("[AUDIT] Checking for broken images...");
    const brokenImages = await page.evaluate(() => {
      const images = Array.from(document.querySelectorAll("img[src]"));
      return images
        .filter((img) => {
          const rect = img.getBoundingClientRect();
          return rect.width === 0 && rect.height === 0; // Likely broken or hidden
        })
        .map((img) => img.src)
        .filter((src) => src && !src.startsWith("data:"));
    });
    result.brokenImages = brokenImages;
    
    // --- Desktop Screenshot ---
    console.error("[AUDIT] Taking desktop screenshot...");
    const screenshotDir = path.join(__dirname, "ops", "screenshots");
    if (!fs.existsSync(screenshotDir)) {
      fs.mkdirSync(screenshotDir, { recursive: true });
    }
    const desktopScreenshot = path.join(screenshotDir, `${leadId}-desktop.png`);
    await page.screenshot({ path: desktopScreenshot, fullPage: false });
    result.screenshots.desktop = desktopScreenshot;
    
    // --- Mobile Test ---
    console.error("[AUDIT] Testing mobile viewport...");
    const mobileContext = await browser.newContext({
      viewport: { width: 375, height: 812 },
      userAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1",
      ignoreHTTPSErrors: true,
      // Additional evasion settings for mobile
      hasTouch: true,
      isMobile: true,
      locale: 'en-US',
      timezoneId: 'America/New_York',
    });
    const mobilePage = await mobileContext.newPage();
    
    // Keep mobile on the lighter script too; this is a signal-gathering run, not a bypass-first run.
    await mobilePage.addInitScript(LIGHT_HEAVY_DETECTION_BYPASS_SCRIPT);
    
    // Block tracking/analytics scripts for mobile too
    await setupTrackingBlocker(mobilePage);
    
    try {
      // Use the same URL that worked for desktop (or finalUrl if we had to use alternative)
      const mobileTargetUrl = finalUrl || testUrl;
      await mobilePage.goto(mobileTargetUrl, { waitUntil: "domcontentloaded", timeout: 60000 });
      
      // Check for bot blocker on mobile
      await mobilePage.waitForTimeout(2000);
      const mobileBlocker = await detectBotBlocker(mobilePage);
      if (mobileBlocker.challengeDetected && mobileBlocker.cloudflare) {
        const passed = await waitForCloudflareChallenge(mobilePage, 15000);
        if (!passed) {
          console.error("[AUDIT] Mobile blocked by Cloudflare, using cached desktop state");
        }
      } else {
        // Wait for network idle if no blocker
        try {
          await mobilePage.waitForLoadState("networkidle", { timeout: 15000 });
        } catch (e) {
          // Timeout is okay
        }
      }
      
      await mobilePage.waitForTimeout(1000);
      
      // Check for mobile menu
      const mobileNavSelectors = [
        "nav",
        ".nav",
        ".navigation",
        "#nav",
        "[class*='nav']",
        "[class*='menu']",
        "button[aria-label*='menu']",
        ".hamburger",
        "[class*='hamburger']",
        ".mobile-menu",
        "[class*='mobile']",
      ];
      
      let navFound = false;
      for (const selector of mobileNavSelectors) {
        const el = await mobilePage.$(selector);
        if (el) {
          navFound = true;
          break;
        }
      }
      result.mobile.navWorks = navFound;
      
      // Mobile screenshot
      const mobileScreenshot = path.join(screenshotDir, `${leadId}-mobile.png`);
      await mobilePage.screenshot({ path: mobileScreenshot, fullPage: false });
      result.screenshots.mobile = mobileScreenshot;
      
    } catch (e) {
      console.error(`[AUDIT] Mobile test error: ${e.message}`);
      result.mobile.friendly = false;
    }
    
    await mobileContext.close();

    result.consoleWarnings = formatObservedSummary(getObservedEntries(result._observedConsoleWarnings));
    await reconcileJavaScriptFindings(browser, finalUrl || testUrl, result, effectiveUserAgent);
    
    // --- Admin Endpoint Probing ---
    console.error("[AUDIT] Probing for admin endpoints...");
    result.adminEndpoints.found = await probeAdminEndpoints(page, testUrl);
    result.adminEndpoints.accessible = result.adminEndpoints.found.filter(e => e.accessible);
    
        await context.close();
      }
    } // End browser setup / browser-dependent tests
    
    // --- Calculate Score ---
    console.error("[AUDIT] Calculating audit score...");
    buildConfidenceFindings(result);
    result.securityOutreach = buildSecurityOutreachSummary(result);
    calculateAuditScore(result);
    result.enrichment = buildLeadEnrichment(result);
    
    // --- Save Evidence Files ---
    if (profileTarget) {
      console.error(`[AUDIT] Saving evidence to ${profileTarget.evidenceDir}...`);
      saveEvidence(profileTarget.evidenceDir, result);
    }
    
    // --- Update Profile ---
    if (profileTarget && fs.existsSync(profileTarget.profilePath)) {
      let content = fs.readFileSync(profileTarget.profilePath, "utf8");
      const auditSection = generateProfileSection(result);
      
      // Replace existing audit section or prepend
      const auditRegex = /## Technical Audit.*?(?=## |\n$)/s;
      if (auditRegex.test(content)) {
        content = content.replace(auditRegex, auditSection);
      } else {
        content = auditSection + "\n" + content;
      }
      
      fs.writeFileSync(profileTarget.profilePath, content, "utf8");
      console.error(`[AUDIT] Updated profile: ${profileTarget.profilePath}`);
    }
    
    // --- Output Result ---
    const duration = Date.now() - startTime;
    result.duration = duration;
    delete result._observedConsoleErrors;
    delete result._observedConsoleWarnings;
    delete result._observedPageErrors;
    result.auditStatus = result.criticalIssues.length > 0 ? "completed_with_findings" : "completed";
    
    console.error(`[AUDIT] Complete in ${(duration / 1000).toFixed(2)}s. Score: ${result.auditScore}/100`);
    console.log(JSON.stringify(result, null, 2));
    process.exit(0);
    
  } catch (error) {
    console.error(`[AUDIT] Error: ${error.message}`);
    delete result._observedConsoleErrors;
    delete result._observedConsoleWarnings;
    delete result._observedPageErrors;
    result.criticalIssues.push(`Audit error: ${error.message}`);
    result.auditScore = 0;
    console.log(JSON.stringify(result, null, 2));
    process.exit(1);
    
  } finally {
    if (browser) {
      await browser.close();
    }
  }
}

if (isMainModule) {
  audit().catch((error) => {
    console.error(`[AUDIT] Fatal error: ${error.message}`);
    process.exit(1);
  });
}

module.exports = {
  extractApiKeysFromPageContent,
  analyzeCookieSecurity,
  analyzePaymentSecurity,
  buildDkimReviewSummary,
  buildReviewQueueHighlights,
  buildLeadEnrichment,
  buildSecurityOutreachSummary,
  determineSensitiveSurfaceContext,
  getMissingHeaderSeverity,
  buildConfidenceFindings,
  checkSSLCertificate,
  checkEmailAuth,
  analyzeForms,
  probeAdminEndpoints,
  calculateAuditScore,
  generateProfileSection,
  getActionableBrokenLinks,
};
