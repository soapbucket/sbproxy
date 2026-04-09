/**
 * k6 Load Test Configuration for SoapBucket Proxy
 *
 * Targets: 10K RPS sustained for 60 seconds with ramp-up/ramp-down.
 * Measures: p50, p95, p99 latency. Verifies error rate < 1%.
 * Scenarios: cache hit, cache miss, threat protection enabled.
 *
 * Usage:
 *   k6 run proxy/test/loadtest/k6_config.js
 *
 * Environment variables:
 *   PROXY_BASE_URL   - Base URL of the proxy (default: http://localhost:8080)
 *   PROXY_HOSTNAME   - Hostname header to send (default: test.demo.soapbucket.com)
 *   ADMIN_KEY        - Bearer token for admin endpoints (optional)
 *   ENABLE_THREAT    - Set to "1" to include threat-protection scenario
 */

import http from "k6/http";
import { check, sleep } from "k6";
import { Rate, Trend } from "k6/metrics";

// ---------------------------------------------------------------------------
// Custom metrics
// ---------------------------------------------------------------------------

const errorRate = new Rate("errors");
const cacheHitLatency = new Trend("cache_hit_latency", true);
const cacheMissLatency = new Trend("cache_miss_latency", true);
const threatLatency = new Trend("threat_check_latency", true);

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const BASE_URL = __ENV.PROXY_BASE_URL || "http://localhost:8080";
const HOSTNAME = __ENV.PROXY_HOSTNAME || "test.demo.soapbucket.com";
const ADMIN_KEY = __ENV.ADMIN_KEY || "";
const ENABLE_THREAT = __ENV.ENABLE_THREAT === "1";

// Paths that are expected to be cached after the first request
const CACHED_PATHS = [
  "/",
  "/api/health",
  "/static/style.css",
  "/static/app.js",
  "/images/logo.png",
];

// Paths that bypass cache (unique query strings force misses)
function cacheMissPath() {
  return `/api/data?t=${Date.now()}&r=${Math.random()}`;
}

// Paths used for threat-protection testing (WAF, rate limiting, etc.)
const THREAT_PAYLOADS = [
  { path: "/api/search?q=<script>alert(1)</script>", name: "xss" },
  { path: "/api/search?q=' OR 1=1 --", name: "sqli" },
  { path: "/../../../etc/passwd", name: "path_traversal" },
  { path: "/api/data", name: "oversized_header" },
];

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------

export const options = {
  discardResponseBodies: true,

  scenarios: {
    // Scenario 1: Cache hit path (warm cache, high RPS)
    cache_hit: {
      executor: "constant-arrival-rate",
      rate: 6000, // 6K RPS for cache hits
      timeUnit: "1s",
      duration: "60s",
      preAllocatedVUs: 200,
      maxVUs: 500,
      exec: "cacheHitScenario",
      startTime: "10s", // Start after warm-up
    },

    // Scenario 2: Cache miss path (forces origin fetch)
    cache_miss: {
      executor: "constant-arrival-rate",
      rate: 3000, // 3K RPS for cache misses
      timeUnit: "1s",
      duration: "60s",
      preAllocatedVUs: 150,
      maxVUs: 400,
      exec: "cacheMissScenario",
      startTime: "10s",
    },

    // Scenario 3: Threat protection (WAF + rate limiting active)
    threat_check: {
      executor: "constant-arrival-rate",
      rate: ENABLE_THREAT ? 1000 : 0, // 1K RPS when enabled, 0 otherwise
      timeUnit: "1s",
      duration: "60s",
      preAllocatedVUs: 50,
      maxVUs: 200,
      exec: "threatScenario",
      startTime: "10s",
    },

    // Warm-up: prime caches before the main test
    warmup: {
      executor: "shared-iterations",
      vus: 10,
      iterations: CACHED_PATHS.length * 5,
      maxDuration: "10s",
      exec: "warmupScenario",
      startTime: "0s",
    },
  },

  thresholds: {
    // Global error rate must be under 1%
    errors: ["rate<0.01"],

    // Latency thresholds for cache hits
    cache_hit_latency: [
      "p(50)<10",   // p50 under 10ms
      "p(95)<50",   // p95 under 50ms
      "p(99)<100",  // p99 under 100ms
    ],

    // Latency thresholds for cache misses (higher, origin fetch involved)
    cache_miss_latency: [
      "p(50)<50",   // p50 under 50ms
      "p(95)<200",  // p95 under 200ms
      "p(99)<500",  // p99 under 500ms
    ],

    // Threat check latency (WAF processing adds overhead)
    threat_check_latency: [
      "p(50)<20",
      "p(95)<100",
      "p(99)<250",
    ],

    // Overall HTTP request duration
    http_req_duration: [
      "p(95)<200",
      "p(99)<500",
    ],
  },
};

// ---------------------------------------------------------------------------
// Scenario functions
// ---------------------------------------------------------------------------

/** Warm-up: prime the cache with known paths. */
export function warmupScenario() {
  const path = CACHED_PATHS[Math.floor(Math.random() * CACHED_PATHS.length)];
  const params = {
    headers: { Host: HOSTNAME },
    tags: { scenario: "warmup" },
  };
  http.get(`${BASE_URL}${path}`, params);
  sleep(0.1);
}

/** Cache hit: request paths that should already be cached. */
export function cacheHitScenario() {
  const path = CACHED_PATHS[Math.floor(Math.random() * CACHED_PATHS.length)];
  const params = {
    headers: { Host: HOSTNAME },
    tags: { scenario: "cache_hit" },
  };

  const res = http.get(`${BASE_URL}${path}`, params);

  const isOk = check(res, {
    "status is 2xx or 3xx": (r) => r.status >= 200 && r.status < 400,
  });

  errorRate.add(!isOk);
  cacheHitLatency.add(res.timings.duration);
}

/** Cache miss: unique query strings bypass cache. */
export function cacheMissScenario() {
  const path = cacheMissPath();
  const params = {
    headers: { Host: HOSTNAME },
    tags: { scenario: "cache_miss" },
  };

  const res = http.get(`${BASE_URL}${path}`, params);

  const isOk = check(res, {
    "status is not 5xx": (r) => r.status < 500,
  });

  errorRate.add(!isOk);
  cacheMissLatency.add(res.timings.duration);
}

/** Threat protection: send known-bad payloads with WAF enabled. */
export function threatScenario() {
  const payload = THREAT_PAYLOADS[Math.floor(Math.random() * THREAT_PAYLOADS.length)];

  const headers = { Host: HOSTNAME };

  // For the oversized header test, add a large custom header
  if (payload.name === "oversized_header") {
    headers["X-Malicious"] = "A".repeat(8192);
  }

  const params = {
    headers: headers,
    tags: { scenario: "threat_check", attack_type: payload.name },
  };

  const res = http.get(`${BASE_URL}${payload.path}`, params);

  // WAF should block malicious requests with 403 or allow safe ones.
  // Either way, the proxy should not crash (no 500).
  const isOk = check(res, {
    "not a server error": (r) => r.status < 500,
    "WAF blocks or passes cleanly": (r) =>
      r.status === 403 || r.status === 400 || (r.status >= 200 && r.status < 400),
  });

  errorRate.add(res.status >= 500);
  threatLatency.add(res.timings.duration);
}

// ---------------------------------------------------------------------------
// Default function (required by k6, unused since we use named scenarios)
// ---------------------------------------------------------------------------

export default function () {
  // All work is done in named scenario functions above.
}

// ---------------------------------------------------------------------------
// Setup and teardown
// ---------------------------------------------------------------------------

export function setup() {
  // Verify the proxy is reachable before starting
  const res = http.get(`${BASE_URL}/`, {
    headers: { Host: HOSTNAME },
    timeout: "5s",
  });

  if (res.error) {
    console.error(
      `Proxy not reachable at ${BASE_URL}. Error: ${res.error}. ` +
      `Set PROXY_BASE_URL environment variable if the proxy is on a different address.`
    );
  }

  return {
    startTime: new Date().toISOString(),
    baseUrl: BASE_URL,
    hostname: HOSTNAME,
    threatEnabled: ENABLE_THREAT,
  };
}

export function teardown(data) {
  console.log(`Load test completed. Started at ${data.startTime}`);
  console.log(`Target: ${data.baseUrl} (Host: ${data.hostname})`);
  console.log(`Threat scenarios enabled: ${data.threatEnabled}`);
}
