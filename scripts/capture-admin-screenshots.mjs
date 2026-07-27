#!/usr/bin/env node
//
// Recapture the admin console screenshots in docs/admin-ui.md.
//
// Every shot includes the sidebar, so adding or renaming a console page
// makes all of them stale at once. Rerun the whole set rather than adding
// one image next to nineteen that disagree with it.
//
//   npm install puppeteer            # from the workspace root
//   cargo build --release -p sbproxy --features embed-admin-ui
//   sbproxy serve <a config with admin enabled>
//   ADMIN_URL=http://127.0.0.1:9090 ADMIN_USER=admin ADMIN_PASS=admin \
//     node scripts/capture-admin-screenshots.mjs
//
// Pages render whatever the running gateway has. A gateway with no traffic
// produces a wall of empty states, which is worse documentation than the
// screenshots you already have: drive real traffic through the config first
// and confirm each page has data before committing the result.
//
// admin-cluster-degraded.png is not captured here. It needs a multi-node
// mesh with a dead member (see examples/model-cluster-symmetric) and is
// still shot by hand.
import { createRequire } from "node:module";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, "..");
const outDir = path.join(root, "docs", "assets");
const puppeteer = require(path.join(root, "node_modules/puppeteer"));

const base = process.env.ADMIN_URL || "http://127.0.0.1:9090";
const user = process.env.ADMIN_USER || "admin";
const pass = process.env.ADMIN_PASS || "admin";

const routes = [
  { path: "/admin/ui/", file: "admin-overview.png" },
  { path: "/admin/ui/keys", file: "admin-keys.png" },
  { path: "/admin/ui/credentials", file: "admin-credentials.png" },
  { path: "/admin/ui/config", file: "admin-config.png" },
  { path: "/admin/ui/logs", file: "admin-logs.png" },
  { path: "/admin/ui/metrics", file: "admin-metrics.png" },
  { path: "/admin/ui/spend", file: "admin-spend.png" },
  { path: "/admin/ui/ai-performance", file: "admin-ai-performance.png" },
  { path: "/admin/ui/guardrails", file: "admin-guardrails.png" },
  { path: "/admin/ui/alerts", file: "admin-alerts.png" },
  { path: "/admin/ui/prompts", file: "admin-prompts.png" },
  { path: "/admin/ui/playground", file: "admin-playground.png" },
  { path: "/admin/ui/cache", file: "admin-cache.png" },
  { path: "/admin/ui/compression", file: "admin-compression.png" },
  { path: "/admin/ui/model-host", file: "admin-model-host.png" },
  { path: "/admin/ui/storage", file: "admin-storage.png" },
  { path: "/admin/ui/audit", file: "admin-audit.png" },
  { path: "/admin/ui/users", file: "admin-users.png" },
  { path: "/admin/ui/cluster", file: "admin-cluster.png" },
  { path: "/admin/ui/sessions", file: "admin-sessions.png" },
];

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const browser = await puppeteer.launch({
  headless: true,
  defaultViewport: { width: 1440, height: 900 },
  // A cold headless Chrome on a loaded machine can take well over the
  // 30s default to answer the first captureScreenshot.
  protocolTimeout: 180000,
  // --disable-gpu and --disable-dev-shm-usage are load-bearing here:
  // without them captureScreenshot hangs indefinitely on macOS headless.
  args: [
    "--no-sandbox",
    "--disable-setuid-sandbox",
    "--disable-gpu",
    "--disable-dev-shm-usage",
  ],
});
const page = await browser.newPage();
page.setDefaultTimeout(20000);
await page.authenticate({ username: user, password: pass });
fs.mkdirSync(outDir, { recursive: true });

await page.goto(`${base}/admin/ui/`, { waitUntil: "domcontentloaded" });
await sleep(1000);
await page.screenshot({ path: path.join(outDir, "admin-login.png") });
console.log("wrote admin-login.png");

// Fill login form if present
const passInput = await page.$('input[type="password"]');
if (passInput) {
  const userInput = await page.$('input[type="text"], input[name="username"], input:not([type])');
  if (userInput) {
    await userInput.click({ clickCount: 3 });
    await userInput.type(user);
  }
  await passInput.click({ clickCount: 3 });
  await passInput.type(pass);
  await Promise.all([
    page.click('button[type="submit"]').catch(() => page.keyboard.press("Enter")),
    sleep(1500),
  ]);
  await sleep(1000);
}

for (const r of routes) {
  await page.goto(`${base}${r.path}`, { waitUntil: "domcontentloaded" });
  await sleep(900);
  await page.screenshot({ path: path.join(outDir, r.file) });
  console.log("wrote", r.file);
}

// Session detail needs a real session id, so discover one from the ring
// rather than hard-coding an id that goes stale the next time this runs.
const sessionId = await page.evaluate(async () => {
  const res = await fetch("/api/requests?limit=200", { credentials: "same-origin" });
  if (!res.ok) return null;
  const rows = await res.json();
  const list = Array.isArray(rows) ? rows : (rows.requests ?? []);
  // Prefer a multi-request session: a one-call detail page shows nothing
  // of the causal ordering the page exists to show.
  const counts = new Map();
  for (const r of list) {
    if (typeof r.session_id === "string" && r.session_id) {
      counts.set(r.session_id, (counts.get(r.session_id) ?? 0) + 1);
    }
  }
  let best = null;
  for (const [id, n] of counts) if (!best || n > best[1]) best = [id, n];
  return best?.[0] ?? null;
});

if (sessionId) {
  await page.goto(`${base}/admin/ui/sessions/${sessionId}`, {
    waitUntil: "domcontentloaded",
  });
  await sleep(900);
  await page.screenshot({ path: path.join(outDir, "admin-session-detail.png") });
  console.log("wrote admin-session-detail.png");
} else {
  console.log("skipped admin-session-detail.png (no captured session in the ring)");
}

await browser.close();
console.log("done");
