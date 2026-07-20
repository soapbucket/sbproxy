#!/usr/bin/env node
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
  { path: "/admin/ui/prompts", file: "admin-prompts.png" },
  { path: "/admin/ui/playground", file: "admin-playground.png" },
  { path: "/admin/ui/cache", file: "admin-cache.png" },
  { path: "/admin/ui/model-host", file: "admin-model-host.png" },
  { path: "/admin/ui/storage", file: "admin-storage.png" },
  { path: "/admin/ui/audit", file: "admin-audit.png" },
  { path: "/admin/ui/cluster", file: "admin-cluster.png" },
];

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const browser = await puppeteer.launch({
  headless: true,
  defaultViewport: { width: 1440, height: 900 },
  args: ["--no-sandbox", "--disable-setuid-sandbox"],
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

await browser.close();
console.log("done");
