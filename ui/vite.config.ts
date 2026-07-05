import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";

// The SBproxy binary embeds the contents of `ui/dist/` via the
// `include_dir!` macro when built with `--features embed-admin-ui`,
// then serves the assets under the `/admin/ui/` prefix. We bake that
// prefix into `base` so the generated index.html references
// `/admin/ui/assets/*.js` (etc.) and the embedded static host can
// answer the browser without rewriting paths server-side. The server
// also does SPA fallback to index.html so client-side deep links
// (history mode) resolve.
export default defineConfig({
  base: "/admin/ui/",
  plugins: [vue()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
    sourcemap: false,
  },
  server: {
    // `npm run dev` proxies the admin API back to a local sbproxy
    // admin server on :9090 so the dev loop matches the embedded prod
    // shape. Operators can override the upstream via VITE_ADMIN_ORIGIN.
    // We list explicit prefixes rather than a bare `/admin` so the dev
    // server keeps serving the SPA itself under `/admin/ui`.
    proxy: {
      "/api": proxyTarget(),
      "/health": proxyTarget(),
      "/metrics": proxyTarget(),
      "/admin/keys": proxyTarget(),
      "/admin/credentials": proxyTarget(),
      "/admin/model-host": proxyTarget(),
      "/admin/prompts": proxyTarget(),
      "/admin/drift": proxyTarget(),
      "/admin/reload": proxyTarget(),
    },
  },
});

function proxyTarget() {
  return {
    target: process.env.VITE_ADMIN_ORIGIN || "http://127.0.0.1:9090",
    changeOrigin: true,
  };
}
