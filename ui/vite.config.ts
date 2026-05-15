import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The SBproxy binary embeds the contents of `ui/dist/` via the
// `include_dir!` macro when built with `--features embed-admin-ui`,
// then serves the assets under the `/admin/ui/` prefix. We bake
// that prefix into `base` so the generated index.html references
// `/admin/ui/assets/*.js` (etc.) and a single static asset host can
// answer the browser without rewriting paths server-side.
export default defineConfig({
  base: "/admin/ui/",
  plugins: [react()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
    sourcemap: false,
  },
  server: {
    // `pnpm dev` proxies API calls back to a local sbproxy admin
    // server on :9090 so the dev loop matches the embedded prod
    // shape. Operators can override via VITE_ADMIN_ORIGIN.
    proxy: {
      "/admin/api": {
        target: process.env.VITE_ADMIN_ORIGIN || "http://127.0.0.1:9090",
        changeOrigin: true,
      },
    },
  },
});
