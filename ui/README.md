# sbproxy admin UI

A Vue 3 + Vite + TypeScript single-page app for the built-in admin
dashboard served by the `sbproxy` binary. It is a UI over admin API
endpoints that already exist; it adds no backend of its own.

The app is a control surface for operators: a light editorial surface
with a two-tier accent, matching the current sbproxy.dev brand. Navy
(#0e2a4d) is the commit tier (primary buttons, brand mark); azure
(#2563eb) is the interaction tier (links, focus, active states); amber
is a warning color only. Type is Instrument Sans with JetBrains Mono
for code and identifiers. It reads as the same product as sbproxy.dev,
not as a generic dashboard theme.

## Views

The left sidebar routes between seven views, each driven by
same-origin admin endpoints:

- Overview: `/health`, `/api/stats`, `/admin/model-host/status`.
- Keys: list and manage `/admin/keys` (create, edit policy, rotate,
  block, unblock, revoke, delete). A newly created key returns a
  plaintext token once; it is shown in a copy-once modal and is not
  retrievable again.
- Credentials: the same lifecycle over `/admin/credentials`. Secret
  values are write-only and are never displayed.
- Config: `/api/openapi.json` (readable summary plus raw JSON view),
  `/admin/drift` (in-sync or drifted badge with the diff),
  `/admin/reload` (behind a confirm), and `/api/health/targets`.
- Logs: `/api/requests` as a client-filterable table (by method,
  status, and path), newest first, with a manual refresh. Live
  streaming is a planned follow-up.
- Metrics: parses the Prometheus `/metrics` text client-side and
  summarizes a few key `sbproxy_*` series as stat tiles and simple
  bars, with a raw view.
- Prompts: `/admin/prompts` with add-version
  (`POST /admin/prompts/{host}/{name}/versions`) and pin
  (`PUT /admin/prompts/{host}/{name}/pin`).

Every request uses `credentials: "same-origin"` and an absolute path.
The page is served behind the admin port's HTTP Basic auth, so the
browser carries those credentials. Fetch failures (401, 403, 404, 5xx,
or network) render a clear error surface, and empty lists render an
empty state, rather than a blank panel.

## Routing

Vue Router runs in history mode with base `/admin/ui/`. The admin
server does SPA fallback to `index.html`, so deep links and refreshes
resolve. `vite.config.ts` sets `base: "/admin/ui/"` so hashed asset
URLs resolve under the mount.

## Build

```sh
cd ui
npm install
npm run build
```

The build writes to `ui/dist/` (Vite default output): a hashed
`index.html` plus `assets/*`. That directory is what the Rust side
embeds.

An optional type-check is available separately and is not part of the
build gate:

```sh
npm run typecheck
```

## Embed into the binary

Build sbproxy with the cargo feature:

```sh
cargo build -p sbproxy --features embed-admin-ui --locked
```

The feature gates `include_dir!("../../ui/dist")` at compile time and
registers the `/admin/ui/*` route on the admin server. Without the
feature, the admin port responds 404 to `/admin/ui`.

## Dev loop

Run a local sbproxy with the admin server enabled (default port 9090),
then run the Vite dev server:

```sh
cd ui
npm install
npm run dev
```

`vite.config.ts` proxies the admin API prefixes (`/api`, `/health`,
`/metrics`, and the `/admin/*` management paths, but not `/admin/ui`
itself) to `http://127.0.0.1:9090`. Override the upstream with the
`VITE_ADMIN_ORIGIN` environment variable.

## Dependencies

Deliberately light: Vue and vue-router only, `@vitejs/plugin-vue` for
the build. No component library, no CSS framework, no charting
library. Design tokens live in `src/styles/tokens.css` and every
component is built off those CSS custom properties. Charts are
hand-rolled bars.
