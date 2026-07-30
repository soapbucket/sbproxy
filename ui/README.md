# sbproxy admin UI

A Vue 3 + Vite + TypeScript single-page app for the built-in admin
dashboard served by the `sbproxy` binary. It is a UI over admin API
endpoints that already exist; it adds no backend of its own.

The app is a control surface for operators: a light editorial surface
matching the current sbproxy.dev paper, ink, and green system. Ink is
the commit tier, green is the interaction tier, and amber is a warning
color only. Type is Instrument Sans with JetBrains Mono for code and
identifiers. It reads as the same product as sbproxy.dev, not as a
generic dashboard theme.

## Views

The router currently exposes 25 named views covering onboarding, keys
and credentials, config, request observability, AI operations, model
hosting, storage, administration, and cluster health. The authoritative
page-by-page behavior and endpoint inventory lives in
[`docs/admin-ui.md`](../docs/admin-ui.md).

Every request uses `credentials: "same-origin"` and an absolute path.
The login route exchanges credentials for an `HttpOnly` session cookie
and an in-memory CSRF token. Fetch failures (401, 403, 404, 5xx, or
network) render a clear error surface, and empty lists render an empty
state rather than a blank panel.

## Documentation links

Every component route declares a `meta.documentation` slug in
`src/router.ts`. The shared `PageHeader` turns it into a visible
`https://sbproxy.dev/docs/<slug>` link, and the login card reuses the
same link component. Redirect-only records explicitly use
`documentation: null`; `src/router.test.ts` fails when any route is
left unaccounted for.

The links are passive anchors that open in a new tab. The UI never
prefetches documentation and does not depend on the public site. In an
air-gapped deployment an unreachable docs tab has no effect on the
console; operators can mirror the repository's `docs/` Markdown to an
internal host.

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
