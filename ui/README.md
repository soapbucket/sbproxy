# sbproxy admin UI

Vite + React + TypeScript scaffold for the built-in admin dashboard
served by the `sbproxy` binary. Tracked under WOR-227.

This is a foundation only. The real views (providers, models,
routing-strategy preview, metrics tiles, live chat) land in follow-up
tickets.

## Build

```sh
cd ui
pnpm install
pnpm build
```

The build writes to `ui/dist/`. That directory is gitignored except
for an empty `.gitkeep` so the `include_dir!` macro can resolve at
compile time even without a prior `pnpm build` (the embed surface
serves a 404 in that case).

## Embed into the binary

Build sbproxy with the cargo feature:

```sh
cargo build -p sbproxy --features embed-admin-ui --locked
```

The feature gates `include_dir!("../../ui/dist")` at compile time
and registers the `/admin/ui/*` route on the admin server. Without
the feature, the admin port responds 404 to `/admin/ui` with a one
line message explaining how to enable the embed.

## Dev loop

Run a local sbproxy with the admin server enabled on the default
port (9090), then run the Vite dev server in a separate terminal:

```sh
cd ui
pnpm install
pnpm dev
```

`vite.config.ts` proxies `/admin/api/*` to `http://127.0.0.1:9090`
by default so the dev shape matches the embedded prod shape. The
`VITE_ADMIN_ORIGIN` env var overrides the upstream for non-default
deployments.

## Scope (WOR-227 scaffold)

What ships in this scaffold:

- One placeholder page that calls `/admin/api/health` and renders
  the response.
- A disabled chat-playground card that does not submit model traffic.
- A `/admin/ui/*` mount on the admin server, behind the
  `embed-admin-ui` cargo feature.
- A reserved `POST /admin/api/playground/chat` admin route that
  returns a JSON `feature disabled` envelope after admin auth.

What is deferred:

- The real React views (providers, models, routing-strategy
  preview, metrics).
- The chat playground routing requests through the production AI
  dispatch path.
- Live metrics tiles.
- Bundling `ui/dist/` in CI.
