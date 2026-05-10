# Bulk redirects

*Last modified: 2026-04-27*

Each origin owns its own redirect list, compiled at config-load into an O(1) lookup keyed on the request path. Three sources are supported: inline `rows:`, a local file via `path:`, or an HTTPS URL via `url:`. This example ships two origins. `marketing.local` reads `redirects.csv` next door (default 301 status, `preserve_query: true`). `shop.local` ships an inline list with per-row status overrides (308 for `/category/legacy`, default 302 for the others) and falls back to `https://shop.example.com/` for unmapped paths.

## Run

```bash
sbproxy serve -f sb.yml
```

The `redirects.csv` file lives next to `sb.yml`. Lines starting with `#` and blank lines are skipped.

## Try it

```bash
# marketing.local: file-backed list, default 301.
curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' \
     -H 'Host: marketing.local' http://127.0.0.1:8080/old/about
# 301 https://example.com/about... (well, /about; relative target)

curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' \
     -H 'Host: marketing.local' http://127.0.0.1:8080/old/team
# 301 /about/team

# Press archive: status falls back to action's default (301).
curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' \
     -H 'Host: marketing.local' http://127.0.0.1:8080/press/2022/october-launch
# 301 /press/archive/2022-10

# Cross-host moves: row carries its own status.
curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' \
     -H 'Host: marketing.local' http://127.0.0.1:8080/blog/announcement-2023
# 308 https://blog.example.com/announcements/2023

# shop.local inline list with 308 override.
curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' \
     -H 'Host: shop.local' http://127.0.0.1:8080/category/legacy
# 308 /category/2024

# Unmapped path on shop.local -> 302 fallback to https://shop.example.com/.
curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' \
     -H 'Host: shop.local' http://127.0.0.1:8080/anything-else
# 302 https://shop.example.com/

# Query strings preserved by default (preserve_query: true).
curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' \
     -H 'Host: marketing.local' 'http://127.0.0.1:8080/old/about?utm=launch'
# 301 /about?utm=launch
```

## What this exercises

- `action.type: redirect` with `bulk_list`
- File-backed (`bulk_list.type: file`) and inline (`bulk_list.type: inline`) sources
- Per-row `status` override and `preserve_query`
- Default `status_code` and fallback `url:` for unmapped paths
- CSV header (`from,to,status`) and comment lines

## See also

- [docs/features.md](../../docs/features.md)
- [docs/configuration.md](../../docs/configuration.md)
- [docs/manual.md](../../docs/manual.md)
