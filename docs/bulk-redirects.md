# Bulk redirects
*Last modified: 2026-08-19*

![/old/about answered with a 301 from a CSV row and a shop path answered 308 from an inline row](assets/bulk-redirects.gif)

Rows compile into an O(1) path lookup at config load ([config](../examples/bulk-redirects/)).

The `redirect` action accepts a list of source-to-destination rows
in addition to (or instead of) a single `url:`. Each origin owns its
own list. The proxy compiles the rows once at config-load time into
an O(1) lookup table keyed on the request path; runtime cost is one
hash hit on the redirect dispatch path.

## Sources

| `bulk_list.type` | What it loads |
|------------------|---------------|
| `inline` | YAML rows embedded directly in the config under `rows:`. |
| `file` | A local file. CSV when the path ends in `.csv`, YAML otherwise. |
| `url` | An HTTPS URL fetched once at startup. CSV/YAML by URL extension or explicit `format:`. A plain `http://` URL is refused because list contents drive 30x responses. |

```yaml
origins:
  "marketing.local":
    action:
      type: redirect
      status_code: 301
      preserve_query: true
      bulk_list:
        type: file
        path: /etc/sbproxy/marketing-redirects.csv
```

## Row shape

CSV columns: `from,to[,status]`. Lines starting with `#` and blank
lines are ignored. A leading row whose first column is the literal
`from` is treated as a header.

```csv
from,to,status
/old/about,/about,301
# status defaults to the action's status_code:
/old/help,/help
/blog/2023,https://blog.example.com/2023,308
```

Comments must sit on their own line; only lines starting with `#`
are ignored, so a trailing comment after a row would be parsed as
part of the destination.

YAML or inline:

```yaml
bulk_list:
  type: inline
  rows:
    - from: /category/legacy
      to:   /category/2024
      status: 308
    - from: /docs/v1
      to:   https://docs.example.com/v2
      preserve_query: false   # override per row
```

## Lookup semantics

- Exact-match on the request path. Wildcards and prefix matching are
  not supported; use the existing `forward_rules` for those.
- A row's `status` and `preserve_query` default to the action's
  values when omitted; per-row overrides win when set.
- Unmapped paths fall through to the action's `url:`. When `url:`
  is empty, the proxy returns `404`.

## Calling it

The runnable configuration is
[`examples/bulk-redirects/`](../examples/bulk-redirects/). It declares two
origins: `marketing.local` reads `redirects.csv` from disk with
`status_code: 301` and `preserve_query: true`, and `shop.local` carries an
inline list with per-row overrides and a `url:` fallback. Start it from the
repo root, because the file-backed list resolves its path against the working
directory:

```bash
make run CONFIG=examples/bulk-redirects/sb.yml
```

`%{redirect_url}` is the useful curl format here: it prints the resolved
`Location` without following it.

```bash
curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' \
  -H 'Host: marketing.local' http://127.0.0.1:8080/old/about
```

Running each interesting path through that gives:

```
marketing.local /old/about                  301 http://127.0.0.1:8080/about
marketing.local /old/team                   301 http://127.0.0.1:8080/about/team
marketing.local /press/2022/october-launch  301 http://127.0.0.1:8080/press/archive/2022-10
marketing.local /blog/announcement-2023     308 https://blog.example.com/announcements/2023
shop.local      /category/legacy            308 http://127.0.0.1:8080/category/2024
shop.local      /promo/black-friday-2024    302 http://127.0.0.1:8080/promo/cyber-monday-2024
shop.local      /docs/v1                    302 https://docs.example.com/v2
shop.local      /nothing-here               302 https://shop.example.com/
```

Read the status column against the config to see the override rules working.
On `marketing.local` the CSV rows that name `301` and the press rows that name
nothing both answer `301`, because the action's `status_code` is the fallback.
The `/blog/announcement-2023` row carries `308` of its own and wins. On
`shop.local` the action's `status_code` is `302`, so `/category/legacy` answers
`308` only because its row overrides it.

The last line is the fallback rather than a match: `/nothing-here` is in no
row, so it lands on the action's `url:`. An origin with no `url:` returns
`404` for an unmapped path instead, which is the difference between a redirect
list and a catch-all.

Destinations are used as written. A row pointing at `/about` produces a
relative `Location`, which is why curl resolves it against the request origin
and prints `http://127.0.0.1:8080/about`; a row pointing at a full URL sends
the browser off-host.

Query strings follow `preserve_query`, and the two origins differ:

```bash
curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' \
  -H 'Host: marketing.local' 'http://127.0.0.1:8080/old/about?utm=spring&id=7'
# 301 http://127.0.0.1:8080/about?utm=spring&id=7

curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' \
  -H 'Host: shop.local' 'http://127.0.0.1:8080/category/legacy?x=1'
# 308 http://127.0.0.1:8080/category/2024
```

`marketing.local` sets `preserve_query: true` on the action, so the whole
query survives. `shop.local` does not set it at all, so it defaults to off and
every row drops the query. That default is worth knowing before a migration:
losing `utm=` parameters across a bulk redirect is silent, and the row-level
`preserve_query: false` on `/docs/v1` is redundant on this origin precisely
because the action-level default is already off.

## Per-origin isolation

Lists never cross origins. Two origins can declare lists with
overlapping paths and no row leaks; each origin's compiled table is
scoped to its hostname.

## If the list fails to load

A `file` source that cannot be read, a `url` source that cannot be
fetched (including a plain `http://` URL, refused before the request
is made), or a CSV/YAML body that fails to parse does not fail config
load and does not stop the proxy from starting. The action logs a
`WARN` naming the error and falls back to behaving like a plain
single-target redirect: the compiled lookup table is empty, so every
request falls straight through to the action's `url:` (or to `404`
when `url:` is also unset). Nothing else on the origin is affected.

That means a typo'd file path or an unreachable list URL is silent at
the HTTP layer: the origin comes up healthy and answers every request
with the fallback, not with an error. Watch the proxy's startup log
for `bulk_list failed to load` rather than relying on the origin's
own responses to catch it.

## Reload

The list reloads on the next config swap. There is no per-row hot
reload; redeploy the config to pick up new rows. URL-backed lists
re-fetch on each config compile, so the same silent-fallback behavior
applies to a URL that goes unreachable between reloads: the prior
in-memory table is not kept, and a subsequent reload has to reach the
source again to get rows back.

## Performance

A 100k-row CSV compiles in well under a second on a warm cache and
serves redirects in tens of nanoseconds per request (HashMap lookup
on a `String` key). Cap the list length at the size your operators
can audit.

## See also

- [configuration.md](configuration.md#redirect) - full action schema.
- `examples/bulk-redirects/` - runnable CSV + inline example.
