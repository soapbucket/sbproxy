# Bulk redirects
*Last modified: 2026-04-27*

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
| `url` | An HTTPS URL fetched once at startup. CSV/YAML by URL extension or explicit `format:`. The proxy refuses HTTP because list contents drive 30x responses. |

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
/old/help,/help          # status defaults to the action's status_code
/blog/2023,https://blog.example.com/2023,308
```

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

## Per-origin isolation

Lists never cross origins. Two origins can declare lists with
overlapping paths and no row leaks; each origin's compiled table is
scoped to its hostname.

## Reload

The list reloads on the next config swap. There is no per-row hot
reload; redeploy the config to pick up new rows. URL-backed lists
re-fetch on each config compile.

## Performance

A 100k-row CSV compiles in well under a second on a warm cache and
serves redirects in tens of nanoseconds per request (HashMap lookup
on a `String` key). Cap the list length at the size your operators
can audit.

## See also

- [configuration.md](configuration.md#redirect-action) - full action schema.
- `examples/74-bulk-redirects/` - runnable CSV + inline example.
