# Config history: a durable local ring of every applied config

*Last modified: 2026-08-18*

Every config this proxy applies, whether at boot or through a later reload, gets kept as a content-addressed entry on local disk: the digest, when it applied, who or what applied it, the blast radius against the previous entry, and the pre-resolution document bytes exactly as they were read, before `${VAR}` and `vault://`/`secret://` references resolved. `GET /admin/config/history` reads the ring back; `GET /admin/config/history/{digest}` reads one entry in full, including a diff against the config running now.

`proxy.config_history` is disabled by default, and turning it on takes a restart: the ring recorder is built once at boot, right after the pipeline publishes. This example ships with it already enabled, so the walkthrough starts from a live ring on the first run.

## Run

```bash
rm -rf /tmp/sbproxy-config-history
sbproxy serve -f sb.yml
```

The boot log shows the ring taking its first entry, and warns about the one config value this example leaves unresolved on purpose (more on that below):

```
config: unresolved ${VAR} reference(s) left as literal text; ... refs=origins.api.local.request_modifiers.0.headers.set.X-Demo-Var: ${DEMO_VAR}
config file watcher started path=examples/config-history/sb.yml dir=examples/config-history
admin server listening addr=127.0.0.1:9090 tls=false
```

## Read the ring

In another terminal:

```bash
curl -s -u admin:demo-change-me http://127.0.0.1:9090/admin/config/history | jq .
```

```json
{
  "entries": [
    {
      "actor": "boot",
      "applied_at": "2026-08-18T04:23:49.562Z",
      "blast_radius": null,
      "degraded": [],
      "digest": "c43d279441bb6ff6c451dfb376618835253bc8515d019ea181f116a1ec152697",
      "provenance": "local_file",
      "revision": 1,
      "state": "applied"
    }
  ],
  "lineage": "44c4996c-515c-4e07-8f78-4eda3a1d85ff",
  "lkg_revision": null
}
```

One entry: the boot itself. `blast_radius` is `null` because there is nothing before it to diff against. `lkg_revision` is `null` because nothing has ever been marked last-known-good; see [What this ring does not do yet](#what-this-ring-does-not-do-yet).

The CLI reads the same route and renders it as a table:

```bash
sbproxy config history --password demo-change-me
```

```
lineage 44c4996c-515c-4e07-8f78-4eda3a1d85ff
REVISION	STATE	BLAST RADIUS	PROVENANCE	APPLIED AT	ACTOR	DIGEST
1	applied	-	local_file	2026-08-18T04:23:49.562Z	boot	c43d279441bb6ff6c451dfb376618835253bc8515d019ea181f116a1ec152697
```

## Change something, then apply it

Add a second outbound header:

```bash
python3 -c "
import pathlib
p = pathlib.Path('sb.yml')
text = p.read_text()
old = '            X-Demo-Var: \"\${DEMO_VAR}\"\n'
new = old + '            X-Config-Rev: \"v2\"\n'
p.write_text(text.replace(old, new, 1))
"
```

Now apply it with `sbproxy apply`, not a raw `POST /admin/reload`. `sbproxy serve` also runs a file watcher, so a plain edit-then-reload races it: whichever one gets there first wins, and the other finds nothing changed and records nothing. `apply` avoids the race by pushing the file straight to `PUT /admin/config` in one request. The server validates, persists, and hot-swaps before the file watcher gets a chance to notice the write.

```bash
sbproxy apply -f sb.yml --password demo-change-me
```

```
apply: applied to http://127.0.0.1:9090, config revision 8f10eba811d1
```

`config revision` in that line is the pipeline's own content-hash tag, a different thing from the ring's sequential `revision` number below; don't confuse them.

```bash
curl -s -u admin:demo-change-me http://127.0.0.1:9090/admin/config/history | jq .
```

```json
{
  "entries": [
    {
      "actor": "admin",
      "applied_at": "2026-08-18T04:23:57.422Z",
      "blast_radius": "reload",
      "degraded": [],
      "digest": "076956027088d7209683733e68a122b7276e414de304fa6123732ed70b06d3e0",
      "provenance": "local_file",
      "revision": 2,
      "state": "applied"
    },
    {
      "actor": "boot",
      "applied_at": "2026-08-18T04:23:49.562Z",
      "blast_radius": null,
      "degraded": [],
      "digest": "c43d279441bb6ff6c451dfb376618835253bc8515d019ea181f116a1ec152697",
      "provenance": "local_file",
      "revision": 1,
      "state": "applied"
    }
  ],
  "lineage": "44c4996c-515c-4e07-8f78-4eda3a1d85ff",
  "lkg_revision": null
}
```

`actor` is `admin`, the Basic Auth username `apply` authenticated with. `blast_radius` is `reload`: a header addition hot-swaps the pipeline without dropping a connection, so this is the cheapest change class above a no-op.

## Read one revision back

`sbproxy config show <rev>` resolves a ring revision number to its digest, then prints the stored document:

```bash
sbproxy config show 1 --password demo-change-me
```

The tail of the output is the part to look at:

```yaml
    request_modifiers:
      - headers:
          set:
            X-Demo-Var: "${DEMO_VAR}"
```

`${DEMO_VAR}` comes back exactly as written, unresolved. Nobody exported it, so if this document were ever re-applied the header value would still read `${DEMO_VAR}` literally. That is the point: the ring stores what was on disk before `${VAR}` / `vault://` / `secret://` interpolation ran, never what a request handler resolved those references to.

That is a guarantee about *resolution*, not about what an operator typed. A reference like `${DEMO_VAR}` never resolves into a stored entry, but a literal secret pasted directly into the YAML (an inline API key, a password field) is not a reference, and it stores exactly as written, the same as it sits in the file on disk. `config show` and `GET /admin/config/history/{digest}` mask a literal secret as `[REDACTED]` before either ever leaves the process, the same redaction `GET /admin/config` applies to the live editor -- but that is display redaction. The ring file underneath still holds the original bytes (a rollback needs them); the ring directory's owner-only permissions (`0700`/`0600`) are what actually protect a secret at rest there, the same as the config file itself.

The same document is available with its full envelope, including a diff against the config running now:

```bash
curl -s -u admin:demo-change-me \
  http://127.0.0.1:9090/admin/config/history/c43d279441bb6ff6c451dfb376618835253bc8515d019ea181f116a1ec152697 \
  | jq '{entry, plan_text}'
```

```json
{
  "entry": {
    "actor": "boot",
    "applied_at": "2026-08-18T04:23:49.562Z",
    "blast_radius": null,
    "degraded": [],
    "digest": "c43d279441bb6ff6c451dfb376618835253bc8515d019ea181f116a1ec152697",
    "provenance": "local_file",
    "revision": 1,
    "state": "applied"
  },
  "plan_text": "  ~ origins.api.local [reload] origin 'api.local' changed (request_modifiers) [dominant path 'origins.*.request_modifiers.0.headers.set.X-Config-Rev': origin-level field re-read on reload]\n\nPlan: 0 added, 1 changed, 0 removed. max-blast-radius: reload\n"
}
```

`plan_text` is the same `terraform plan`-style diff `sbproxy plan` renders, computed between the stored revision and whatever is running when you ask, so it stays useful even after several more revisions have landed.

## What this ring does not do yet

Today it is a local audit trail an operator reads by hand. `lkg_revision` above stayed `null` through this whole walkthrough because nothing in this release ever marks a revision as last-known-good, and nothing reads that pointer to decide anything. Reapplying a prior entry is also not implemented: `config show` prints the stored document so an operator can read or copy it, but nothing in this ring puts it back. `keep_rejected` reserves ring space for refused candidates, but writing to that space is a later change too, so a config that fails to apply is not yet recorded here at all.

To move a running config back today, use whatever put the current one there in the first place: `sbproxy apply -f <known-good.yml>`, a Kubernetes rollback, or a Helm rollback. Soak-window promotion and a rollback that reapplies a ring entry directly are follow-on work.

## Reference

- [docs/configuration.md](../../docs/configuration.md#config_history) - the `proxy.config_history` block, its fields, and the restart requirement
- [docs/admin-api-reference.md](../../docs/admin-api-reference.md#get-adminconfighistory) - the full `GET /admin/config/history` and `GET /admin/config/history/{digest}` wire contract
- [docs/operator-runbook.md](../../docs/operator-runbook.md#config-history-ring) - the ring in the context of an actual rollback procedure
