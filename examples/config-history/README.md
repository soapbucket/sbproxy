# Config history: a durable local ring of every applied config

*Last modified: 2026-08-28*

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

That is a guarantee about *resolution*, not about what an operator typed. A reference like `${DEMO_VAR}` never resolves into a stored entry, but a literal secret pasted directly into the YAML (an inline API key, a password field) is not a reference, and it stores exactly as written, the same as it sits in the file on disk. `config show` and `GET /admin/config/history/{digest}` mask a literal secret as `[REDACTED]` before either ever leaves the process, the same redaction `GET /admin/config` applies to the live editor. The masking is by recognized credential shape and key name, so a secret under a name the redactor does not recognize comes back as written -- and it is display redaction either way. The ring file underneath still holds the original bytes (a rollback needs them); the ring directory's owner-only permissions (`0700`/`0600`) are what actually protect a secret at rest there, the same as the config file itself.

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

## Watch a revision soak

`lkg_revision` is `null` in the responses above, and it stays that way until a revision earns the pointer. Recording is not promoting: a config that compiles is not a config that works, and the whole point of this block is that something has to observe the config running before it becomes the thing you would roll back to.

This example arms a 15 second window on every reload and points an operator probe at the admin server's `/healthz`. Reload once, then watch:

```bash
curl -s -u admin:demo-change-me http://127.0.0.1:9090/metrics \
  | grep -E 'sbproxy_config_(lkg_revision|soak_verdict_total)'
```

```
sbproxy_config_lkg_revision 2
sbproxy_config_soak_verdict_total{signal="operator_probe",verdict="passed"} 1
sbproxy_config_soak_verdict_total{signal="request_outcome",verdict="abstain"} 1
sbproxy_config_soak_verdict_total{signal="upstream_health",verdict="abstain"} 1
sbproxy_config_soak_verdict_total{signal="degraded_subsystems",verdict="abstain"} 1
sbproxy_config_soak_verdict_total{signal="window",verdict="passed"} 1
```

Three signals abstained and one passed, so the window passed and `lkg_revision` moves off `-1` to the revision that just soaked. Three of those abstentions are worth reading:

- `request_outcome` abstains because a demo box serves no traffic. Below `min_requests` it reports nothing rather than calling four requests and one error a 25% failure rate. This is the mistake that produces spurious rollbacks in canary systems, and abstaining is the fix.
- `degraded_subsystems` abstains on a *clean* reload. It is a veto, not a promoter: nothing came up degraded, which proves the config constructed and proves nothing about whether it works.
- `upstream_health` abstains because this example's origin is a `type: proxy` with no `health_check:`, `circuit_breaker:`, or `outlier_detection:` block, so there is nothing for the soak to read. It will not report health it never looked for. That is also why this walkthrough declares a `probe:` rather than relying on `proxy.synthetic_probe`: the synthetic origin is a non-network action, and while `upstream_health` is blind a synthetic pass cannot promote on its own. On a node whose origins all answer from the proxy itself there is no upstream to be blind to, and the driver alone is enough.

Comment out the `probe:` block and reload again, and every signal abstains. The verdict is then `inconclusive`, `lkg_revision` stays where it was, and the entry stays `applied` rather than reaching `good`. That is deliberate. Promoting on a window that measured nothing would be promote-on-apply with fifteen extra seconds attached.

A deployment pipeline does not have to wait:

```bash
curl -s -u admin:demo-change-me -X POST http://127.0.0.1:9090/admin/config/confirm | jq .
```

```json
{
  "revision": 2,
  "verdict": "passed",
  "promoted": true,
  "signals": [
    {"signal": "degraded_subsystems", "outcome": "abstain", "detail": "no subsystem stayed on prior state, which is not by itself evidence that this config works"},
    {"signal": "upstream_health", "outcome": "abstain", "detail": "1 origin(s) expose no health signal, so this cannot say their upstreams are reachable: default/api.local. declare a health_check, a circuit_breaker, or an outlier detector on them, or a soak probe that exercises them"},
    {"signal": "request_outcome", "outcome": "abstain", "detail": "the window observed 0 request(s), under the min_requests of 5"},
    {"signal": "operator_probe", "outcome": "passed", "detail": ""}
  ]
}
```

That short-circuits the wait, not the judgment. Read `promoted` rather than assuming a `200` means the pointer moved.

## Break the config on purpose

Two things happen when you push a config that does not apply, and both of them are new here.

First, the refusal is kept. Add a misspelled key to `sb.yml` and save it:

```bash
printf '\n  http2_cleartextt: true\n' >> sb.yml   # under proxy:
curl -s -u admin:demo-change-me http://127.0.0.1:9090/admin/config/rejected | jq '.entries[0]'
```

```json
{
  "digest": "3f79bb7b435b05321651daefd374cdc681dc06faa65e374e38337b88ca046dea",
  "reason": "compile_failed",
  "stage": "file_watcher",
  "detail": "unknown field `http2_cleartextt`",
  "count": 1,
  "first_seen_at": "2026-08-26T09:02:11.004Z",
  "last_seen_at": "2026-08-26T09:02:11.004Z"
}
```

The node always knew this; before, it became a log line and then it was gone. Save the same broken file again and `count` goes to 2 rather than a second row appearing.

Second, restart with the file still broken. `boot.fallback` is `last_known_good` in this example, so the node walks the ring instead of exiting:

```
WARN this node booted on a configuration restored from its revision ring, not on the
     config file it was pointed at. the file watcher, SIGHUP, and the source: refresh
     poller are suspended until an operator clears the pin with
     DELETE /admin/config/fallback revision=2
```

```bash
curl -s -u admin:demo-change-me http://127.0.0.1:9090/admin/config/fallback | jq .
```

```json
{
  "active": true,
  "revision": 2,
  "digest": "c43d279441bb6ff6c451dfb376618835253bc8515d019ea181f116a1ec152697",
  "suspended": ["file_watcher", "sighup", "config_refresh_poller"]
}
```

Fix the file and save it, and nothing happens: the watcher is suspended, which is the point. Leaving it live would re-apply the broken file on the next save in that directory and loop straight back into the state the fallback just rescued the node from. Clear the pin and the three suspended paths come back without a restart:

```bash
curl -s -u admin:demo-change-me -X DELETE http://127.0.0.1:9090/admin/config/fallback | jq .
```

Set `boot.fallback: off` (the shipping default) and the same restart exits 1 with the compile error, exactly as it always has.

## Roll back

Look before you leap. `config diff` renders a plan between what is running
and a stored revision, or between two stored revisions, and touches
neither:

```bash
sbproxy config diff 1 --password demo-change-me
```

```
config diff: the running configuration -> revision 1, largest blast radius hitless
~ origins.api.local.request_modifiers
```

Then do it. `--expected-current` is optional and worth typing: it refuses
if somebody else moved this node between your `config history` and your
rollback, rather than silently undoing their change.

```bash
sbproxy config rollback --to 1 --expected-current 2 --password demo-change-me
```

```
config rollback: restored revision 1 (c43d2794...), blast radius hitless
config rollback: revision 2 is marked reverted
config rollback: appended as revision 3; history is append-only, so this rollback is itself in the history
config rollback: the restored revision is soaking like any other candidate. POST /admin/config/confirm promotes it early; a failed soak leaves the last-known-good pointer where it is
config rollback: warning: this node's config file is unchanged: the next file-watcher event, SIGHUP, source: poll, or authority bundle re-applies whatever the source of truth still says. fix it before then
```

Three things that walkthrough shows and are easy to miss:

* The ring now holds **three** entries, not two. History is append-only, so
  the rollback is itself in the history and a second rollback can undo it.
  Read it back with `sbproxy config history` and revision 2's state is
  `reverted`.
* The restored revision **soaks**. It is an ordinary candidate: it
  resolved, it compiled, it published through the same transaction, and
  its own window is open. `POST /admin/config/confirm` closes that early.
* The config **file** is untouched. This example's file still holds the
  edit you made, so the next save in that directory re-applies it. On a
  real node, fix the source of truth as the second half of the recovery.

Ask for something that is not there and the refusal names what is:

```bash
curl -s -u admin:demo-change-me -X POST \
  http://127.0.0.1:9090/admin/config/rollback \
  -H 'content-type: application/json' -d '{"revision": 99}' | jq .
```

```json
{
  "error": "revision 99 is not in this node's config revision ring. available: 1, 2, 3",
  "code": "unknown_revision",
  "rolled_back": false,
  "available_revisions": [1, 2, 3]
}
```

## Let it revert on its own (or do not)

`soak.auto_revert` in this example is `false`, which is the shipping
default and the setting most deployments should run. With it off the soak
still runs, still promotes, and still alerts; what changes is only whether
the node is allowed to undo an operator's change without being asked.

Flip it to `true` in `sb.yml` and restart, and a failed soak on a `hitless`
or `reload` class change re-applies the last known good through the same
path the manual rollback above uses. Watch
`sbproxy_config_apply_total{outcome="reverted"}`, which is disjoint from
the `applied` a manual rollback counts.

What it will **not** do, and the log says so at WARN with the radius
named: revert a `restart` or `breaking` change. Change
`proxy.http_bind_port` in this example, let the soak fail, and the node
leaves it running rather than half-undoing it, because swapping the
pipeline pointer back does not unbind a socket. Boot fallback (already on
above) and `POST /admin/config/rollback` are the answer for that class.

It also will not loop. If the revision an automatic revert restored then
fails its own soak, the node escalates at ERROR instead of reverting to
itself, because both the new config and the last known good are failing
the same signals and a second swap does not fix that.

## What this ring does not do yet

The console's Config page already draws the ring: every revision with its state badge and blast radius, the lineage, which revision the last-known-good pointer names, and the stored document and plan for any row you click. What it has no control for is acting on one. Rolling back is the admin API and the CLI only, and the Roll back button is tracked separately.

The gating rule that button will use (a `restart` or `breaking` rollback, or one whose radius could not be measured, needs the revision typed back) ships ahead of it as a tested function in `ui/src/lib/config-history.ts`, so the panel inherits the rule rather than reinventing it.

The two are not computing the same radius, though, and whoever wires the button has to close that. The client can only see the radius `GET /admin/config/history` stored on the entry, which was measured against the revision before it at the time it applied. The server measures the running document against the target at the moment you ask. Those are different pairs of documents, so the two can disagree in either direction: the button may wave through a rollback the route then refuses with a `409`, or demand a confirmation the route would not have. The route is always the one that decides.

## Reference

- [docs/configuration.md](../../docs/configuration.md#config_history) - the `proxy.config_history` block, its fields, and the restart requirement
- [docs/admin-api-reference.md](../../docs/admin-api-reference.md#get-adminconfighistory) - the full `GET /admin/config/history` and `GET /admin/config/history/{digest}` wire contract
- [docs/admin-api-reference.md](../../docs/admin-api-reference.md#get-adminconfigrejected) - `GET /admin/config/rejected`, `POST /admin/config/confirm`, and the fallback routes
- [docs/admin-api-reference.md](../../docs/admin-api-reference.md#post-adminconfigrollback) - `POST /admin/config/rollback` and `GET /admin/config/diff`, with every refusal code
- [docs/configuration.md](../../docs/configuration.md#auto_revert) - `soak.auto_revert`, why it ships off, and the blast-radius arming rule
- [docs/operator-runbook.md](../../docs/operator-runbook.md#config-history-ring) - the ring in the context of an actual rollback procedure, including the soak window and the fallback boot
