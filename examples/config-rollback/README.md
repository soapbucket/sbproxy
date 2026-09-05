# Config rollback: a change that compiles and still breaks production

*Last modified: 2026-08-28*

A config that compiles is not a config that works. This example is the smallest thing that shows the difference: two documents that differ only in an upstream port, a soak window short enough to watch, and a node that refuses to promote the one that broke traffic.

The whole walkthrough is four commands and about a minute. It needs the binary, a shell, and nothing else.

| File | What it is |
|---|---|
| `sb.yml` | the good config: one origin forwarding to an upstream on 19701 |
| `sb-broken.yml` | the same document with the port changed to 19702, where nothing listens |

The runbook this demonstrates is [docs/config-rollback.md](../../docs/config-rollback.md).

## Start an upstream and the proxy

```bash
# Terminal 1: something for the origin to forward to.
python3 -m http.server 19701

# Terminal 2:
rm -rf /tmp/sbproxy-config-rollback
sbproxy serve -f sb.yml
```

Traffic works, and the ring has its first entry:

```bash
curl -s -H 'Host: api.local' http://127.0.0.1:8080/ | head -3
curl -s -u admin:demo-change-me http://127.0.0.1:9090/admin/config/history | jq '{lkg_revision, states: [.entries[] | {revision, state}]}'
```

```json
{
  "lkg_revision": null,
  "states": [
    { "revision": 1, "state": "applied" }
  ]
}
```

`applied`, not `good`. The soak window is still open. Wait out the twenty seconds and look again:

```json
{
  "lkg_revision": 1,
  "states": [
    { "revision": 1, "state": "good" }
  ]
}
```

That is the pointer a rollback and a fallback boot both aim at. Nothing else moves it.

## Apply the change that breaks traffic

```bash
cp sb-broken.yml sb.yml
curl -s -u admin:demo-change-me -X POST http://127.0.0.1:9090/admin/reload \
  | jq '{config_revision, fully_applied, degraded}'
```

```json
{
  "config_revision": "8cb4b33d8ffc",
  "fully_applied": true,
  "degraded": []
}
```

It applies. It compiled, every module constructed, and the reload transaction committed, which is exactly the point: nothing about the document is wrong in a way a parser can see. Traffic tells a different story:

```bash
curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: api.local' http://127.0.0.1:8080/
# 502
```

## Watch the soak refuse to promote it

The health check on the target fails twice in a row, the upstream-health signal reports `failed`, and the window closes on a failing verdict:

```bash
curl -s -u admin:demo-change-me http://127.0.0.1:9090/admin/config/history \
  | jq '{lkg_revision, entries: [.entries[] | {revision, state}]}'
```

```json
{
  "lkg_revision": 1,
  "entries": [
    { "revision": 2, "state": "failed" },
    { "revision": 1, "state": "good" }
  ]
}
```

`lkg_revision` is still 1. That is the whole feature in one number: the broken document is recorded, it is serving, and it did not become the thing this node falls back to.

Revision 2 reads `failed`, not `applied`. `applied` is the state while the window is still open; the moment it closes on a failing verdict the entry becomes `failed` and stays there. That distinction is what you are grepping for mid-incident, and it is the row `sbproxy config history` shows in the `STATE` column.

The ring's rows carry the state, not the verdict. Which signal caught it is on the metric, which is also where the alert goes:

```bash
curl -s -u admin:demo-change-me http://127.0.0.1:9090/metrics \
  | grep sbproxy_config_soak_verdict_total
```

```
sbproxy_config_soak_verdict_total{signal="operator_probe",verdict="passed"} 1
sbproxy_config_soak_verdict_total{signal="upstream_health",verdict="failed"} 1
sbproxy_config_soak_verdict_total{signal="upstream_health",verdict="passed"} 1
sbproxy_config_soak_verdict_total{signal="window",verdict="failed"} 1
sbproxy_config_soak_verdict_total{signal="window",verdict="passed"} 1
```

One row per signal per verdict, plus a `window` row for the verdict the window itself closed on. The operator probe passed, because the admin port is fine; the upstream-health signal failed; and one non-abstaining failure is a failed window whatever else passed, which is what the `window` row records.

## Undo it

```bash
sbproxy config rollback --to last-known-good --password demo-change-me
```

```
config rollback: restored revision 1 (2c26b46b68ffc68ff99b453c1d3041341340d0d0d0d0d0d0d0d0d0d0d0d0d0d0), blast radius reload
config rollback: revision 2 is marked reverted
config rollback: appended as revision 3; history is append-only, so this rollback is itself in the history
config rollback: the restored revision is soaking like any other candidate. POST /admin/config/confirm promotes it early; a failed soak leaves the last-known-good pointer where it is
config rollback: warning: this node's config file is unchanged: the next file-watcher event, SIGHUP, source: poll, or authority bundle re-applies whatever the source of truth still says. fix it before then
```

Read that last line. The rollback put a *document* back; it did not touch `sb.yml`. The file on disk still says 19702, and the next thing that touches it will undo your undo. Restore it before you walk away:

```bash
git checkout sb.yml   # or however your config gets there
```

## What `auto_revert` would have changed

Set `soak.auto_revert: true` in `sb.yml` and run the walkthrough again. Everything up to the failing verdict is identical. Then the node reverts on its own: revision 2 goes from `failed` to `reverted`, the good document comes back, and `sbproxy_config_apply_total{outcome="reverted"}` counts one.

It ships off, and [docs/config-rollback.md](../../docs/config-rollback.md#auto_revert-and-why-it-ships-off) has the reasoning. The short version: a node that undoes an operator's change without being asked is surprising in a way that costs trust, and it is only ever half a fix, because whatever produced the bad document still says what it said.

## Related

- [docs/config-rollback.md](../../docs/config-rollback.md) - the operator runbook this example is the runnable half of.
- [examples/config-history](../config-history/) - the ring itself: what is stored, and what a stored document does and does not contain.
- [docs/configuration.md](../../docs/configuration.md#config_history) - every field in the block.
