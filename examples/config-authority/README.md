# Config authority: fleet configuration distribution

*Last modified: 2026-08-16*

One node signs a configuration and the rest of the fleet verifies it and applies it, so a change ships once instead of being copied to every box. Every payload carries an Ed25519 signature and a monotonic revision, and the authority validates it exactly the way boot does before it signs anything.

This directory holds both halves and the payload that travels between them:

| File | Role |
|---|---|
| `sb.yml` | the authority: validates, signs, stores, and serves |
| `subscriber.yml` | a fleet node: polls, verifies, merges, applies |
| `bundle.yml` | the payload an operator publishes |

A node is either an authority or a subscriber, never both. Setting `publish` and `upstream` on one node is a config error.

## Why this exists

Configuration in a file is configuration you have to copy to every box. The usual answers are a config-management tool that rewrites files and restarts processes, or a control plane that holds the truth and hands it out. This is the second, with two properties that matter when the fleet is bigger than the change window:

- **Every payload is signed.** A subscriber verifies an Ed25519 signature over the canonical bundle before it compiles anything, so an authority that gets compromised at the network layer still cannot push configuration. A revision counter refuses a replay of an older bundle, and it survives a restart.
- **The authority validates exactly what boot validates.** `compile_config` alone leaves `action`, `policies`, `transforms`, and `authentication` as opaque JSON, so a typo inside a policy entry would sign cleanly and then fail on every subscriber at once. The publish path runs the module constructors and the model-host checks too, so a payload that cannot boot never gets a revision number.

The subscriber also owns a list of paths no authority can touch: `proxy.listeners`, `proxy.tls`, `proxy.admin`, `proxy.secrets`, `proxy.cluster`, `proxy.model_host`, `proxy.config_authority`, `source`, and `origin_sources`. A payload that names one is refused at publish time and, if it somehow arrives anyway, refused again at merge time. That is what keeps a fleet-wide push from taking away the admin port you would use to undo it.

## Two ways to drive it

Every step below is shown as a `curl` against the admin API, because that is the contract and a non-SBproxy control plane can implement it. The CLI wraps the same routes and is what you would actually use day to day:

| Instead of | Run |
|---|---|
| generating a key by hand | `sbproxy config authority init --dir /etc/sbproxy` |
| `POST .../subscribers` | `sbproxy config authority subscriber add edge-01` |
| `POST .../publish` | `sbproxy config authority publish -f bundle.yml` |
| `GET .../status` | `sbproxy config authority status` |
| `POST .../subscribers/revoke` | `sbproxy config authority subscriber revoke --credential-id <id>` |
| reading a diff out of the logs | `sbproxy config pull sb.yml --dry-run` on a subscriber |

The CLI also runs the authority's own validation locally before it sends anything, so a payload that would be refused never spends a revision number, and it has an exit-code contract (`4` the authority refused, `7` the authority was unreachable) that a deploy script can branch on. See [manual.md](../../docs/manual.md#config-authority---operate-a-config-authority).

## Set up the authority

Generate a signing key. It is a 32-byte Ed25519 seed in standard base64, and it must be owner-only:

```bash
export ADMIN_PASSWORD=pick-a-real-one
mkdir -p /var/lib/sbproxy/config-authority
sbproxy config authority init --dir /etc/sbproxy
export SB_CONFIG_AUTHORITY_SIGNING_KEY=/etc/sbproxy/authority-signing.key
```

`init` writes the seed to `authority-signing.key` at mode 0600 and the verifying-key file subscribers install to `authority-keys.json`, then prints what to copy where. It refuses to overwrite an existing signing key; `--force` rotates and keeps the old verifying key in the map so subscribers keep verifying while they are updated.

By hand, if you would rather:

```bash
head -c 32 /dev/urandom | base64 > /etc/sbproxy/authority-signing.key
chmod 600 /etc/sbproxy/authority-signing.key
```

A publishing node refuses to start with the shipped default admin password, whatever `proxy.admin.bind` says, and refuses to start if the signing key is missing, oversized, group-readable, or not a 32-byte seed. Both are startup failures rather than surprises during a change window.

```bash
make run CONFIG=examples/config-authority/sb.yml
```

Two listeners come up. The admin server on `127.0.0.1:9090` is where an operator publishes; the bundle listener on `127.0.0.1:9443` is where subscribers fetch. They are separate on purpose: subscribers present a long-lived fleet credential, and that credential should not reach an admin surface.

## Register a subscriber

```bash
curl -sS -u admin:"$ADMIN_PASSWORD" \
  -H 'Content-Type: application/json' \
  -d '{"subscriber_id":"edge-01"}' \
  http://127.0.0.1:9090/admin/config-authority/subscribers
```

```json
{
  "schema_version": 1,
  "subscriber_id": "edge-01",
  "credential_id": "0lJ8kQ2vTn5mAqRt",
  "credential": "sbca1.0lJ8kQ2vTn5mAqRt.9pQx7Yb2ZmKd3Lw8Rn6Tf1Vc4Hs0Jg5Ee2Aa8Bb1Cc",
  "note": "shown once and never again; the authority keeps only a SHA-256 fingerprint..."
}
```

The clear credential appears exactly once. The authority stores only a SHA-256 fingerprint of it, so the registry file is not a credential store: someone who reads it cannot authenticate with it. Give the token to the subscriber by secret reference:

```bash
export SB_CONFIG_AUTHORITY_TOKEN='sbca1.0lJ8kQ2vTn5mAqRt.9pQx7Yb2ZmKd3Lw8Rn6Tf1Vc4Hs0Jg5Ee2Aa8Bb1Cc'
```

## Publish the authority's public key

Subscribers need the verifying key, and `status` hands it over in the exact file shape they install:

```bash
curl -sS -u admin:"$ADMIN_PASSWORD" \
  http://127.0.0.1:9090/admin/config-authority/status \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["verifying_keys_file"])' \
  > /etc/sbproxy/authority-keys.json
```

```json
{
  "authority-2026-07": {
    "algorithm": "ed25519",
    "key": "3p8Q0mB1yV4kX7wR2tL6nS9cF5jH0dA8gZ2eK4uY1oM="
  }
}
```

Rotation is additive: publish under a new `key_id` while subscribers still trust the old one, then drop the old entry a window later. No restart on any node: a subscriber re-reads this file on every poll that returns a bundle, so adding an entry starts verifying and removing one stops verifying immediately. The removal half is the one worth knowing about, because it means revoking a leaked key is an edit rather than a rolling restart.

## Publish a configuration

```bash
curl -sS -u admin:"$ADMIN_PASSWORD" \
  --data-binary @examples/config-authority/bundle.yml \
  'http://127.0.0.1:9090/admin/config-authority/publish?mode=overlay'
```

```json
{
  "schema_version": 1,
  "authority_id": "control-plane-lab",
  "key_id": "authority-2026-07",
  "revision": 1,
  "content_digest": "sha256:fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9",
  "etag": "\"1-sha256:fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9\"",
  "mode": "overlay",
  "issued_at_unix_ms": 1753401600000
}
```

Break the payload on purpose and the refusal names the step that caught it and says whether it spent a revision number. Read `revision_consumed` rather than inferring the spend from the code: a validation refusal like this one costs nothing, so it is `false`; `signing_failed` and `internal` are always after the reservation and report `true`; and `store_failed` sits on both sides of it, because the store both reserves the number and persists the bundle:

```json
{
  "error": "config authority publish rejected: the payload compiles, but a module failed to construct, so every subscriber would refuse it at boot: unknown policy type ...",
  "code": "construct_failed",
  "revision_consumed": false
}
```

`mode` has to match what the subscriber is configured for. A `replace` payload applied as an overlay would keep keys its author meant to drop, so the subscriber refuses the disagreement rather than guessing.

## Start a subscriber

```bash
make run CONFIG=examples/config-authority/subscriber.yml
```

The first poll fetches the bundle, verifies it, merges it over `subscriber.yml`, and applies the result through the same three-phase transaction a SIGHUP takes. Boot does no network I/O: a node with an empty cache boots on its local document under `overlay` (with a loud warning) or refuses to start under `replace`, and the first poll a few seconds later brings the authority's document in.

## Watch the rollout

```bash
curl -sS -u admin:"$ADMIN_PASSWORD" \
  http://127.0.0.1:9090/admin/config-authority/status
```

```json
{
  "current_revision": 2,
  "previous_revision": 1,
  "high_water_revision": 2,
  "subscriber_count": 2,
  "live_subscriber_count": 2,
  "subscribers": [
    {
      "subscriber_id": "edge-01",
      "credential_id": "0lJ8kQ2vTn5mAqRt",
      "revoked": false,
      "last_seen_revision": 2,
      "last_seen_at_unix_ms": 1753401660000,
      "up_to_date": true
    },
    {
      "subscriber_id": "edge-02",
      "credential_id": "7bN2xW9pQr4sTu6v",
      "revoked": false,
      "last_seen_revision": 1,
      "last_seen_at_unix_ms": 1753401612000,
      "up_to_date": false
    }
  ]
}
```

`up_to_date` is the question an operator actually has during a rollout, so it is answered rather than left as arithmetic. `high_water_revision` above `current_revision` means a revision was reserved and never published, which happens when the process died mid-publish; the number is burned rather than reused, because a subscriber may already hold it.

## Undo a bad revision

```bash
sbproxy config authority rollback
```

```json
{
  "schema_version": 1,
  "revision": 3,
  "restored_from_revision": 1,
  "replaced_revision": 2,
  "mode": "overlay"
}
```

The store keeps the current bundle and the one before it for exactly this. Note that the number moves *forward*: the previous revision's payload is republished as a new revision rather than re-served under its old number, because a subscriber's replay cursor refuses any revision that is not greater than the one it applied. Re-serving revision 1 would reach only the nodes that had not yet taken 2, which is the opposite of what you want at that moment.

The payload is revalidated on the way through, so a configuration that published cleanly before a binary upgrade and no longer constructs after one is refused here rather than pushed to the fleet. With nothing to go back to, the answer is `400` with code `no_previous_revision` and `"revision_consumed": false`.

## Retire a credential

```bash
curl -sS -u admin:"$ADMIN_PASSWORD" \
  -H 'Content-Type: application/json' \
  -d '{"credential_id":"0lJ8kQ2vTn5mAqRt"}' \
  http://127.0.0.1:9090/admin/config-authority/subscribers/revoke
```

Pass `{"subscriber_id":"edge-01"}` instead to retire every credential that node holds. Revocation takes effect on the next fetch and survives a restart. A revoked subscriber keeps serving the configuration it already applied rather than losing it: an expired credential should not take a node down.

To rotate without a gap, register a second credential for the same `subscriber_id`, deploy it, then revoke the first.

## See who owns what on the subscriber

Once a subscriber applies a bundle, "show me the config" has two different answers on that node. `GET /admin/config` is still its own file. `GET /admin/config/effective` is the document actually running, with the layer that set each setting:

```bash
curl -sS -u admin:"$ADMIN_PASSWORD" \
  http://127.0.0.1:9091/admin/config/effective | jq '{locally_owned, layers, provenance}'
```

```json
{
  "locally_owned": false,
  "layers": {
    "base": {"kind": "local"},
    "authority": {"authority_id": "control-plane-lab", "revision": 2, "mode": "overlay"}
  },
  "provenance": {
    "proxy.http_bind_port": "local",
    "proxy.admin.port": "local",
    "origins.edge.example.com.action.url": "authority"
  }
}
```

`locally_owned` is the flag the admin console reads to decide whether to offer its config editor at all.

## Watch a write get refused

The subscriber's own file is still on disk, and editing the parts the authority owns would look like it worked and then vanish at the next poll. So the write is refused instead:

```bash
# The authority sets origins.edge.example.com.action.url, so this edit cannot survive.
curl -sS -u admin:"$ADMIN_PASSWORD" -X PUT \
  --data-binary @- http://127.0.0.1:9091/admin/config <<'YAML'
proxy:
  http_bind_port: 8080
origins:
  edge.example.com:
    action:
      type: proxy
      url: https://not-the-authoritys-value.test
YAML
```

```json
{
  "error": "this node does not own the edited path: origins.edge.example.com.action.url",
  "code": "config_not_locally_owned",
  "conflicts": [{"path": "origins.edge.example.com.action.url", "owner": "authority"}],
  "remedy": "authority control-plane-lab owns these paths at revision 2; publish the change through the authority with `sbproxy authority publish`"
}
```

Now change something the authority does not set. Under `mode: overlay` that still works, because the guard is per-setting rather than per-node:

```bash
# proxy.http_bind_port is not in the bundle, so this is still this node's to change.
curl -sS -u admin:"$ADMIN_PASSWORD" -X PUT \
  --data-binary @- http://127.0.0.1:9091/admin/config <<'YAML'
proxy:
  http_bind_port: 8081
origins:
  edge.example.com:
    action:
      type: proxy
      url: https://test.sbproxy.dev
YAML
```

Under `mode: replace` the same node keeps only the subscriber-owned paths, so `proxy.admin`, `proxy.tls`, and `proxy.secrets` remain editable and almost nothing else is. That is deliberate: a central authority that could take the admin listener could take away the port you would use to undo a bad push.

Refusals land in the audit log, not only successful writes:

```bash
grep 'rejected_not_locally_owned' /var/log/sbproxy.log
```

## Build an editor against the running binary's schema

`GET /admin/config/schema` serves the JSON Schema generated from the types the running binary parses with, so a form cannot offer fields the proxy would reject:

```bash
curl -sS -u admin:"$ADMIN_PASSWORD" -D /tmp/schema-headers \
  http://127.0.0.1:9091/admin/config/schema > /tmp/sb-config.schema.json
grep -i etag /tmp/schema-headers
```

The document is around 440KB and immutable for a given build, so send the `ETag` back as `If-None-Match` and get a `304` on every load after the first.

## Reference

Full field tables and the wire contract are in [docs/configuration.md](../../docs/configuration.md#config-authority-fleet-configuration-distribution). The endpoint reference is in [docs/admin-api-reference.md](../../docs/admin-api-reference.md#get-adminconfigeffective).
