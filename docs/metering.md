# Attested metering

*Last modified: 2026-08-02*

![A metered request cuts a signed receipt, the chain verifies, one tampered entry on disk breaks it, and the verifier names the broken sequence number](assets/metering-verify.gif)

Attested metering turns "trust my dashboard" into "check my math". When `proxy.attestation` is on, every request an attesting origin serves cuts a receipt: who consumed, on which route, how many units, under which outcome, priced by which configuration. Each receipt is Ed25519-signed and hash-chained to the one before it on an append-only ledger, so editing any past record breaks every link after it, and a buyer holding nothing but the operator's published key set can re-derive the whole chain and catch the edit.

Two halves make up attestation, and they answer the two halves of a billing dispute. A claim is made before a call and says what it is going to cost. A receipt is written after it and says what it actually consumed. This page is about receipts: configuring the meter, reading it, verifying the chain, and handing a buyer something they can check without trusting you. For charging before the call is served, see [payment-settlement.md](payment-settlement.md).

## Metrics are not the billing record

The proxy exports `sbproxy_meter_*` metric families, and they are the right tool for dashboards and alerts. They are the wrong tool for billing, for three reasons that are structural rather than fixable:

- OTLP export is best-effort. An exporter that cannot reach its collector drops data, and nobody is credited for the drop.
- Counters reset. A process restart zeroes them, and a scrape that lands after the reset reads a quiet hour that was not quiet.
- Aggregation destroys events. A counter says "40,000 units this month" and cannot answer "which call, which route, which outcome", which is the entire content of a dispute.

The signed chain is the authoritative record. It is written before the metric is scraped, it survives restarts, it names every call individually, and it is the only surface here whose integrity can be checked by someone who does not trust the operator. When the counters and the chain disagree, the chain wins, and `sbproxy_meter_divergence_total` exists so somebody notices the disagreement.

## Configuration

The config below is `examples/metering-verify/sb.yml`, the runnable example this page walks through. One origin proxies the example's own demo upstream (`bin/upstream.py`, a stdlib HTTP server that answers every path with a small article, so metered requests carry real egress bytes); the attestation block makes every call it serves a metered one.

<!-- sbproxy-config: examples/metering-verify/sb.yml -->
```yaml
proxy:
  http_bind_port: 8080

  # Only because the demo upstream runs on this machine: the SSRF guard
  # refuses private upstream addresses unless allowlisted. A production
  # config pointing at a real origin does not need this block.
  extensions:
    upstream:
      allow_private_cidrs:
        - '127.0.0.1/32'

  # The meter's operator surface: /api/meter/summary, /api/meter/receipts,
  # and POST /api/meter/verify all live on the admin server.
  admin:
    enabled: true
    port: 9090
    username: admin
    # Demo password for local runs. Change before any non-loopback bind.
    password: demo-change-me

  # The signing identity receipts are cut with. Demo key only: this is
  # the published RFC 8032 test vector, the same pair
  # docs/web-bot-auth.md uses, so the walkthrough runs without
  # generating keys. Generate your own before metering real traffic.
  web_bot_auth:
    key_id: metering-demo-2026
    ed25519_seed_hex: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"

  attestation:
    # This proxy records what calls actually consumed, after serving
    # them. `claim` asserts cost before the call; `both` does both.
    role: receipt

    # What happens when metering itself breaks (full ledger disk,
    # unusable signing key): serve the call, mark the guarantee as not
    # made, count the gap. `closed` refuses traffic instead.
    failure_mode: degraded

    # What happens when attestation reaches a "refuse" verdict.
    # `observe` records the verdict without acting on it.
    enforcement_mode: block

    # Receipts sign with the identity above; the ledger chain signs
    # with the same key, so a buyer fetches one key set for both.
    sign_with: proxy.web_bot_auth

    # Claims wait here between "call started" and "call settled".
    queue:
      path: '/tmp/sbproxy-metering/claims'

    # The receipt chain: an append-only JSONL file, one signed,
    # hash-chained entry per metered call. This is the tamper target
    # in the verify demo.
    ledger:
      path: '/tmp/sbproxy-metering/receipts.ndjson'

    # The outcome table: all eight answers are required, and none is
    # defaulted. "yes" bills every unit, "no" bills nothing (the call
    # is still recorded), "partial" bills the work performed before a
    # cut, "collapse" folds retries into one invoice line.
    billable:
      delivered: "yes"
      client_disconnected: partial
      origin_4xx: "no"
      origin_5xx: "no"
      policy_blocked: "no"
      rate_limited: "no"
      # Both answers are defensible here; this deployment sells
      # answers, so a cache hit bills. See docs/metering.md.
      cache_hit: "yes"
      retry: collapse

    # Units the proxy counted itself: bytes on the wire, kibibyte
    # granularity, partial units bill whole.
    measured:
      - name: egress_kib
        quantity: bytes_out
        per: 1024

    # Routes priced in this document. The signed config revision on
    # each receipt is what lets a buyer check the price applied.
    route_weights:
      - name: api_call
        path: '/anything/*'
        weight: 1

origins:
  "api.local":
    action:
      type: proxy
      # The example ships its own upstream so metered requests carry
      # real egress bytes: python3 bin/upstream.py
      url: 'http://127.0.0.1:8099'

    # Names the commercial agreement receipts on this origin bill
    # under. The role is inherited from proxy.attestation.
    attestation:
      agreement_id: agreement-2026-001

    # Publish the signing key's public half, JWKS-shaped, at
    # /.well-known/http-message-signatures-directory on this origin.
    # This is the key set a buyer verifies receipts against.
    web_bot_auth_publish:
      enabled: true
      key_id: metering-demo-2026
      public_key_hex: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
      agent_name: metering-demo
      directory_url: "https://api.local/.well-known/http-message-signatures-directory"
```

Each component, and when you would change it:

### `role`

Which halves of attestation this proxy performs. Four values, because the two halves are independently useful:

- `off`: attest to nothing. The default, and what every config that does not mention the block gets.
- `claim`: assert what a call is going to cost, before it is served. The posture for a gateway in front of somebody else's metered API.
- `receipt`: record what a call actually consumed, after it is served. The posture for a proxy selling its own upstream, and the one this page demonstrates.
- `both`: claims and receipts. The posture for reselling metered capacity, where you answer to a buyer and a supplier at once.

Individual origins can narrow or widen the proxy-wide role through `origins.<host>.attestation.role`, because one gateway commonly fronts both a partner API it resells and its own service.

Once the role is anything but `off`, the queue, the ledger, and a complete `billable` table are all required, and `sign_with` is required whenever the role writes receipts. Each of those requirements fails at config compile, with a message naming what is missing, rather than at the moment somebody disputes an invoice.

### `failure_mode`

What happens when metering itself cannot run: the queue is full, the ledger will not accept an append, the signing identity is unusable. Four postures:

- `closed`: refuse the request. Choose this only if you genuinely cannot serve unbilled traffic, and mean it, because a full ledger disk then takes your API down.
- `open`: admit the request and claim nothing. Cheapest, and the least recoverable after the fact, because nothing marks the hole.
- `degraded`: admit the request while explicitly marking the guarantee as not made. The default for this block. The call proceeds, the gap is counted through `sbproxy_meter_chain_gap_total`, and wherever a chain survives to be written to, the gap is marked in the chain itself.
- `observe`: admit the request and record what the control would have done. The rollout posture for a control being tuned against live traffic.

The `degraded` default is a deliberate departure from the fail-closed default the rest of the config surface takes. Fail-closed is right for a security boundary, because a control that silently admits traffic when it breaks is worse than no control. Billing is not a security boundary: a provable hole in the record is a better outcome than the whole API going down over a disk, and `degraded` is precisely the posture that keeps the hole provable.

### `enforcement_mode`

A different question from `failure_mode`, and the two are easy to conflate. `failure_mode` decides what happens when attestation cannot run. `enforcement_mode` decides what happens when it runs fine and the verdict is "refuse", for example a claim that exceeds an agreement's ceiling. `block` acts on the verdict; `observe` records it and admits the call anyway. A control can reasonably observe while it is being tuned and still fail closed when its backend disappears, which is why these are two knobs and not one.

### `sign_with` and the signing identity

A receipt nobody can verify is a log line, so a role that writes receipts must name a signing identity. The only accepted value today is `proxy.web_bot_auth`, pointing at an identity your config already declares rather than inventing a second one. The same Ed25519 key signs the receipt tokens and the ledger chain entries, so a buyer fetches one key set and checks everything with it, instead of discovering a second key-distribution problem at the moment they are ready to pay.

The public half is published by opting the origin into `web_bot_auth_publish`, which serves a JWKS-shaped directory at `/.well-known/http-message-signatures-directory` on the data plane. That URL is the whole trust bootstrap for the buyer flow below. See [web-bot-auth.md](web-bot-auth.md) for the directory format and key generation.

### `queue` and `ledger`

The queue is where claims wait between "call started" and "call settled"; the gap between those two moments is where a crash loses money, and the queue is that gap made durable. The ledger is the receipt chain itself: an append-only JSONL file, one entry per metered call, each entry hash-chained to its predecessor and signed. Both paths become required as soon as a role is declared.

The ledger file is its own write-ahead log: each entry is serialized, written, and flushed before the append returns. Appends happen after the response is already sent, so metering never adds latency to the call it records, and a metering defect can never fail the request it is reporting on.

### `billable`: the outcome table

Every metered call ends in exactly one of eight outcomes: `delivered`, `client_disconnected`, `origin_4xx`, `origin_5xx`, `policy_blocked`, `rate_limited`, `cache_hit`, `retry`. The table gives the billing answer for each: `yes` bills every unit the call produced, `no` bills nothing, `partial` bills the work performed before a cut, and `collapse` folds every attempt at one unit of work into the invoice line its claim names, so a flaky origin costs the buyer once rather than once per attempt.

All eight answers are required and none is defaulted, on purpose. An unstated billing rule still runs; it just runs as whatever the code happened to do, and nobody discovers what that was until a buyer asks. An outcome the table says is free still gets a receipt, with an empty units list: "not billed, because the table says origin_5xx is free" is exactly the evidence a dispute needs, and an omitted receipt would be indistinguishable from a call that never happened.

`cache_hit` deserves an honest paragraph, because it is a commercial decision wearing a config key. A vendor selling compute can argue a cache hit cost them nothing and should bill nothing. A vendor selling answers can argue the answer is what was bought, and where it came from is their business. Both are positions real companies hold, both are defensible, and this surface deliberately holds neither: you have to write the answer down, and the receipt then records which answer applied. The example bills cache hits because it sells responses, not CPU time; reverse it if your pricing story is compute.

### Unit resolvers: `measured`, `route_weights`, `origin_headers`

Three ways to turn a request into billable units, kept as three separate lists because each has its own provenance and its own way of being wrong, and a receipt read back must never confuse them.

`measured` counts what the proxy observed on the wire: `requests`, `bytes_in`, `bytes_out`, or `duration_ms`, divided by `per` to set the unit size (`per: 1024` against `bytes_out` bills one unit per kibibyte written). It is the resolver to reach for first, because nothing outside the process contributed to the number: the proxy saw the bytes and held the clock. A partial unit bills as a whole one; the operator delivered those bytes, and there is no fraction of a kibibyte to hand back.

`route_weights` is a price list written into the config: this route costs this many units of this name. The most specific match wins (a named method beats an unnamed one, an exact path beats a prefix, a longer prefix beats a shorter one), and a `weight: 0` route is metered and free, which is not the same as an unpriced one. The number is a pure function of the route and the config document, and the receipt names that document's revision, so a buyer can check the price themselves.

`origin_headers` reads a count from a response header the upstream sends, for the APIs whose real unit only the origin knows (result rows, for example). It is the only resolver that can be wrong without the proxy being wrong, because the party supplying the number is the party being paid for it. So the proxy attests rather than vouches: the receipt records the header name and the raw value exactly as it arrived, and a value that does not parse bills zero and goes on the receipt verbatim. There is no knob to substitute a proxy-counted number, because a receipt that cannot separate "the origin lied" from "the proxy miscounted" is worthless in the dispute it exists for.

Unit names must be unique across all three lists (route weights may repeat a name across routes on purpose: several routes priced differently are still one invoice line). Declaring a role with no resolvers at all is legal and logged loudly: you get an outcome-only chain that proves no call went missing and bills nothing.

## Run it

Everything below runs from a repository checkout, against the example config. Start clean; the tamper step later corrupts the chain on purpose, so a rerun against a stale state directory starts broken.

```bash
rm -rf /tmp/sbproxy-metering
python3 examples/metering-verify/bin/upstream.py &
sbproxy serve -f examples/metering-verify/sb.yml
```

In a second terminal, serve three metered requests:

```bash
for i in 1 2 3; do curl -s -o /dev/null -w '%{http_code}\n' \
     -H 'Host: api.local' http://127.0.0.1:8080/anything/article; done
```

```
200
200
200
```

Each of those wrote one entry to the chain. Look at the first one as it sits on disk:

```bash
head -1 /tmp/sbproxy-metering/receipts.ndjson | jq .
```

```
{
  "seq": 0,
  "recorded_at": "2026-08-02T02:40:23.727231+00:00",
  "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000",
  "entry_hash": "ea200fd6282b277f614980198c98223651b72e36119833cc4a5ad703dbccf0ab",
  "signature": "7653d513863e8e02a5c296732ee7b6970eada242062f2a73478b14a31e159951635106673a4627b614cb71533d3a4c7c858c58d7c09845a62850d9e2883efd04",
  "event": {
    "seq": 0,
    "prev": "0000000000000000000000000000000000000000000000000000000000000000",
    "node_id": "sbproxy-node",
    "claim_id": "019fc0580cad79d38ad6e66807528ca2",
    "agreement_id": "agreement-2026-001",
    "subject": {
      "tenant": "__default__"
    },
    "route": "/anything/article",
    "units": [
      {
        "name": "egress_kib",
        "count": 3,
        "source": "measured",
        "evidence": {
          "bytes_in": 0,
          "bytes_out": 2525,
          "duration_ms": 1
        }
      },
      {
        "name": "api_call",
        "count": 1,
        "source": "route_weight",
        "evidence": {
          "config_revision": "8f10eba811d1"
        }
      }
    ],
    "outcome": "delivered",
    "config_revision": "8f10eba811d1"
  }
}
```

The envelope is the chain link: `seq` is the entry's position, `prev_hash` is the previous entry's digest (all zeros for the first), `entry_hash` is the SHA-256 binding this entry to everything before it, and `signature` is the Ed25519 signature over that digest. The `event` inside is the receipt itself: the subject the units are charged to, the route, the outcome, the units with their provenance and raw evidence, the agreement they bill under, and `config_revision`, the content hash of the configuration that priced the call. That last field answers "you priced my call under a config I never agreed to".

### The operator surface

Three routes on the admin server, all behind the same operator gate as the rest of the admin API:

| Route | Method | Answers |
| --- | --- | --- |
| `/api/meter/summary` | GET | Units by tenant, unit, and provenance, beside the coverage the total was assembled from |
| `/api/meter/receipts` | GET | A cursor-paged window on this node's chain (`since_seq`, `limit`, `tenant`) |
| `/api/meter/verify` | POST | Whether the chain still verifies, and the first sequence number where it does not |

```bash
curl -s -u admin:demo-change-me 'http://127.0.0.1:9090/api/meter/summary' | jq .
```

```
{
  "attestation": {
    "configured": true,
    "failure_mode": "degraded",
    "ledger_path": "/tmp/sbproxy-metering/receipts.ndjson",
    "role": "receipt",
    "signing_key_id": "metering-demo-2026"
  },
  "chain": {
    "damage_reason": null,
    "damaged_at_seq": null,
    "entries": 3,
    "head_hash": "fb1b4bb2a8ed5f5c740601cf0b021faf66fc6e465b589116e7f67627751a9ade",
    "node_id": "sbproxy-node",
    "present": true
  },
  "claims": 3,
  "coverage": {
    "answered": [
      "sbproxy-node"
    ],
    "complete": true,
    "expected": 1,
    "gathered_at": "2026-08-02T02:40:24.776929+00:00",
    "uncovered": []
  },
  "gaps": {
    "by_tenant": [],
    "divergence_total": 0,
    "total": 0
  },
  "gathered_at": "2026-08-02T02:40:24.775533+00:00",
  "group_by": "tenant",
  "nodes": [
    {
      "claims": 3,
      "covered": true,
      "head_hash": "fb1b4bb2a8ed5f5c740601cf0b021faf66fc6e465b589116e7f67627751a9ade",
      "head_seq": 3,
      "local": true,
      "node_id": "sbproxy-node",
      "observed_at": "2026-08-02T02:40:24.775533+00:00"
    }
  ],
  "reason": null,
  "schema_version": 1,
  "state": "reporting",
  "tenant": null,
  "totals": [
    {
      "count": 3,
      "group": "__default__",
      "source": "route_weight",
      "tenant": "__default__",
      "unit": "api_call"
    },
    {
      "count": 9,
      "group": "__default__",
      "source": "measured",
      "tenant": "__default__",
      "unit": "egress_kib"
    }
  ]
}
```

Every response leads with a `state` before it shows a number, because a page of zeros looks the same whether attestation is off, on with no traffic yet, or on with a meter that silently stopped writing, and those are three different problems. `off` means no chain exists and the zeros are not a measurement; `idle` means the meter is configured and has recorded nothing, a real reading of an empty chain; `reporting` means the numbers describe traffic. Nothing manufactures a sample to fill the page out.

`group_by` accepts `tenant`, `unit`, `source`, or `total`, and grouping never folds two provenances into one number: refusing that fold is what the meter exists for. `window` is refused outright, because a chain segment carries a cumulative total with no time index, and answering a windowed question approximately would produce a figure nobody could reproduce from the chain.

Page through the receipts themselves:

```bash
curl -s -u admin:demo-change-me 'http://127.0.0.1:9090/api/meter/receipts?limit=3' \
  | jq '.receipts[] | {seq, entry_hash, outcome: .claims.outcome, units: .claims.units}'
```

```
{
  "seq": 0,
  "entry_hash": "ea200fd6282b277f614980198c98223651b72e36119833cc4a5ad703dbccf0ab",
  "outcome": "delivered",
  "units": [
    {
      "count": 3,
      "evidence": {
        "bytes_in": 0,
        "bytes_out": 2525,
        "duration_ms": 1
      },
      "name": "egress_kib",
      "source": "measured"
    },
    {
      "count": 1,
      "evidence": {
        "config_revision": "8f10eba811d1"
      },
      "name": "api_call",
      "source": "route_weight"
    }
  ]
}
{
  "seq": 1,
  "entry_hash": "ada8d9ba3adc5caf73e566b77625a3372919846420acff3c7dcc933883cdd1be",
  "outcome": "delivered",
  "units": [
    {
      "count": 3,
      "evidence": {
        "bytes_in": 0,
        "bytes_out": 2525,
        "duration_ms": 0
      },
      "name": "egress_kib",
      "source": "measured"
    },
    {
      "count": 1,
      "evidence": {
        "config_revision": "8f10eba811d1"
      },
      "name": "api_call",
      "source": "route_weight"
    }
  ]
}
{
  "seq": 2,
  "entry_hash": "fb1b4bb2a8ed5f5c740601cf0b021faf66fc6e465b589116e7f67627751a9ade",
  "outcome": "delivered",
  "units": [
    {
      "count": 3,
      "evidence": {
        "bytes_in": 0,
        "bytes_out": 2525,
        "duration_ms": 0
      },
      "name": "egress_kib",
      "source": "measured"
    },
    {
      "count": 1,
      "evidence": {
        "config_revision": "8f10eba811d1"
      },
      "name": "api_call",
      "source": "route_weight"
    }
  ]
}
```

An operator entry in `proxy.admin.operators` can be scoped to one tenant. Scoped operators see their own tenant's units and receipts only, and a request naming anybody else's tenant is refused with `403` rather than quietly filtered, because a silently empty result reads as "that tenant used nothing". Chain-level facts (sequence numbers, digests, the verify verdict) go to every operator, because they name no tenant and a stalled meter is everybody's problem.

## The verify demo

Verification re-derives the chain from genesis: every `prev_hash` must match the running head, every `entry_hash` must match a digest recomputed from the entry's own bytes. It is a `POST` even though it writes nothing, because it walks the whole file and is an action an operator takes, not a panel that refreshes; the RBAC gate restricts it to the admin role.

```bash
curl -s -u admin:demo-change-me -X POST http://127.0.0.1:9090/api/meter/verify | jq .
```

```
{
  "broken_seq": null,
  "entries": 3,
  "node_id": "sbproxy-node",
  "outcome": "ok",
  "reason": null,
  "schema_version": 1,
  "state": "reporting",
  "verified_at": "2026-08-02T02:40:24.800844+00:00"
}
```

Now tamper. The chain is a JSONL file at `proxy.attestation.ledger.path`, so the edit is one line of Python: find the first `"count"` in the second entry (sequence 1) and put a `9` in front of it, turning a small number into a much bigger one. Exactly the edit a dishonest operator, or a compromised disk, would love to get away with:

```bash
python3 -c "import pathlib; p=pathlib.Path('/tmp/sbproxy-metering/receipts.ndjson'); l=p.read_text().splitlines(); l[1]=l[1].replace('\"count\":','\"count\":9',1); p.write_text('\n'.join(l)+'\n')"
```

Run the verifier again:

```bash
curl -s -u admin:demo-change-me -X POST http://127.0.0.1:9090/api/meter/verify | jq .
```

```
{
  "broken_seq": 1,
  "entries": 1,
  "node_id": "sbproxy-node",
  "outcome": "broken",
  "reason": "entry_hash does not match recomputed digest (tampered event)",
  "schema_version": 1,
  "state": "reporting",
  "verified_at": "2026-08-02T02:40:24.830515+00:00"
}
```

The verdict names the broken index: the recomputed digest of entry 1 no longer matches the `entry_hash` that entry 2's `prev_hash` committed to. One edited byte anywhere in the history breaks the link at that exact position, which is the property that makes the chain worth more than a log file. Re-signing the edited entry does not help the attacker either, because the signature has to verify against the published key they do not hold.

## Verifying as the buyer

This section is addressed to the buyer: the party being billed, outside the operator's company, holding none of the operator's infrastructure.

You need two things, and only two. First, the chain data: either the raw ledger file, an export of it, or the same entries read from `/api/meter/receipts` if the operator gives you scoped access. Second, the operator's published key set, which is a public URL on their origin:

```bash
curl -s -H 'Host: api.local' \
  http://127.0.0.1:8080/.well-known/http-message-signatures-directory | jq .
```

```
{
  "keys": [
    {
      "alg": "EdDSA",
      "crv": "Ed25519",
      "kid": "metering-demo-2026",
      "kty": "OKP",
      "use": "sig",
      "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
    }
  ]
}
```

That is a standard JWKS-shaped document; the `x` field is the raw Ed25519 public key, base64url-encoded, and `kid` matches the key id on every receipt. From those two inputs you can check, with no SBproxy software and no trust in the operator:

- Nothing was removed: sequence numbers run from 0 with no gaps.
- Nothing was reordered or spliced in: each entry's `prev_hash` equals the previous entry's `entry_hash`.
- Nothing was edited: each `entry_hash` is the SHA-256 over the previous digest, the sequence number as 8 raw little-endian bytes, the timestamp, and the receipt's own bytes, each of the first three followed by a newline. Recompute it and compare.
- The record is the operator's: each `signature` is Ed25519 over that raw 32-byte digest and must verify against the published key. Nobody without the private key can rewrite history and re-sign it.

Be equally clear about what the chain does not prove. It proves the record is intact and attributable, not that the meter observed honestly in the first place: a `measured` unit is the proxy's own arithmetic over bytes it served you, a `route_weight` is checkable against the signed config revision on the receipt, but an `origin_header` unit is the upstream's claim, recorded verbatim, and the receipt proves only that the origin sent that value. The provenance is on every unit precisely so you can price your skepticism per source.

The repository ships a reference implementation of the whole check, about 150 lines of Python with no SBproxy imports, at `examples/metering-verify/bin/verify-chain.py`:

```bash
curl -s -H 'Host: api.local' \
  http://127.0.0.1:8080/.well-known/http-message-signatures-directory > jwks.json

examples/metering-verify/bin/verify-chain.py \
  --chain /tmp/sbproxy-metering/receipts.ndjson --jwks jwks.json
```

Run against the chain tampered with above, it finds the same break the operator's verifier found, from the outside:

```
chain verify: FAILED at seq 1: entry_hash does not match recomputed digest (tampered event)
```

That symmetry is the point of the design. The operator's verify endpoint and your script disagree with each other only if one of you has different bytes, and the signature says whose bytes the operator stands behind.

## Gap markers

Under the `degraded` posture, a receipt that could not be written is not silently absent. The meter writes a gap marker instead: an ordinary chained, signed receipt whose outcome is `chain_gap`, with an empty units list, filed under the original claim id plus a `:chain_gap` suffix. The suffix matters: the chain deduplicates on claim id so retries bill once, and a marker filed under the bare id would make a later successful retry look like a duplicate, turning a temporary gap into a permanent one.

Reading one in a chain means: a record was owed here and the chain could not take it at the time, and this marker is the chain's own admission of that. What to do about it:

- Alert on `sbproxy_meter_chain_gap_total`. A nonzero rate is a meter failing while traffic flows, which is exactly the situation `degraded` exists to make visible instead of silent.
- Find the cause the way you would any write failure: disk space at the ledger path, permissions, the signing identity.
- Reconcile the window. The marker carries the subject, route, and claim id of the call it stands in for, so the affected traffic is identifiable even though its units are not on the chain.

When the marker itself cannot be written, the counter is the only record left; that is the failure mode's floor, and it is why the metric and the marker both exist rather than either alone.

## Cluster totals are labelled, never estimated

Chains are per node. Two nodes serving the same tenant each write their own sequence, so a sequence number is only meaningful next to the node id it was counted under, and a cluster total is an assembly of per-node chains, not a number any single chain contains.

`/api/meter/summary` therefore never quotes a cluster figure without a `coverage` block naming which nodes are inside it: how many nodes were expected, how many answered, and, for each node that did not, the last chain head it was ever seen at. An unreachable node stays in the report at its last known position rather than being dropped, counted as zero, or extrapolated. When no mesh is configured, `coverage` is `null`, because there is exactly one chain and a coverage block would claim a fan-out that never happened.

The refusal to estimate is a billing decision, not a reporting limitation. A partial total labelled partial is a fact; a partial total padded to look complete is an invoice line nobody can reproduce from any chain, and being reproducible from the chain is the only property that makes any number on this page worth writing down.

## See also

- [ai-usage-ledger.md](ai-usage-ledger.md) - the same chain construction recording LLM spend, with its own `sbproxy ai ledger verify` CLI. Note that CLI verifies the usage ledger's payload format, not the receipt chain; receipts verify through `POST /api/meter/verify` or the buyer script above.
- [payment-settlement.md](payment-settlement.md) - charging before the call is served, the claim half of attestation.
- [web-bot-auth.md](web-bot-auth.md) - the signing identity, key generation, and the published key directory.
- [admin-api-guide.md](admin-api-guide.md) - admin server auth, roles, and the curl cookbook.
- [observability.md](observability.md) - the `sbproxy_meter_*` metric families, for the dashboards this page tells you not to bill from.
