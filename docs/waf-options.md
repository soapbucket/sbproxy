# WAF options

*Last modified: 2026-08-09*

![A request denied by the WAF baseline inside a layered ip_filter -> ddos -> waf -> dlp stack](assets/waf-layered.gif)

SBproxy ships a Web Application Firewall. It is a curated signature
baseline of 16 rules, against roughly 900 in the OWASP Core Rule Set.
Operators reasonably ask what to do about that gap. This page records
the decision not to close it by embedding a SecLang engine, says plainly
what the baseline does and does not catch, and gives followable recipes
for the three ways to get more coverage: a CRS-capable WAF in front, the
signed rule feed, and layering the policies already in the binary.

## What ships today

Sixteen rules, in two corpora that toggle independently.

Four built-in patterns, compiled into the binary and enabled with
`owasp_crs.enabled: true`: `sqli`, `xss`, `path_traversal`, and
`sqli_strict`.

Twelve managed-bundle rules, vendored as JSON and enabled with
`owasp_crs.managed_bundle: true`. They carry CRS-style identifiers and
category numbering (`crs-941-100` for XSS, `crs-942-100` for SQLi,
`crs-930-100` for LFI, and so on through RFI, RCE, PHP injection, Node
injection, scanner detection, protocol attack, and Java injection). The
patterns are written here rather than copied from upstream, because
upstream ships ModSecurity `.conf` files and leans on libinjection where
this bundle uses plain regular expressions. `NOTICE` records the
provenance either way.

The two flags are independent. Neither implies the other, and enabling
only `enabled: true` gets you four patterns rather than sixteen rules.
Turn on both:

```yaml
policies:
  - type: waf
    owasp_crs:
      enabled: true
      managed_bundle: true
    paranoia: 2
    action_on_match: block
    failure_posture: closed
```

Every rule carries a paranoia level from 1 to 4, and the policy's
`paranoia` setting gates all three corpora (built-ins, bundle, feed) at
once. The default is 1, which is quieter than most people expect:

| `paranoia` | Built-in patterns | Bundle rules | Total active |
|---|---|---|---|
| 1 (default) | 3 | 5 | 8 |
| 2 | 4 | 11 | 15 |
| 3 | 4 | 12 | 16 |
| 4 | 4 | 12 | 16 |

Around that corpus sit the parts that are genuinely ours rather than
CRS-derived: a signed remote rule feed with HMAC-SHA256 verification,
last-good disk caching and a staleness bound; and persistent
strike-based blocking that escalates a repeat offender into a time-boxed
block, shared across replicas when a Redis tier is configured.

## What the baseline is not

Upstream CRS 4.x is roughly 900 rules plus anomaly scoring,
transformation pipelines, body processors, and per-application exclusion
packages. Reading "OWASP CRS" on a config key and inferring any of that
would be a mistake, so here is the specific list.

**Request bodies are not inspected at all.** The rule engine takes a body
argument, and the one place in the proxy that calls it passes nothing. No
multipart, no JSON, no XML, no form-encoded bodies. A payload in a POST
body is invisible to this WAF. The `dlp` policy and the AI-gateway
guardrails have their own body story; the WAF does not.

**Normalization is one percent-decode and a plus-to-space swap.** That is
the whole transformation pipeline. There is no null-byte stripping, no
Unicode normalization, no comment removal, no whitespace compression, no
HTML or JavaScript entity decoding, and no repeated decoding pass. CRS
does all of those before a rule ever sees the input, and that difference
is the classic evasion surface. Double-encoded payloads survive except
where a pattern happens to spell the encoded form out literally.

**There is no anomaly scoring.** Each rule independently blocks or logs.
Nothing accumulates a score across rules and compares it to a threshold,
so the tuning move CRS operators rely on most is not available here.

**There are no exclusion packages and no per-path scoping.** A WAF policy
applies to its whole origin. There is no equivalent of
`SecRuleRemoveById`, no per-application tuning set for WordPress or
Drupal or cPanel, and no way to disable one rule on one route short of
splitting the origin.

**Headers are scanned wholesale, including `Authorization` and
`Cookie`.** They are joined into one `name: value` text block separated by
newlines and matched against every rule, so a pattern can match across a
header boundary, and a long bearer token or session cookie can trip a
signature that a real attack never would. A header value that is not
valid UTF-8 is read as empty and skipped entirely. This is a false
positive source worth measuring in `test_mode: true` before you enforce.

None of that makes the baseline useless. It stops opportunistic scanner
traffic and unsophisticated injection attempts at the edge, cheaply, with
no extra process to run, and that is the job worth judging it against.

## The decision: no SecLang engine in the dataplane

We are not embedding a SecLang rule engine, taking an FFI dependency on
Coraza, or shipping a sidecar that runs one. Three reasons, in order of
weight.

**Nine hundred rules is a standing maintenance commitment.** The rules
are the visible part of it. Behind them sit the transformation
functions each rule composes, the body processors that decide what a rule
even sees, the anomaly-scoring machinery that makes CRS tunable, and the
exclusion packages that make it deployable. Upstream revises all of it,
and a WAF that lags upstream is worse than one that never claimed to
follow it, because operators stop reading the release notes. Signing up
to track CRS means signing up to track it forever, with a false-positive
budget owned by us rather than by the project that publishes the rules.

**Reaching Coraza means either cgo or a second process.** Coraza is the
credible SecLang implementation and it is written in Go. Consuming it
means either cgo across a per-request boundary in a proxy whose whole
performance argument is that it has no garbage collector, or a sidecar
process, which means a second failure domain, a second lifecycle, a
second config surface, and a network hop on the request path. The
guardrail sidecar already exists for classifier work and it earns that
cost by running ONNX models we genuinely cannot run in process. A regex
matcher does not clear the same bar.

**A signature matcher wearing CRS names would be worse than an honest
baseline.** This is the reason that actually decides it. We could
plausibly grow the vendored bundle to a few hundred regexes with CRS
identifiers and call it CRS coverage. Every one of those rules would run
against an unnormalized, body-less input, with no anomaly score to tune
against, and the config key would still say `owasp_crs`. An operator would
read the rule count, believe the CRS name, and skip the WAF they actually
needed. Sixteen rules that say sixteen rules is a defensible product.
Three hundred rules that imply nine hundred is a liability.

The cost of this decision is real and we accept it: SBproxy's WAF will
not catch what a tuned CRS deployment catches, and an operator with a
compliance requirement naming ModSecurity or CRS cannot satisfy it with
this policy alone. The next three sections are about making that cheap to
fix.

## Option 1: put a CRS-capable WAF in front

The normal answer, and the one to reach for when you need real CRS. Run
ModSecurity (the nginx connector or Apache), Coraza (Caddy natively,
Envoy or Istio through its proxy-wasm filter, HAProxy through SPOA), or a
CDN WAF such as Cloudflare, Fastly, or AWS WAF at the edge, and put
SBproxy behind it.

```text
client -> [ nginx + ModSecurity/CRS ]  -> [ SBproxy ] -> upstream
          full CRS, anomaly scoring,      identity, keys, budgets,
          body processors, exclusions     AI routing, baseline WAF
```

The division of labor is clean. The front WAF owns HTTP attack signatures
and the CRS tuning loop. SBproxy owns everything the front WAF has no
opinion about: authentication, virtual keys, rate and spend budgets,
provider routing, guardrails, and the audit trail. Keep the baseline WAF
enabled behind the front one; two independent corpora are worth more than
one, and it costs a few regexes per request.

### Configure SBproxy behind it, or client IP becomes a lie

This is the part that silently breaks, so do it first.

Once another proxy terminates the client connection, SBproxy's immediate
TCP peer is that proxy, not the client. The real address lives in
`X-Forwarded-For`. SBproxy will not read that header from just anyone:

```yaml
proxy:
  http_bind_port: 8080
  # CIDRs (or bare IPs) whose forwarding headers we trust. Set this to
  # the WAF's egress range and nothing wider.
  trusted_proxies:
    - 10.42.0.0/16
```

Two behaviors follow from that list, and both matter.

When the immediate peer **is** inside `trusted_proxies`, SBproxy walks the
inbound `X-Forwarded-For` chain from the right and takes the first
address that is not itself a trusted proxy. That becomes the client IP for
the rest of the request.

When the peer is **not** inside it, SBproxy strips `X-Forwarded-For`,
`X-Real-IP`, `X-Forwarded-Proto`, `X-Forwarded-Port`, `X-Forwarded-Host`,
and `Forwarded` on ingress, along with the TLS-fingerprint and A2A
envelope headers, so a client that reaches the proxy directly cannot name
its own source address. The default is an empty list, meaning the TCP peer
is always the client and no forwarding header is ever honored.

Get this wrong in either direction and the failure is quiet.

*Left unset behind a WAF*, every request in the fleet carries the WAF's
egress IP. `ip_filter` allowlists and denylists stop distinguishing
clients, the `ddos` policy's per-IP ceiling becomes a global ceiling that
one noisy caller can exhaust for everybody, rate limits collapse into a
single bucket, and a WAF `persistent_block` with `track_by: ip` will
eventually blocklist the WAF itself and take the site down.

*Set too wide*, say `0.0.0.0/0`, and every client can spoof its own
source address by sending an `X-Forwarded-For` header. Allowlists,
denylists, rate limits, and persistent blocks all become opt-in.

Everything downstream reads the same resolved value, so one setting is
either right for all of it or wrong for all of it: `ip_filter`, the
`ddos` policy, the default rate-limit key, `concurrent_limit` with
`key_by: ip`, WAF `persistent_block` with `track_by: ip`, the
`connection.remote_ip` variable in CEL expressions, and the access log's
client address.

### Check it before you trust it

Send a request through the front WAF and confirm the access log records
the real client address rather than the WAF's. Then send one directly to
SBproxy's port with a forged header:

```bash
curl -i -H 'X-Forwarded-For: 203.0.113.9' http://sbproxy.internal:8080/
```

If your source is outside `trusted_proxies`, the header is stripped and
the log shows your real address. If the log shows `203.0.113.9`, the CIDR
list is too wide and every IP-keyed control on the origin is spoofable.
Close the port to everything but the WAF's range while you are there;
`trusted_proxies` decides whose headers are believed, not who can connect.

## Option 2: publish your own rules through the signed feed

The feed is the supported extension point for adding signatures without
waiting on a release, and it is the least known thing on this page. A
publisher serves a JSON bundle, signs it with a shared HMAC key, and every
subscribed proxy hot-loads it into the running policy. No restart, no
config reload.

Be aware of one gap before you plan around it: **nothing in this
repository builds or signs a bundle for you.** There is no CLI subcommand
and no script. The format is small enough to hand-author and sign with
five lines of Python, which is what the rest of this section shows, but if
you were looking for `sbproxy waf bundle sign`, it does not exist.

### The bundle format

A bundle is one JSON object.

```json
{
  "version": "2026-08-09T12:00:00Z",
  "channel": "acme-internal",
  "rules": [
    {
      "id": "ACME-001",
      "paranoia": 1,
      "category": "sqli",
      "pattern": "(?i)\\bunion\\s+all\\s+select\\b",
      "action": "block",
      "severity": "critical"
    }
  ]
}
```

`version` is the revision marker: the subscriber echoes it back as
`?after=` on the next poll, and the staleness bound is measured against
it. Make it an RFC 3339 timestamp. Any other string still parses, but the
staleness check cannot read it and is skipped for that bundle, which is a
quiet way to lose the protection you configured. `channel` names the
corpus and is
used for the on-disk cache filename and the outage event. `id` is any
stable string; a feed rule whose `id` matches an inline `custom_rules`
entry shadows that entry, which is how you override a rule an origin
already carries. `pattern` is a Rust `regex` crate pattern, so no
backreferences and no lookaround. `paranoia` defaults to 1 and is clamped
to 1 through 4. `action` is `block` or `log` and defaults to `block`.
`severity` is `info`, `low`, `medium`, `high`, or `critical` and only
enriches the log line.

A rule whose pattern fails to compile is dropped with a warning and the
rest of the bundle still loads. A bundle carrying an `expires_at` field
parses, but nothing enforces it today; use `max_age` on the subscriber
instead.

### Sign and serve it

The signature is a hex-encoded HMAC-SHA256 over the exact response body
bytes, keyed by the raw UTF-8 bytes of the shared secret. Not a hash of a
canonical form, not a signature over a subset: the bytes you send.

```python
import hashlib, hmac, pathlib

key = b"the-shared-secret"
body = pathlib.Path("bundle.json").read_bytes()
print(hmac.new(key, body, hashlib.sha256).hexdigest())
```

Serve the bytes and that hex digest together:

```text
GET /waf/rules/acme-internal?after=2026-08-08T12:00:00Z
Authorization: Bearer <token>

HTTP/1.1 200 OK
Content-Type: application/json
X-SBProxy-Feed-Sig: 9f2c...<64 hex chars>

{"version":"2026-08-09T12:00:00Z","channel":"acme-internal","rules":[...]}
```

Answer `304 Not Modified` when `after` already names your newest revision
and the proxy will skip the parse. A response without the
`X-SBProxy-Feed-Sig` header is rejected outright, as is any non-2xx
status.

There is a Redis Streams transport too. Publish to the stream with fields
`version`, `bundle` (the same JSON), and `signature` (the same hex digest
over that JSON), and the subscriber `XREAD`s them.

### Subscribe

```yaml
policies:
  - type: waf
    owasp_crs:
      enabled: true
      managed_bundle: true
    paranoia: 2
    action_on_match: block
    failure_posture: closed
    feed:
      enabled: true
      transport: http
      url: https://feeds.internal.example.com/waf/rules/acme-internal
      channel: acme-internal
      signature_key_env: SBPROXY_WAF_FEED_KEY
      auth_token_env: SBPROXY_WAF_FEED_TOKEN
      poll_interval: 60
      max_age: 86400
      fallback_to_static: true
      cache_dir: /var/lib/sbproxy/cache
```

`signature_key_env` names the environment variable holding the shared
secret; it is required, and the variable's value is used as key bytes
directly. `auth_token_env` is optional and is skipped silently if the
variable is unset, so a feed that requires a bearer token will simply 401
rather than telling you the variable was missing. `poll_interval` is in
seconds and defaults to 60. `max_age` rejects a bundle whose `version`
timestamp is older than that many seconds, defaulting to 86400, and `0`
disables the check.

`fallback_to_static: true` (the default) keeps the last good corpus live
when the publisher is unreachable. Set it to `false` and an unreachable
feed clears the rule set and logs a `WafFeedDown` event instead, which is
the right choice when a stale corpus is worse than no corpus. Alert on
that event either way.

### What happens at runtime

Every successful fetch writes the raw bundle to
`<cache_dir>/waf-feed-<channel>.json` with the signature in a sibling
`.sig` file. On a cold start the subscriber loads that pair and
re-verifies it against the configured key, so a proxy that reboots during
a feed outage comes up with rules, and a tampered cache file is rejected
rather than trusted. `cache_dir` defaults to `~/.cache/sbproxy`, which is
usually the wrong place under systemd or in a container; set it
explicitly to a path the service user owns.

A bundle that fails signature verification is dropped and the last good
corpus stays live. Rotating the shared key means rotating it on the
publisher and every subscriber together, because there is no key id in
the protocol and no overlap window.

One operational surprise worth planning around: the background poller is
spawned lazily, on the first request that reaches a WAF policy with a feed
configured. An origin with no traffic never polls. If you need to see the
subscriber start, send a request.

## Option 3: layer what is already in the binary

Before concluding that sixteen rules is the whole defense, look at what
runs alongside them. The rules are the narrowest layer and the loudest to
count.

- `ip_filter` decides whether the source is allowed to speak at all, from
  CIDR allowlists and denylists, and it is a pure address comparison, so
  it is the cheapest thing to put first.
- `ddos` puts a per-IP request ceiling in front of the scanning layers and
  hard-blocks an offender for a fixed window once it trips.
- `waf` runs the signature corpus over the URI and headers.
- `dlp` runs the credential and PII detector catalog over the same
  surface, in the other direction: it catches an AWS key or a GitHub token
  going out through a query string, which no WAF rule is looking for.
- `persistent_block` on the WAF policy turns repeated denials into a
  time-boxed block, so a scanner that trips three rules inside a minute
  stops getting a rule evaluation at all for the next ten minutes.

Policies run in declaration order and the first denial short-circuits, so
the order in the file is the order of the funnel.
[examples/waf-layered/](../examples/waf-layered/) is a runnable config of
exactly this stack, with `trusted_proxies` set so the IP-keyed layers
mean something.

## When to revisit

Three things reopen this decision.

**A compliance requirement that names CRS by version.** Not "a WAF" and
not "OWASP protections", but an auditor asking which CRS release is
deployed and which paranoia level is set. Option 1 answers that today, and
if enough deployments hit it, the useful work is a tested reference
deployment (nginx plus Coraza plus SBproxy, as a compose file and a
Kubernetes overlay) rather than an engine in our process.

**Repeated demand for one attack class we keep missing.** The right
response to that is more managed-bundle rules in that category, published
through the feed and folded into the vendored bundle when they settle.
That grows coverage where the evidence is, keeps the count honest, and
costs nothing structural.

**A pure-Rust SecLang engine that someone else maintains.** The Go
dependency is the reason the FFI path is closed, and it is the one reason
here that could stop being true. A maintained Rust crate that parses
SecLang, implements the transformation functions, and passes the CRS test
suite would change the arithmetic. It does not exist today.

## The bar an in-process CRS design would have to clear

If someone proposes bringing CRS into the dataplane, this is what the
proposal has to answer. The list exists so a future design is measured
against it instead of relitigating the boundary.

- **Transformations before rules.** At minimum repeated URL decoding,
  null-byte stripping, whitespace compression, comment removal, and HTML
  and JavaScript entity decoding, applied per rule as the rule declares,
  not once globally. Rules without them are the false-positive engine we
  already declined to build.
- **Real body processing.** Multipart, URL-encoded, JSON, and XML bodies
  parsed into addressable variables, with a size cap and a defined
  behavior when the cap is hit. Scanning a raw body as one string does
  not count.
- **Anomaly scoring, not per-rule blocking.** Inbound and outbound score
  accumulation with configurable thresholds, which is the mechanism CRS
  operators actually tune with.
- **Exclusions as a first-class config surface.** Disable a rule, a tag,
  or a category, scoped to a path or a parameter, without editing rule
  text.
- **A rule-source provenance story.** Where rules come from, how they are
  verified before they load, and how upstream revisions reach a running
  proxy. The signed feed is the existing answer and a new design should
  extend it rather than open a second channel.
- **A measured latency budget.** Published P50 and P99 for the full
  pipeline at a stated rule count, against the current baseline, on the
  benchmark harness already in this repository. "It should be fast enough"
  is not a number.
- **No new process on the request path unless it earns it.** A sidecar
  needs to justify a second failure domain and a network hop against what
  it adds, the way the classifier sidecar does by running models that
  genuinely cannot run in process.

Nothing here commits to building any of it.

## Related

- [configuration.md](configuration.md) has the full `waf` policy field
  reference.
- [features.md](features.md) puts the WAF in context with the other
  security policies.
- [threat-model.md](threat-model.md) covers the trust boundaries the
  `trusted_proxies` discussion above depends on.
- [examples/trusted-proxies/](../examples/trusted-proxies/) is the
  standalone demo of the forwarding-header trust boundary.
- [examples/waf-layered/](../examples/waf-layered/) is the layered stack
  from Option 3, runnable.
- [custom-engines.md](custom-engines.md) records a deferral of the same
  shape on the model-host side.
