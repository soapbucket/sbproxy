# Layered WAF

*Last modified: 2026-08-09*

![Layered WAF](../../docs/assets/waf-layered.gif)

Four screening policies on one origin, in the order they should run: `ip_filter` (403 for a source outside the allowlist), `ddos` (429 past the per-IP ceiling), `waf` (403 on an attack signature), and `dlp` (403 on a leaking credential). The WAF baseline is 16 rules and is the narrowest layer here; this config shows the stack it belongs to, with `proxy.trusted_proxies` set so the IP-keyed layers resolve a real client address instead of the address of whatever proxy sits in front.

## Run

```bash
sbproxy serve -f sb.yml
```

No setup required. The proxy listens on `127.0.0.1:8080` and the origin is selected by the `layered.local` Host header.

## The order is the funnel

Policies are evaluated in declaration order and the first denial short-circuits, so a request only reaches the regex layers if it survived the address layers.

| Order | Policy | Question | Denial |
|---|---|---|---|
| 1 | `ip_filter` | Is this source allowed to speak at all? | 403 |
| 2 | `ddos` | Is it inside the per-IP request ceiling? | 429 |
| 3 | `waf` | Does the URI or a header carry an attack signature? | 403 |
| 4 | `dlp` | Is a credential leaking out through the URI or a header? | 403 |

`ip_filter` first because a CIDR comparison is the cheapest thing in the chain. `dlp` last because it is asking about the opposite direction from everything above it: not what an attacker is sending in, but what a client or an internal caller is leaking out.

## Why `trusted_proxies` is in this file

Layers 1 and 2 key off the client IP, and so does `persistent_block` on layer 3. By default SBproxy treats the immediate TCP peer as the client and strips every inbound forwarding header, which is the right default when nothing sits in front of it.

Behind a load balancer or a CDN WAF that default is wrong in an expensive way. Every request would carry the load balancer's egress address, the per-IP ceiling would become one global ceiling that a single noisy caller can exhaust for everybody, the allowlist and denylist would stop distinguishing clients, and a persistent block keyed by IP would eventually blocklist the load balancer.

`proxy.trusted_proxies` names the CIDRs whose `X-Forwarded-For` header is believed. A peer inside the list gets its chain walked from the right, and the first address that is not itself a trusted proxy becomes the client IP. A peer outside the list has its forwarding headers stripped on ingress and cannot name its own source address.

This example lists `127.0.0.1/32` so the commands below can present a client address from a local shell. That is a demo affordance. In production the list is the egress range of the proxy in front of you and nothing wider, because anything inside it can choose its own identity. [docs/waf-options.md](../../docs/waf-options.md) works through the failure modes in both directions, and [examples/trusted-proxies/](../trusted-proxies/) is the standalone demo.

## Try it

```bash
# Allowed source, nothing suspicious. Forwarded to test.sbproxy.dev and
# the upstream response comes back.
curl -i -H 'Host: layered.local' http://127.0.0.1:8080/get
```

```bash
# Layer 1. The loopback peer is trusted, so this X-Forwarded-For is
# honored and the resolved client becomes 203.0.113.9, which is outside
# the whitelist. Denied with 403 before any regex runs.
curl -i -H 'Host: layered.local' \
     -H 'X-Forwarded-For: 203.0.113.9' http://127.0.0.1:8080/get
```

```bash
# Layer 3, built-in pattern. A classic SQL injection signature in the
# query string. Denied with 403.
curl -i -H 'Host: layered.local' \
     "http://127.0.0.1:8080/get?id=1%27%20OR%20%271%27=%271"
```

```bash
# Layer 3, managed bundle. A scanner fingerprint in the User-Agent,
# caught by crs-913-100, which only exists because managed_bundle is on.
# With owasp_crs.enabled alone this request is forwarded.
curl -i -H 'Host: layered.local' -A 'sqlmap/1.7' http://127.0.0.1:8080/get
```

```bash
# Layer 4. An AWS access key smuggled through the query string. Nothing
# in the WAF corpus looks for this; the dlp detector does. Denied with 403.
curl -i -H 'Host: layered.local' \
     'http://127.0.0.1:8080/get?key=AKIAIOSFODNN7EXAMPLE'
```

Repeat the WAF denials three times inside a minute and `persistent_block` escalates: the client is refused up front, before the rule engine runs, until the window lifts. The window here is set to one minute (the shortest supported) so a local run recovers quickly. Production wants the ten-minute default or longer.

## What this exercises

- `proxy.trusted_proxies` resolving the client IP from `X-Forwarded-For`, and stripping forwarding headers from anyone else
- `ip_filter` whitelist and blacklist CIDRs against that resolved address
- `ddos` per-IP request ceiling with a temporary block and its own bypass whitelist
- `waf` with **both** `owasp_crs.enabled: true` (4 built-in patterns) and `owasp_crs.managed_bundle: true` (12 vendored CRS-derived rules). The flags are independent; `enabled` alone gives you 4 rules, not 16
- `paranoia: 2`, which runs 15 of the 16 rules. The default of 1 runs 8
- `failure_posture: closed`, so a request the WAF could not fully evaluate is refused rather than admitted
- `persistent_block` with `track_by: ip`, turning repeated denials into a time-boxed block
- `dlp` with `action: block` over the credential detector catalog

## See also

- [docs/waf-options.md](../../docs/waf-options.md) - what the baseline catches, why there is no SecLang engine, and how to run a real CRS WAF in front
- [examples/waf/](../waf/) - the WAF policy on its own
- [examples/trusted-proxies/](../trusted-proxies/) - the forwarding-header trust boundary on its own
- [examples/dlp-catalog/](../dlp-catalog/) - the DLP detector catalog, including tag mode
- [docs/configuration.md](../../docs/configuration.md) - configuration schema
