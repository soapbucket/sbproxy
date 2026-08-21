# Structural body threat limits

*Last modified: 2026-08-20*

A request body can attack a service without carrying a single recognizable payload string: a thousand levels of JSON nesting to blow a recursive parser's stack, a million-key object to soak CPU in hash insertion, an XML DTD whose entities expand into gigabytes. The `body_threat_protection` policy refuses these by shape. It bounds JSON nesting depth, entries per object, items per array, key and string lengths, and total container count; for XML it bounds depth, element count, and attributes per element, and refuses any `<!DOCTYPE` outright, which is the guard against billion-laughs entity expansion. Kong sells the equivalent pair of plugins in its Enterprise tier; this ships in OSS.

This example runs two origins with deliberately tight limits: `body.local` in `mode: block` (violations get a 400 naming the limit) and `tap.local` in `mode: tap` (violations are logged and counted, the request proceeds).

## Run

```bash
make run CONFIG=examples/body-threat-protection/sb.yml
```

## Try it

A flat JSON body within every limit reaches the upstream:

```bash
$ curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: body.local' \
    -H 'Content-Type: application/json' \
    -d '{"order_id":"a-1","qty":2}' http://127.0.0.1:8080/anything
200
```

Six levels of nesting against `max_depth: 4` is refused with a 400 naming the
limit. The scan exits at the first container past the limit, so the observed
number is 5, not 6:

```bash
$ curl -is -H 'Host: body.local' -H 'Content-Type: application/json' \
    -d '{"a":{"b":{"c":{"d":{"e":{"f":1}}}}}}' http://127.0.0.1:8080/anything
HTTP/1.1 400 Bad Request
content-type: application/json
content-length: 152

{"detail":"json.max_depth: observed 5 exceeds the configured limit 4","error":"request body violates structural threat limits","limit":"json.max_depth"}
```

The billion-laughs prefix, an XML DTD declaring entities, is refused at the
DOCTYPE without any entity ever being expanded:

```bash
$ curl -is -H 'Host: body.local' -H 'Content-Type: application/xml' \
    --data-binary '<!DOCTYPE l [<!ENTITY a "x">]><l>&a;</l>' http://127.0.0.1:8080/anything
HTTP/1.1 400 Bad Request
content-type: application/json
content-length: 162

{"detail":"xml.doctype: DOCTYPE declarations are refused (entity expansion guard)","error":"request body violates structural threat limits","limit":"xml.doctype"}
```

A 300-byte string against `max_string_length: 256`:

```bash
$ curl -is -H 'Host: body.local' -H 'Content-Type: application/json' \
    -d "{\"note\":\"$(printf 'x%.0s' {1..300})\"}" http://127.0.0.1:8080/anything
HTTP/1.1 400 Bad Request
content-type: application/json
content-length: 172

{"detail":"json.max_string_length: observed 300 exceeds the configured limit 256","error":"request body violates structural threat limits","limit":"json.max_string_length"}
```

A document at exactly `max_depth: 4` passes, and a non-JSON/XML content type
is never scanned at all:

```bash
$ curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: body.local' \
    -H 'Content-Type: application/json' \
    -d '{"a":{"b":{"c":{"d":1}}}}' http://127.0.0.1:8080/anything
200

$ curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: body.local' \
    -H 'Content-Type: text/plain' -d 'not scanned at all' http://127.0.0.1:8080/anything
200
```

The same over-depth document against `tap.local` proceeds (200 from the
upstream) while the violation is logged and counted:

```bash
$ curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: tap.local' \
    -H 'Content-Type: application/json' \
    -d '{"a":{"b":{"c":{"d":{"e":{"f":1}}}}}}' http://127.0.0.1:8080/anything
200
```

The proxy log carries both outcomes, and blocked requests also emit a
`security_audit` event with the violated limit as the reason. Both warn
lines name the origin, the tenant, and the request id, which is what makes
tap mode usable: a tap run has no audit record, so its warn line is the
only per-request evidence there is, and an operator tapping several
origins at once has to be able to tell which one produced a line.

Fields are abridged below (`...` in the audit record stands for the
`timestamp`, `client_ip`, `request_id`, `tenant_id`, and key-context
fields the real record carries) and shown in reading order rather than
serialization order:

```text
WARN sbproxy::body_threat_protection: blocked: request body violates structural threat limit hostname="body.local" tenant="__default__" request_id="01K3..." limit="json.max_string_length" observed=300 allowed=256
WARN security_audit: {"event_type":"body_threat_protection","reason":"json.max_string_length: observed 300 exceeds the configured limit 256","hostname":"body.local","method":"POST","status_code":400,...}
WARN sbproxy::body_threat_protection: tap mode: request body violates structural threat limit (not blocked) hostname="tap.local" tenant="__default__" request_id="01K3..." limit="json.max_depth" observed=5 allowed=4
```

The policy counter splits enforcement from observation by the `action` label:

```bash
$ curl -s -u admin:changeme http://127.0.0.1:9091/metrics \
    | grep 'sbproxy_policy_triggers_total.*body_threat_protection'
sbproxy_policy_triggers_total{action="deny",agent_class="",agent_id="",origin="body.local",policy_type="body_threat_protection"} 3
sbproxy_policy_triggers_total{action="tap",agent_class="",agent_id="",origin="tap.local",policy_type="body_threat_protection"} 1
```

The blocks on this page are a transcript of a real run rather than a
replayed capture: unlike the pages listed in `scripts/check-doc-captures.py`,
nothing re-executes these commands on every change. If you are sizing
limits from a tap run, read the counter above rather than trusting the
numbers here.

## What this shows

- Each refusal is a 400 that names the violated limit (`json.max_depth`, `xml.doctype`, `json.max_string_length`) and the observed and allowed numbers, and never echoes body content back to the caller.
- A document exactly at a limit passes; one element past it is refused.
- The XML DOCTYPE refusal is unconditional. Entity declarations live in the DTD, so refusing the DTD refuses the entire expansion class without the proxy ever expanding an entity.
- The content-type gate: only `application/json` (and `+json`), `application/xml`, `text/xml` (and `+xml`) bodies are scanned. Everything else, including a request with no `Content-Type`, streams through untouched.
- `mode: tap` observes without blocking, so you can watch the `action="tap"` counter against production traffic before flipping an origin to `block`.

## Notes on sizing

The demonstration limits here are tiny on purpose. The production defaults (what you get by omitting the `json:` and `xml:` blocks) are depth 64, 10,000 entries per object and items per array, 1 KiB keys, 128 KiB strings, 50,000 containers, 10,000 XML elements, and 256 attributes per element. The policy deliberately has no body-size knob: `request_limit.max_body_size` is the byte cap, and the shared body-buffering seam refuses anything past its 8 MiB hard cap with a 413 before a scan ever runs, so an oversized body is refused as oversized rather than waved through unscanned.

## See also

- [docs/api-security.md](../../docs/api-security.md#structural-body-threat-limits) documents the policy in context, with the full decision-path diagram.
- [docs/waf-options.md](../../docs/waf-options.md#what-the-baseline-is-not) explains what these shape limits are not: the WAF's signature rules still do not read bodies, and this policy does not change that.
- [examples/request-validator](../request-validator/) validates body *content* against a JSON Schema; the two policies compose.
