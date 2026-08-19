# HTTP framing policy

Request smuggling starts with a request two servers read differently: a front-end proxy sees one request, the back-end sees two, and the extra one rides in unnoticed. The `http_framing` policy refuses the ambiguous framing that makes this possible before the request reaches an upstream. This example serves a static page behind it and blocks a duplicate `Transfer-Encoding` header, the classic TE.TE shape.

## What the policy owns, and what Pingora already handles

The policy is the semantic-ambiguity layer sitting on top of Pingora's own HTTP/1.1 parser, and the split matters for what you can watch happen:

- **Pingora's parser rejects first.** A malformed `Transfer-Encoding` value (`xchunked`), a duplicate `Content-Length`, or control characters in a header are refused at the wire with a bare `400 Bad Request` (`Server: Pingora`, empty body). These never reach the policy, and they do not touch the policy's counters.
- **Pingora resolves a dual CL+TE.** A request carrying both `Content-Length` and `Transfer-Encoding: chunked` is disambiguated by Pingora in the safe direction: it honors the chunked encoding and drops the length. By the time the policy sees the request there is no ambiguity left, so the request is served. The primitive is neutralized, just not by this policy.
- **The policy owns duplicate `Transfer-Encoding`.** Two `Transfer-Encoding` headers reach the policy as two headers, and the policy rejects them. This is the case with a policy-specific outcome: a `400` and a bump on `sbproxy_http_framing_blocks_total{reason="duplicate_te"}`, which the wire-parser rejections do not produce.

So the request this example blocks is the one that both survives the parser and is caught by the policy: a duplicate `Transfer-Encoding`.

## Run

```bash
sbproxy serve -f sb.yml
```

## Try it

A normal request passes untouched:

```bash
$ curl -i -H 'Host: framing.local' http://127.0.0.1:8080/
HTTP/1.1 200 OK
content-type: application/json
content-length: 96

{"framing": "unambiguous", "note": "this body is only reachable through a well-framed request"}
```

A well-formed client cannot send a duplicate header, so the violation goes over raw bytes with netcat. Two `Transfer-Encoding: chunked` lines is the TE.TE desync:

```bash
$ printf 'GET / HTTP/1.1\r\nHost: framing.local\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n' \
    | nc 127.0.0.1 8080
HTTP/1.1 400 Bad Request
```

The policy tags every block with the reason it fired on:

```bash
$ curl -s -u admin:changeme http://127.0.0.1:9091/metrics | grep sbproxy_http_framing_blocks_total
sbproxy_http_framing_blocks_total{reason="duplicate_te",tenant="__default__"} 1
```

## What this shows

- The `http_framing` policy blocking a duplicate `Transfer-Encoding` with a `400`
- The `sbproxy_http_framing_blocks_total{reason}` counter, which distinguishes a policy block from a wire-parser rejection
- The division of labor with Pingora's parser: malformed and duplicate-CL cases are refused earlier, and a dual CL+TE is resolved rather than rejected

The policy has no tunable knobs. Its defense set is hard-coded because each violation maps to a known smuggling primitive that no legitimate caller produces. It is also the request-phase piece of the `owasp_api_top10` pack's `api8`, so a config that enables the pack gets this behavior without naming the policy.

## See also

- [docs/api-security.md](../../docs/api-security.md) covers the request-smuggling defense in context.
- [examples/owasp-api-top10](../owasp-api-top10/) enables `http_framing` through the OWASP pack rather than directly.
