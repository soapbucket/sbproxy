# Headless detection

The runnable half of [docs/headless-detection.md](../../docs/headless-detection.md). A stealth automation tool can patch `navigator.webdriver` and rotate its TLS fingerprint, but it cannot easily rewrite the shape of the request it sends. A real Chrome navigation carries a `Sec-Ch-Ua` client-hint family and `Sec-Fetch-*` fetch metadata; a headless Chromium claiming to be Chrome usually does not. This example turns those header-only heuristics into a 0-100 score and blocks requests that score high.

The score is computed from headers alone: no model, no client-side JavaScript, no session state. Enabling `proxy.extensions.agent_detect` is what turns it on, and it exposes the score to CEL as `request.agent.headless_score`, so blocking is one expression policy.

## Run

The rule-pack path in `sb.yml` is relative, so run from this directory:

```bash
cd examples/headless-detection
sbproxy serve -f sb.yml
```

## Try it

A User-Agent that admits to being headless Chromium trips the automation-marker indicator (weight 60) and is blocked:

```bash
$ curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: secure.local' \
    -A 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/126.0.0.0 Safari/537.36' \
    http://127.0.0.1:8080/
403
```

A stealthier shape claims to be Chrome but sends no `Sec-Ch-Ua` and no `Sec-Fetch-*` headers, which every real Chrome navigation sends. Those two missing families, plus a missing `Accept-Language`, add up past the threshold:

```bash
$ curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: secure.local' \
    -A 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36' \
    http://127.0.0.1:8080/
403
```

A client that does not claim to be Chrome trips none of the Chrome-gated indicators and passes. Firefox and Safari requests are expected to lack the `Sec-Ch-Ua` family, so the heuristic gates those checks on a Chrome vendor token in the User-Agent and never flags them:

```bash
$ curl -i -H 'Host: secure.local' -H 'Accept-Language: en-US' http://127.0.0.1:8080/
HTTP/1.1 200 OK
content-type: application/json
content-length: 82

{"page": "protected", "note": "you look like a real browser or an honest client"}
```

## What this shows

- A deterministic headless score exposed as `request.agent.headless_score`
- An expression policy blocking above a threshold with a chosen status and message
- The Chrome-only indicators leaving non-Chrome clients alone

## Layering

Pair the headless score with `request.agent.score` from the rule pack and a JA4 fingerprint verdict for defense in depth: a stealth client that defeats one layer still trips the others. The rule pack here is a single rule (see `agents.yml`); its job is to install detection so the header-only extractor runs, and it also names the obvious `HeadlessChrome` case so the example demonstrates a rule-pack hit alongside the score.

The TLS fingerprint catalog ships empty for licensing reasons, so a stock build never contradicts a client on fingerprint grounds. See [docs/headless-detection.md](../../docs/headless-detection.md) for how to supply your own catalog and capture a known-good value.

## See also

- [docs/headless-detection.md](../../docs/headless-detection.md) lists every indicator and its weight.
- [examples/web-bot-auth](../web-bot-auth/) is the cryptographic counterpart: proving a bot is who it claims to be, rather than catching one that hides.
