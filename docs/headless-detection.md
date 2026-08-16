# Headless detection
*Last modified: 2026-08-16*

Header-only heuristics that flag headless and stealth-browser clients even when their TLS / JA4 fingerprint matches a real browser. Pairs with the rule-based agent detection (`request.agent.score`) and the JA4 scorer.

## What it catches

Vanilla automation tooling (Puppeteer, Playwright, Selenium with default config) ships an obvious automation marker in the `User-Agent`. The TLS layer catches the rest of the unstealthy cases. The remaining gap is stealth wrappers (puppeteer-stealth, undetected-chromedriver, Playwright with the stealth plugin) that patch the JS-side `navigator.webdriver` and rotate the JA4 vector but cannot rewrite the request shape itself. Their requests carry a Chrome `User-Agent` but lack the `Sec-Ch-Ua` and `Sec-Fetch-*` families that every real Chrome navigation sends.

The deterministic indicators below score these requests without running a model, without running JavaScript on the client, and without holding any session state.

## Indicators

| Indicator | Fires when | Weight |
|---|---|---|
| `automation_marker_in_user_agent` | UA contains `HeadlessChrome`, `PhantomJS`, `Puppeteer`, `Playwright`, `Selenium`, `WebDriver`, or `SlimerJS` | 60 |
| `claims_chrome_without_client_hints` | UA carries the Chrome vendor token but no `Sec-Ch-Ua` / `Sec-Ch-Ua-Mobile` / `Sec-Ch-Ua-Platform` header is present | 25 |
| `claims_chrome_without_sec_fetch` | UA carries the Chrome vendor token but no `Sec-Fetch-*` fetch-metadata header is present | 25 |
| `accept_language_missing` | the request omits `Accept-Language` entirely | 15 |
| `accept_encoding_anomalous` | the `Accept-Encoding` value does not match a canonical browser order (`gzip, deflate, br` or `gzip, deflate, br, zstd`) | 10 |

Weights add up; the score saturates at 100. Score bands:

| Score   | Interpretation                                  |
|---------|-------------------------------------------------|
| 0-19    | indistinguishable from a real browser           |
| 20-49   | one or two stealth hints; low confidence        |
| 50-79   | several hints; high-confidence headless         |
| 80-100  | obvious automation; vanilla headless saturates  |

Real Firefox and Safari requests never trip the Chrome-only indicators because the heuristic gates the `Sec-Ch-Ua` and `Sec-Fetch` checks on a Chrome vendor token in the UA. Firefox and Safari requests without the Sec-Ch-Ua family are expected; the heuristic does not flag them.

## Surface

The indicators are computed automatically when `proxy.extensions.agent_detect.enabled` is set; the same site that builds `Signals` for the rule pack also runs the header-only headless extractor. Two CEL bindings are exposed under the existing `request.agent.*` namespace:

* `request.agent.headless_score` - integer 0-100.
* `request.agent.headless_indicators` - list of indicator names that fired.

## Example: block obvious headless above 50

```yaml
proxy:
  extensions:
    agent_detect:
      enabled: true
      rule_pack_path: /etc/sbproxy/agents.yml
      onnx_model_path: /etc/sbproxy/ja4-catboost.onnx

origins:
  "secure.example.com":
    action:
      type: proxy
      url: http://backend:3000
    policies:
      - type: expression
        expression: 'request.agent.headless_score < 50'
        deny_status: 403
        deny_message: "automation suspected"
```

Pair with `request.agent.score` and the JA4 verdict for a layered defense: a benign request scoring low on every dimension passes; a stealth headless that defeats one layer still trips the others.

`onnx_model_path` loads an in-process CatBoost ONNX scorer at startup.
When both `rule_pack_path` and `onnx_model_path` are set, exact
rule-pack identity matches win and the ONNX scorer runs on rule misses.

## The fingerprint catalog ships empty

`tls_fingerprint_matches(ja4, agent_class_id)` reads a catalog of known
JA3 / JA4 / JA4H values per agent class. That catalog contains the class
names and **no fingerprints**.

The reason is licensing rather than laziness. A JA4 value is a measurement
of one specific client build, and the published collections of those
measurements come with their own license terms. Shipping a populated
default meant redistributing somebody else's licensed data inside an
Apache-2.0 binary, which is a promise we cannot keep on data we do not
own.

An empty class answers `true`, which is the conservative direction. A
stock build therefore never contradicts a client on fingerprint grounds:
detection is inert rather than wrong, and no legitimate crawler is
accused of spoofing because we guessed at its hash.

Supply your own file to turn it on:

```yaml
proxy:
  extensions:
    tls_fingerprint:
      enabled: true
      catalog_file: /etc/sbproxy/tls-fingerprints.json
```

It replaces the embedded catalog wholesale rather than merging into it,
so the file you wrote is the whole truth and nothing ships underneath it
that you did not put there. The schema is
`crates/sbproxy-classifiers/data/tls-fingerprints.json`.

### Capturing a value

The proxy already computes the fingerprint of every live handshake and
exposes it as `request.tls.ja4`, so a known-good client is one catalog
line. Stamp it into a response header with a CEL transform and read it
back:

```yaml
transforms:
  - type: cel
    headers:
      - { op: set, name: x-ja4, value_expr: "request.tls.ja4" }
```

Then send one request from the client you want to catalog and record
what comes back. An access-log field works equally well for collecting
values from real traffic over time.

Two things worth knowing before you trust a value. A headless
fingerprint tracks the bundled Chromium build, so a hash captured from
Puppeteer 22 says nothing about Puppeteer 23; capture per release you
care about. And a value is only as trustworthy as the client that
produced it, so capture from a client you control rather than from
traffic you are trying to classify.

## Scope and limitations

This module is the deterministic, request-side half of the headless-detection design. Two further layers compose on top in follow-ups:

* **JS-execution challenge**: serve a script that posts a token back on first navigation; absence of the token on subsequent requests is a stronger signal than any header heuristic.
* **Session-window consistency**: header-order hash drift across the same session is a strong stealth indicator; needs the session-tracking surface to land.

The proprietary ML score that Akamai Content Protector pairs with these heuristics stays an integration boundary; this module is the open half.

## See also

- [scripting.md](scripting.md) - the full CEL / Lua / JavaScript / WASM expression surface.
- `crates/sbproxy-agent-detect/src/headless_indicators.rs` - source.
- The JA4 CatBoost scorer that this pairs with.
