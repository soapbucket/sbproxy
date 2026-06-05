# Headless detection
*Last modified: 2026-05-31*

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

Pair with `request.agent.score` and the JA4 verdict for a layered defence: a benign request scoring low on every dimension passes; a stealth headless that defeats one layer still trips the others.

## Scope and limitations

This module is the deterministic, request-side half of the headless-detection design. Two further layers compose on top in follow-ups:

* **JS-execution challenge**: serve a script that posts a token back on first navigation; absence of the token on subsequent requests is a stronger signal than any header heuristic.
* **Session-window consistency**: header-order hash drift across the same session is a strong stealth indicator; needs the session-tracking surface to land.

The proprietary ML score that Akamai Content Protector pairs with these heuristics stays an integration boundary; this module is the open half.

## See also

- [scripting.md](scripting.md) - the full CEL / Lua / JavaScript / WASM expression surface.
- `crates/sbproxy-agent-detect/src/headless_indicators.rs` - source.
- The JA4 CatBoost scorer that this pairs with.
