# ADR: TLS fingerprint pipeline (JA3/JA4/JA4H/JA4S) (Wave 5 / A5.1)

*Last modified: 2026-05-02*

## Status

Accepted. Wave 5 identity pillar. Builds on `adr-agent-class-taxonomy.md` (G1.1, `RequestContext` that gains the `tls_fingerprint` field), `adr-bot-auth-directory.md` (A1.3, the UA-spoof detection use case), `adr-admin-action-audit.md` (A1.7, redaction rules for fingerprint data), `adr-schema-versioning.md` (A1.8). Consumed by G5.3 (JA3/JA4 capture in `sbproxy-tls`), G5.4 (headless browser detection in `sbproxy-security/headless_detect.rs`), G5.5 (ML classifier feature input per A5.2), G5.6 (anomaly detection baselines), Q5.2 (fingerprint capture e2e), and Q5.7 (latency overhead bench).

## Context

TLS fingerprinting extracts a stable hash from the TLS ClientHello handshake that identifies the TLS library a client used, independent of its declared User-Agent string. JA3 (Salesforce 2017) hashes the TLS 1.2 ClientHello cipher suites, extensions, elliptic curves, and EC point formats. JA4 (FoxIO 2023) extends the concept to TLS 1.3 with a structured prefix and more stable hash inputs. JA4H captures the HTTP request fingerprint based on header ordering. JA4S captures the TLS ServerHello from the proxy's outbound perspective.

Two primary Wave 5 use cases motivate the capture:

- **UA-spoof detection.** GPTBot's published TLS ClientHello fingerprint differs from Playwright's and curl's. A request claiming `User-Agent: GPTBot` but presenting a Playwright JA4 is likely spoofed.
- **Headless browser detection (G5.4).** Puppeteer, Playwright, and undetected-chromedriver have known JA4 signatures that are distinct from real browser fingerprints.

The capture adds 50-100 microseconds per handshake and is not needed by all operators. It is feature-gated.

## Decision

### What each fingerprint measures

**JA3** targets TLS 1.2 ClientHello. The input string is five comma-delimited fields: TLS version, cipher suite list, extension type list, elliptic curve group list, EC point format list (all as decimal values, colon-delimited within each field). GREASE values (RFC 8701) are filtered before hashing to improve stability across library patch releases. The MD5 hash of this string is the 32-char hex JA3 fingerprint.

**JA4** targets TLS 1.3 ClientHello (FoxIO spec). The fingerprint is two parts joined by `_`: a 10-character human-readable prefix encoding protocol letter, TLS version digits, SNI indicator, cipher-suite count, extension count, and first and last ALPN values; and a 12-character truncated SHA-256 hash of the sorted cipher suite list. JA4 is more stable than JA3 across minor TLS library updates and does not require MD5. Full spec: `https://github.com/FoxIO-LLC/ja4`.

**JA4H** captures the HTTP request fingerprint independently of TLS. The input is the ordered list of request header names (values excluded) concatenated with a method-and-version prefix. The hash is a 12-character truncated SHA-256. JA4H detects agents that spoof `User-Agent` but reveal themselves through non-browser header ordering. This fingerprint is computed mid-pipeline (after TLS handshake, when headers are available), not at handshake time.

**JA4S** captures the TLS ServerHello fingerprint from the proxy's outbound TLS session to the upstream. Useful for confirming upstream identity and detecting outbound MITM conditions. For inbound agent identification JA4S is a secondary diagnostic signal.

### Capture point

TLS fingerprints are captured in `sbproxy-tls` at the Pingora TLS session lifecycle hook that fires after `ClientHello` is received and before the handshake reply is sent. At this point the raw ClientHello bytes are present.

The fingerprint computation is synchronous and completes within the TLS handshake window. The 50-100 microsecond budget is the parse-and-hash time for a typical 300-500 byte ClientHello on a modern CPU. This is inside the TLS handshake RTT (typically 1-3ms) and does not appear in p99 request latency. Q5.7 verifies the p99 latency adder is under 1%.

The result is stored on `RequestContext`:

```rust
pub struct TlsFingerprint {
    pub ja3: Option<String>,   // 32-char hex MD5
    pub ja4: Option<String>,   // e.g. "t13d1516h2_8daaf6152771"
    pub ja4h: Option<String>,  // HTTP fingerprint; populated mid-pipeline, not at handshake
    pub ja4s: Option<String>,  // ServerHello fingerprint; populated on outbound TLS session
    pub trustworthy: bool,
}

// On RequestContext:
pub tls_fingerprint: Option<TlsFingerprint>,
```

`tls_fingerprint` is `None` when the `tls-fingerprint` cargo feature is disabled or when the connection arrived over plaintext HTTP.

**Cargo feature.** The capture is behind `tls-fingerprint` (default off). Operators opt in via Helm value `features.tlsFingerprint = true` (B5.4). With the feature disabled the struct definition exists and the field is always `None`; no parse-and-hash work occurs.

### When fingerprints stop being reliable

The `trustworthy` boolean expresses whether the fingerprint reflects the actual client rather than an intermediate proxy or CDN.

Fingerprints are NOT trustworthy in these conditions:

- **Behind a CDN that terminates TLS.** The fingerprint is the CDN's TLS library, not the agent's.
- **Behind a corporate MITM proxy.** Same problem.
- **Behind a VPN or TLS-rewriting middlebox.** Same class.
- **HTTP/2 multiplexed connections after the first request.** The ClientHello was captured for the connection's first request. Subsequent multiplexed requests reuse the session without a new handshake; `ja3` and `ja4` are inherited and may be stale.

Configuration in `sb.yml`:

```yaml
features:
  tls_fingerprint:
    enabled: true
    trustworthy_client_cidrs:
      - 203.0.113.0/24    # direct-client IP range
    untrusted_client_cidrs:
      - 104.16.0.0/12     # Cloudflare CDN egress IPs
```

When a request's `client_ip` falls in `trustworthy_client_cidrs`, `trustworthy = true`. When it falls in `untrusted_client_cidrs`, `trustworthy = false`. When neither matches, `trustworthy = false` (conservative default). Policies making hard decisions based on fingerprints SHOULD gate on `request.tls.trustworthy == true`.

### Use cases for the fingerprint

**UA-spoof detection.** GPTBot has a published expected JA4. If a request claims `User-Agent: GPTBot` but its JA4 matches Puppeteer's published fingerprint, the gateway has strong evidence of spoofing. Operators act on this via a CEL rule using the `tls_fingerprint_matches(ja4, agent_class_id)` function (shipped in Wave 5 alongside G5.3).

**Headless detection (G5.4).** `sbproxy-security/headless_detect.rs` reads `request.tls_fingerprint.ja4` and checks it against the reference catalogue. A match sets `RequestContext.headless_signal = HeadlessSignal::Detected { library: "puppeteer", confidence: 0.95 }`, which feeds into the G1.4 resolver as an advisory signal.

**ML classifier feature (A5.2).** The agent classifier embeds JA4 prefix bytes as features in the input vector. This lets the classifier distinguish UA-spoofing agents even when behavioral features are otherwise similar.

**Anomaly baselines (G5.6).** The enterprise anomaly detector maintains a rolling 28-day histogram of JA4 values per `agent_class`. A sudden shift in the histogram is an anomaly signal.

### Worked example: GPTBot UA-spoof detection

An operator enables `tls-fingerprint` and configures:

```yaml
policies:
  - type: script
    engine: cel
    on_request: |
      if request.agent_class == "openai-gptbot" &&
         request.tls.trustworthy &&
         request.tls.ja4 != null &&
         !tls_fingerprint_matches(request.tls.ja4, "openai-gptbot") {
        deny(403, "UA-JA4 mismatch: potential GPTBot spoof")
      }
```

`tls_fingerprint_matches(ja4, agent_class_id)` looks up expected JA4 values for the given agent_class in the reference catalogue and returns true if `ja4` is in the set. It returns true if the catalogue has no entry for that agent_class (conservative: do not penalize uncatalogued agents).

The request is GPTBot-UA but Puppeteer-fingerprinted:

- `request.agent_class = "openai-gptbot"` (from UA resolver step).
- `request.tls.ja4 = "t13d1516h2_8daaf6152771"` (known Puppeteer fingerprint).
- `tls_fingerprint_matches(...)` returns false.
- `trustworthy = true` (direct client, no CDN).
- Policy fires: 403 denied.

### Worked example: headless Puppeteer detection

A request arrives with a generic UA and no bot-auth signature. Its JA4 is `t13d1516h2_8daaf6152771`, a known Puppeteer value.

The headless detector checks the reference catalogue and finds a match. It sets `RequestContext.headless_signal = HeadlessSignal::Detected { library: "puppeteer", confidence: 0.95 }`. Because no higher-confidence resolver step matched, the G1.4 chain reaches the new advisory TLS fingerprint step and emits `agent_class = "headless-browser"` (a new taxonomy entry added in the Wave 5 data update to `sbproxy-classifiers/data/agent_classes_default.yaml`).

If `trustworthy = false` (e.g. the request arrived via Cloudflare), the headless detector still records the signal but sets `confidence = 0.4` (advisory; the operator should not make hard decisions on this alone).

### Privacy

TLS fingerprints are not directly PII under most legal frameworks because they identify a software configuration, not a natural person. However, they carry session-correlation risk: the same browser or TLS library from the same user produces the same fingerprint, enabling cross-session tracking without cookies.

Privacy posture:

- Fingerprints are NOT logged to access logs by default.
- When logging is enabled (`log.fingerprint = true`), the logged value is a 16-character prefix of the SHA-256 of the full fingerprint. This retains anomaly-detection utility while reducing cross-session correlation precision.
- The full fingerprint is available to in-process policies (CEL, Lua, JS, WASM) and to the ML classifier. It is never forwarded to the upstream origin in request headers.
- Audit log entries include the fingerprint only in `HeadlessDetection` audit entries when the verdict is non-trivial, subject to A1.5 redaction rules.

### Scripting surface

CEL, Lua, JS, and WASM expose:

- `request.tls.ja3` - 32-char hex string or null.
- `request.tls.ja4` - JA4 structured prefix string or null.
- `request.tls.ja4h` - HTTP fingerprint string or null.
- `request.tls.trustworthy` - boolean.

WASM exposes the same via host function `sbproxy_tls_fingerprint() -> TlsFingerprintResult`.

CEL extension function `tls_fingerprint_matches(ja4: string, agent_class_id: string) -> bool` is shipped in Wave 5 alongside G5.3.

Note on pipeline ordering: `ja4h` is populated mid-pipeline when request headers are read in `sbproxy-core`, not at TLS handshake time. TLS-layer policies cannot read `ja4h`; request-pipeline policies can. This ordering is documented in the scripting reference (S5.1).

### Reference fingerprint catalogue

Vendored at `crates/sbproxy-classifiers/data/tls-fingerprints.json`. Schema:

```json
{
  "version": 1,
  "updated_at": "2026-05-01T00:00:00Z",
  "entries": [
    {
      "agent_class": "openai-gptbot",
      "ja3": ["<hash>"],
      "ja4": ["<hash>"],
      "ja4h": [],
      "notes": "FoxIO published list + Cloudflare agent registry, 2026-04"
    },
    {
      "agent_class": "headless-puppeteer",
      "ja3": [],
      "ja4": ["t13d1516h2_8daaf6152771"],
      "ja4h": [],
      "notes": "Puppeteer 22.x via Chromium 124"
    }
  ]
}
```

Sources: FoxIO's published JA4+ fingerprint databases (`https://github.com/FoxIO-LLC/ja4/tree/main/technical_details/fingerprint_databases`) and Cloudflare's published agent registry. Update cadence: monthly via a B5.x builder task that fetches upstream feeds, validates the JSON schema, and opens a PR. The update is data-only; CI runs Q5.2 against the new catalogue to catch regressions.

## Consequences

- Operators enabling `tls-fingerprint` gain UA-spoof and headless-browser detection at 50-100 microseconds per handshake overhead, verified under 1% p99 latency adder by Q5.7.
- Operators behind CDNs should configure `untrusted_client_cidrs`. Default `trustworthy = false` when no CIDR matches is conservative.
- The privacy defaults (no logging unless opted in, hashed prefix when logged) are appropriate for GDPR and CCPA contexts.
- The reference catalogue is a versioned data file. Monthly updates do not require a binary release; operators hot-reload it via SIGHUP.
- `ja4h` is populated mid-pipeline, not at TLS handshake. TLS-layer policies cannot read it.
- `AgentIdSource::TlsFingerprint` is a new closed-enum variant per A1.8 Rule 4 and requires an ADR amendment entry when G5.3 ships.

## Alternatives considered

**JA3 only, skip JA4.** Rejected. JA4 is more stable across minor TLS library updates (GREASE-resistant, no MD5) and is the FoxIO-recommended forward path. Shipping both preserves compatibility with operators who have existing JA3-based tooling.

**Capture at the Pingora filter layer instead of the TLS handshake.** Rejected. By the filter layer the raw ClientHello bytes are no longer available.

**Log the full fingerprint by default.** Rejected. Session-correlation risk is real. The conservative default is the right privacy posture for a gateway deployed by publishers under GDPR obligations.

**Runtime-fetched reference catalogue.** Rejected for Wave 5. Vendored is simpler (no additional network dependency) and monthly cadence is sufficient.

## References

1. `docs/adr-agent-class-taxonomy.md` (G1.1) - `RequestContext`, `AgentIdSource` enum, resolver chain.
2. `docs/adr-bot-auth-directory.md` (A1.3) - UA-spoof detection motivation.
3. `docs/adr-admin-action-audit.md` (A1.7) and `docs/AIGOVERNANCE.md` section 4.5.
4. `docs/AIGOVERNANCE-BUILD.md` section 8 (G5.3, G5.4, G5.5, G5.6, Q5.2, Q5.7, B5.4).
5. FoxIO JA4 specification: `https://github.com/FoxIO-LLC/ja4`.
6. FoxIO JA4+ fingerprint databases: `https://github.com/FoxIO-LLC/ja4/tree/main/technical_details`.
7. `crates/sbproxy-tls/` - TLS session lifecycle hooks where capture is inserted.
8. `crates/sbproxy-classifiers/` - reference catalogue location; feature-builder location for A5.2.
9. `crates/sbproxy-security/` - `headless_detect.rs` (G5.4) reads `tls_fingerprint` from `RequestContext`.
10. RFC 8701 (GREASE for TLS) - filtered before JA3/JA4 computation.
