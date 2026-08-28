# Anomaly detection
*Last modified: 2026-08-27*

The gateway already collects a TLS fingerprint, a headless-browser indicator, an agent class, and a client address on every request. Anomaly detection is what happens when you keep those signals for a while and ask which of today's requests do not look like the rest.

It is comparative rather than rule-based, and that is the whole trade. A rule list catches what somebody already wrote down. This catches a crawler that claims to be GPTBot and dials with a TLS fingerprint no GPTBot has ever used, without anyone having seen that fingerprint before. What it costs is that it says nothing at all until it has a baseline, and it is only as good as the traffic it learned from.

Off by default. Turn it on with:

```yaml
proxy:
  anomaly:
    enabled: true
```

## What it flags

The detector keeps a rolling 28-day histogram per tenant and agent class and flags an observation whose share of the window sits below `outlier_frequency`.

| Kind | Fires when | Severity |
|---|---|---|
| `ja4_outlier` | A TLS fingerprint is in the long tail for its agent class | `critical` when the class has never presented it, `warn` when it is ten times rarer than the threshold, `info` otherwise |
| `ml_inconsistency` | The resolver source that identified this caller is in the tail for its class | Same scale |
| `headless_library` | A headless-browser library is in the tail of the class's other headless detections | Never below `warn`. A headless library arrives with intent attached |
| `request_rate_spike` | One address is past its class's per-address mean today by `rate_spike_multiplier` | `critical` past five times the multiplier, `warn` otherwise |

A TLS fingerprint the gateway does not trust, because the connection arrived through something that re-terminates TLS, is neither learned nor judged. It is not evidence about the caller.

Two arms have a shape worth knowing before you read their output.

**`ml_inconsistency` never fires for becoming verified.** The dimension is the resolver source (`user_agent`, `bot_auth`, `kya`, `rdns`, ...), and the verified sources (`bot_auth`, `kya`, `rdns`, `tls_fingerprint`) are learned into the baseline but never judged as outliers. Without that rule, turning on Web Bot Auth for an established class scored the first verified request `critical` and floored the class for having strengthened its identity. The reverse still fires, and is the reason the dimension exists: a class whose population is verified, arriving unverified, is an outlier.

**`headless_library` compares libraries against each other, not against traffic.** Only a detection is observed: a request with no headless signal is not counted in the denominator. So the frequency is "this library as a share of the class's headless detections", and a deployment that only ever sees one headless library has that library at 1.0 and this arm stays quiet by construction. It has something to say once a second library shows up.

**A value flagged `critical` is not learned.** Counting it toward the denominator but not into the baseline is what stops a caller from laundering its own fingerprint: keep sending, cross the 1% threshold on your own volume, and you would otherwise stop being flagged and become part of the population that judges everyone else.

## Where it runs, and what that leaves out

The detector is dispatched from the response phase. A request that never reaches a response filter is never judged and never learned from:

- a `static` or `mock` origin, which writes its response in the request phase;
- a request served from the hot cache or the cache reserve;
- anything authentication, a policy, or a rate limiter already refused.

So the population the detector calls "normal" is the population that reached an origin, and an attacker whose requests are all being refused contributes nothing to the histogram and nothing to its class's reputation. That is worth holding in mind before reading a quiet detector as a quiet network.

## Configuration

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `false` | Master switch. When false, no histogram is built and no detector is installed |
| `min_observations` | int | `50` | Observations a dimension needs before anything is called an outlier |
| `outlier_frequency` | float | `0.01` | Share of the window below which a value is an outlier |
| `rate_spike_multiplier` | float | `10.0` | Multiple of the per-address mean that counts as a spike |
| `rate_spike_min_mean` | float | `5.0` | Mean per-address rate below which the spike check does not engage |
| `reputation.deny_below` | float | unset | Reputation score below which admission refuses the request with a `403` |
| `reputation.challenge_below` | float | unset | Reputation score below which admission answers `429` |

Values that would disable the detector silently are clamped rather than accepted: `min_observations: 0` would flag every first sighting, and `outlier_frequency: 0` would flag nothing while looking configured. `outlier_frequency` clamps to a floor of `1e-6` rather than to the smallest positive float, which would have flagged only a value with literally no history and read as a configured, silent detector.

## The window is in memory, and that is a decision

There is no persistence option. A restart empties 28 days of signal, and the detector is quiet until it has re-learned a baseline.

The alternative is a database the proxy cannot start without, which is the dependency this feature ships under a rule against. So read a quiet `sbproxy_anomaly_detected_total` after a deploy as a detector that is still learning rather than as a quiet network, and expect a detector on a frequently-restarted deployment to spend a meaningful fraction of its life below `min_observations`.

Three other bounds are worth knowing, because each one is a place the detector deliberately stops rather than growing:

- **512 tenant-and-class pairs.** The class comes from a closed taxonomy, so this is never reached in a healthy deployment. Past it the detector stops learning new pairs rather than allocating a window for whatever string reached it.
- **1,024 distinct values per dimension per day.** A bounded LRU: past the cap the least recently observed value is evicted. Every dimension the detector reads is derived from something the client controls, and an unbounded set is memory a caller can buy. Eviction costs that value its history, so its next sighting looks *more* anomalous rather than less, which is the direction to fail in. The denominator is a separate running counter, so an evicted observation still counts.
- **4,096 addresses per class per day.** Past that the quietest tracked address is evicted, which under a distributed attacker forgets an honest one. That is why the per-address rate is one signal of four rather than the whole detector.

The per-request cost is bounded for the same reason and in the same place. Reading the denominator is 28 integer loads whatever the client has done to the distinct-value count, and the histogram is sharded across 16 mutexes keyed by tenant and class, so one busy class does not serialize every other one.

## A reload does not cost the window

A config reload keeps the running detector when the resolved `proxy.anomaly` block is unchanged, which is the common case: a reload triggered by a neighboring file, or by an edit somewhere else in the config, leaves the baseline alone. A reload that genuinely changes `proxy.anomaly` starts over, and so does a restart.

A reload that fails to compile changes nothing. The detector is installed after every fallible step of the config compile, so a rejected config cannot leave a security control switched off or a warmed window discarded.

## Reputation

Verdicts feed a per-tenant, per-agent-class score published as `sbproxy_agent_reputation_score`, between 1.0 (nothing flagged inside the window) and 0.0. A `critical` verdict costs five times a `warn`; an `info` costs nothing. Weight decays by rolling out of the same 28-day window rather than on a timer, so a class that stops misbehaving recovers on its own and there is no scheduled task to own or to fail.

The gauge is republished on every analysis, not only when a verdict fires, so the number moves while a class recovers. A class that goes entirely silent keeps its last published score until it sends again: there is no timer, and adding one whose only job is to decay a number nobody is producing would be a background task to own for a dashboard's benefit.

The score carries a `tenant_id` label and the histogram is keyed by tenant, so one customer's noisy crawler cannot move another customer's number.

### Acting on it

Both thresholds are unset by default, which leaves the score advisory: it is published, and nothing acts on it.

```yaml
proxy:
  anomaly:
    enabled: true
    reputation:
      challenge_below: 0.6   # 429
      deny_below: 0.2        # 403
```

That is the same shape Cloudflare's threat score has: the gateway computes the number always, and a rule the operator writes decides what it means. `deny_below` wins when a score is under both. The check runs after the origin resolves and before authentication, because the decision is about the caller's standing rather than its credential, and a floored class should not get its token verified and its issuer dialed before it is refused.

A class with no history is admitted. Refusing on the absence of evidence would refuse every caller for the first `min_observations` requests after every restart.

**Read this before picking a number.** Two properties of the score decide whether a threshold does what you want:

- **The class is a claim unless the resolver source was a verified one.** Anyone can send GPTBot's `User-Agent`, be resolved into the `gptbot` class, and misbehave there, which moves the score the real GPTBot is then admitted against. Only `bot_auth`, `kya`, `rdns`, and `tls_fingerprint` are verified. The decision record carries the source (see below) so a rule written after the fact can tell the two apart, and pairing a reputation floor with [Web Bot Auth](web-bot-auth.md) or [KYA](configuration.md#kya) is what makes it mean something.
- **`unknown` is a shared bucket.** It holds everything the resolver did not recognize, which on a public gateway is most of the web. A floor that catches `unknown` catches all of it.

## Watching it

| Metric | Labels | What it tells you |
|---|---|---|
| `sbproxy_anomaly_detected_total` | `kind`, `severity` | Every flagged observation |
| `sbproxy_agent_reputation_score` | `tenant_id`, `agent_class` | The score, 1.0 down to 0.0 |

The "Behavioral Anomalies" and "Agent Reputation" panels on the `SBProxy Security` dashboard draw both, and the admin console's Metrics view carries an Anomalies card. Every verdict writes a structured log line carrying the kind, the severity, and a reason: `warn` and `critical` at `warn`, everything else at `info`. Nothing logs at `debug`, because a release build compiles `debug!` out and a counted verdict with no record at all is worse than a noisier log.

Every verdict also publishes a typed decision record on the `anomaly` event, and so does every reputation refusal. Turn the feed on with:

```yaml
proxy:
  observability:
    log:
      decision_audit:
        enabled: true
        events:
          anomaly: true
```

A detection record carries `anomaly_kind` and a `verdict` holding the severity, and its outcome is an allow, because a verdict is an observation and the request proceeds. An admission record carries `reputation_bucket` (`clean`, `watch`, `suspect`, `bad`, `floored`) and a `verdict` holding the action, and its outcome is a deny. Both carry `identity_source`. Neither carries the raw score, the fingerprint, or the client address. See [decision-records.md](decision-records.md).

A reason names the class and the dimension and never the request. A rate-spike reason gives the count and the mean but not the address, because the reason string reaches logs and the access log already carries the address in its own column.

## Extending it

`AnomalyDetectorHook` is part of the public plugin surface, so a linked crate can register a detector of its own; every registered hook runs and every verdict any of them returns is counted and logged the same way. See [`plugins.md`](plugins.md).

## See also

- [headless-detection.md](headless-detection.md) - one of the signals this consumes.
- [trust-tiers.md](trust-tiers.md) - the four-value tier a request carries, which is separate from reputation and is read at request time.
- [observability.md](observability.md) - the metric conventions these families follow.
- [examples/anomaly-detection/](../examples/anomaly-detection/) - a runnable config.
