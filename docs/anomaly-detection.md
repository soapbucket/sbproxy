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

The detector keeps a rolling 28-day histogram per agent class and flags an observation whose share of the window sits below `outlier_frequency`.

| Kind | Fires when | Severity |
|---|---|---|
| `ja4_outlier` | A TLS fingerprint is in the long tail for its agent class | `critical` when the class has never presented it, `warn` when it is ten times rarer than the threshold, `info` otherwise |
| `ml_inconsistency` | The resolver source that identified this caller is in the tail for its class | Same scale |
| `headless_library` | A headless-browser library is in the tail | Never below `warn`. A headless library arrives with intent attached |
| `request_rate_spike` | One address is past its class's per-address mean today by `rate_spike_multiplier` | `critical` past five times the multiplier, `warn` otherwise |

A TLS fingerprint the gateway does not trust, because the connection arrived through something that re-terminates TLS, is neither learned nor judged. It is not evidence about the caller.

## Configuration

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `false` | Master switch. When false, no histogram is built and no detector is installed |
| `min_observations` | int | `50` | Observations a dimension needs before anything is called an outlier |
| `outlier_frequency` | float | `0.01` | Share of the window below which a value is an outlier |
| `rate_spike_multiplier` | float | `10.0` | Multiple of the per-address mean that counts as a spike |
| `rate_spike_min_mean` | float | `5.0` | Mean per-address rate below which the spike check does not engage |

Values that would disable the detector silently are clamped rather than accepted: `min_observations: 0` would flag every first sighting, and `outlier_frequency: 0` would flag nothing while looking configured.

## The window is in memory, and that is a decision

There is no persistence option. A restart empties 28 days of signal, and the detector is quiet until it has re-learned a baseline.

The alternative is a database the proxy cannot start without, which is the dependency this feature ships under a rule against. So read a quiet `sbproxy_anomaly_detected_total` after a deploy as a detector that is still learning rather than as a quiet network, and expect a detector on a frequently-restarted deployment to spend a meaningful fraction of its life below `min_observations`.

Three other bounds are worth knowing, because each one is a place the detector deliberately stops rather than growing:

- **64 agent classes.** The class comes from a closed taxonomy, so this is never reached in a healthy deployment. Past it the detector stops learning new classes rather than allocating a window for whatever string reached it.
- **1,024 distinct values per dimension per day.** Past that, values land in one overflow bucket the detector treats as having no baseline.
- **4,096 addresses per class per day.** Past that the quietest tracked address is evicted, which under a distributed attacker forgets an honest one. That is why the per-address rate is one signal of four rather than the whole detector.

## Reputation

Verdicts feed a per-agent-class score published as `sbproxy_agent_reputation_score`, between 1.0 (nothing flagged inside the window) and 0.0. A `critical` verdict costs five times a `warn`; an `info` costs nothing. Weight decays by rolling out of the same 28-day window rather than on a timer, so a class that stops misbehaving recovers on its own and there is no scheduled task to own or to fail.

**Nothing on the request path reads this score.** That is deliberate and it is an open question rather than an oversight: wiring reputation into an admission decision means answering what a request should do when its class scores 0.4, and that has not been decided. Publishing a number for an operator to act on is honest; acting on it automatically without having decided the policy is not. If you want to act on it today, alert on the gauge.

## Watching it

| Metric | Labels | What it tells you |
|---|---|---|
| `sbproxy_anomaly_detected_total` | `kind`, `severity` | Every flagged observation |
| `sbproxy_agent_reputation_score` | `agent_class` | The score, 1.0 down to 0.0 |

The "Behavioral Anomalies" and "Agent Reputation" panels on the `SBProxy Security` dashboard draw both, and the admin console's Metrics view carries an Anomalies card. Every `warn` and `critical` verdict also writes a structured log line carrying the kind, the severity, and a reason; `info` verdicts log at debug.

A reason names the class and the dimension and never the request. A rate-spike reason gives the count and the mean but not the address, because the reason string reaches logs and the access log already carries the address in its own column.

## Extending it

`AnomalyDetectorHook` is part of the public plugin surface, so a linked crate can register a detector of its own; every registered hook runs and every verdict any of them returns is counted and logged the same way. See [`plugins.md`](plugins.md).

## See also

- [headless-detection.md](headless-detection.md) - one of the signals this consumes.
- [trust-tiers.md](trust-tiers.md) - the four-value tier a request carries, which is separate from reputation and is read at request time.
- [observability.md](observability.md) - the metric conventions these families follow.
- [examples/anomaly-detection/](../examples/anomaly-detection/) - a runnable config.
