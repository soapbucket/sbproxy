# Behavioral anomaly detection

*Last modified: 2026-08-27*

The proxy already collects a TLS fingerprint, a headless-browser
indicator, an agent class, and a client address on every request. This
turns those into a question: which of today's requests do not look like
the rest of their class?

The detector keeps a rolling 28-day histogram per tenant and agent class
and flags an observation whose share of the window sits in the long
tail. It is comparative rather than rule-based, which is what lets it
catch a crawler claiming to be GPTBot with a TLS fingerprint no GPTBot
has ever presented, without anyone having written that fingerprint down
first.

## What this example can show you, and what it cannot

Three of the four arms need something a plain-HTTP walkthrough does not
have. `ja4_outlier` and `headless_library` both read a TLS fingerprint,
and `ml_inconsistency` reads the resolver source, which stays `None`
until an agent-class catalog resolves the caller. So this example drives
the fourth, `request_rate_spike`, and drives it from two client
addresses: with one address the per-address mean *is* that address's
rate, and the spike condition cannot be met at any multiplier. The
config's `trusted_proxies` is what lets `X-Forwarded-For` stand in for
two callers on one machine; a real deployment lists its own load
balancers there and nothing else.

To exercise the fingerprint arms, put this config behind a TLS listener
and an agent-class catalog and drive it with two clients whose
ClientHellos differ. That is a bigger setup than an example should ask
for, which is why it is described rather than shipped.

## Run

```bash
python3 examples/cache-reserve/fixture.py &
make run CONFIG=examples/anomaly-detection/sb.yml
```

The upstream is the counting fixture the
[cache-reserve](../cache-reserve/) example ships. A real upstream and
not a `static` origin, because the detector is dispatched from the
response phase and a `static` origin writes its response in the request
phase, so it would never be judged at all.

## It says nothing until it has a baseline

That is the trade, and it is worth seeing rather than reading. Send five
requests from one address:

```bash
for i in $(seq 1 5); do
  curl -s -o /dev/null -H 'Host: anomaly.local' \
    -H 'X-Forwarded-For: 198.51.100.7' http://127.0.0.1:8080/a
done
curl -s http://127.0.0.1:9090/metrics | grep sbproxy_anomaly_detected_total
```

Nothing, and the reason is worth knowing before you tune this on your
own traffic: the mean is read before the request is counted, so with a
single address the count is always exactly one past the mean. Any floor
those five requests could reach would fire on them. `rate_spike_min_mean`
is set to `6.0` here so they stay under it, and five requests from one
address take the mean to `4.0`.

## Then make one address the loud one

```bash
for i in $(seq 1 8); do
  curl -s -o /dev/null -H 'Host: anomaly.local' \
    -H 'X-Forwarded-For: 203.0.113.9' http://127.0.0.1:8080/a
done
curl -s http://127.0.0.1:9090/metrics | \
  grep -E 'sbproxy_anomaly_detected_total|sbproxy_agent_reputation_score'
```

Two lines, and these are the exact ones to expect:

```text
sbproxy_anomaly_detected_total{kind="request_rate_spike",severity="warn"} 1
sbproxy_agent_reputation_score{agent_class="unknown",tenant_id="__default__"} 0.99
```

The eighth request from the second address is the one that fires: at that
point the class has seen 5 requests from one address and 7 from the
other, a mean of `6.0`, and an eighth from the second address is past it.
The verdict is a `warn` rather than a `critical` because it is nowhere
near five times the mean, and a `warn` costs its class one point of
reputation out of a hundred, so the score reads `0.99`.

Those numbers are pinned by a test
(`anomaly::tests::the_shipped_example_walkthrough_produces_the_numbers_it_prints`),
so a change to the detector that moves them fails the build rather than
quietly making this page wrong.

This example sets `min_observations: 5` so a handful of curls is enough
for the dimensions that use it, and `rate_spike_multiplier: 1.0` so
thirteen requests are enough for the one that does not. Leave both at
their defaults (50 and 10.0) in production.

## What it flags

| Kind | Fires when | Severity |
|---|---|---|
| `ja4_outlier` | A TLS fingerprint is in the long tail for its class | `critical` when the class has never presented it |
| `ml_inconsistency` | The resolver source that identified the caller is in the tail | Scales with rarity |
| `headless_library` | A headless-browser library is in the tail | Never below `warn` |
| `request_rate_spike` | One address is past its class's per-address mean by `rate_spike_multiplier` | `critical` past five times that |

A TLS fingerprint the gateway does not trust, because the connection
came through something that re-terminates TLS, is neither learned nor
judged. It is not evidence about the caller, and letting it into the
baseline would teach the detector the CDN's fingerprint instead of the
agent's.

`ml_inconsistency` never fires for a class becoming verified: the
verified resolver sources (`bot_auth`, `kya`, `rdns`,
`tls_fingerprint`) are learned into the baseline but never judged. The
reverse, a class whose population is verified arriving unverified, still
fires, and is why the dimension exists.

## Reputation

```bash
curl -s http://127.0.0.1:9090/metrics | grep sbproxy_agent_reputation_score
```

Every verdict costs its class some reputation: five for a `critical`,
one for a `warn`, nothing for an `info`, out of a hundred. The weight
decays by rolling out of the same 28-day window rather than on a timer,
so a class that stops misbehaving recovers on its own and there is no
scheduled task to own. The gauge is republished on every analysis rather
than only when a verdict fires, so the number moves while the class is
recovering, not only while it is misbehaving.

The score carries a `tenant_id` label and the histogram is keyed by
tenant, so one customer's noisy crawler cannot move another customer's
number.

By default nothing on the request path reads the score: it is published,
and acted on by nothing. Uncomment the `reputation:` block in `sb.yml`
to turn it into an admission decision, and read the "Read this before
picking a number" section of
[docs/anomaly-detection.md](../../docs/anomaly-detection.md) first. The
short version is that the agent class is a claim unless the resolver
source was a verified one, and `unknown` is a shared bucket holding most
of the unclassified web.

## A restart costs the window; a reload does not

There is no persistence option, so a restart empties 28 days of signal
and the detector is quiet until it has re-learned a baseline. The
alternative is a database the proxy cannot start without.

A config reload keeps the running detector when the resolved
`proxy.anomaly` block is unchanged, so a reload triggered by an edit
somewhere else in the config costs nothing. A reload that changes
`proxy.anomaly` starts over, and one that fails to compile changes
nothing at all.

Practically: read a quiet `sbproxy_anomaly_detected_total` after a
deploy as a detector that is still learning, not as a quiet network. On
a deployment that restarts often, expect it to spend a meaningful part
of its life below `min_observations`.

## Watching it

The "Behavioral Anomalies" and "Agent Reputation" panels on the
`SBProxy Security` dashboard draw both families, and the admin console's
Metrics view carries an Anomalies card. Every verdict also writes a
structured log line with the kind, the severity, and a reason: `warn`
and `critical` at `warn`, everything else at `info`. Nothing logs at
`debug`, because a release build compiles that out and a counted verdict
with no record at all is worse than a noisier log.

Every verdict, and every reputation refusal, also publishes a typed
decision record on the `anomaly` event when
`observability.log.decision_audit` is on. The record carries the kind or
the reputation band and the resolver source, never the raw score, the
fingerprint, or the address.

A reason names the class and the dimension, never the request. A
rate-spike reason gives the count and the mean and not the address: the
reason reaches logs and audit records, and the access log already
carries the address in a column of its own.

## See also

- [docs/anomaly-detection.md](../../docs/anomaly-detection.md) - the full reference.
- [docs/headless-detection.md](../../docs/headless-detection.md) - one of the signals this consumes.
- [docs/trust-tiers.md](../../docs/trust-tiers.md) - the tier a request carries, which is read at request time and is a different thing from reputation.
