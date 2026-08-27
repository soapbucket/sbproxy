# Behavioral anomaly detection

*Last modified: 2026-08-27*

The proxy already collects a TLS fingerprint, a headless-browser
indicator, an agent class, and a client address on every request. This
turns those into a question: which of today's requests do not look like
the rest of their class?

The detector keeps a rolling 28-day histogram per agent class and flags
an observation whose share of the window sits in the long tail. It is
comparative rather than rule-based, which is what lets it catch a
crawler claiming to be GPTBot with a TLS fingerprint no GPTBot has ever
presented, without anyone having written that fingerprint down first.

## Run

```bash
make run CONFIG=examples/anomaly-detection/sb.yml
```

## It says nothing until it has a baseline

That is the trade, and it is worth seeing rather than reading. Send
twenty requests:

```bash
for i in $(seq 1 20); do
  curl -s -o /dev/null -H 'Host: anomaly.local' http://127.0.0.1:8080/get
done
curl -s http://127.0.0.1:9090/metrics | grep sbproxy_anomaly_detected_total
```

Nothing. The window has not reached `min_observations` for any
dimension, so there is no population to call anything rare against. A
detector that flagged the first sighting of everything would flag every
request on a fresh deployment, which is the same as flagging nothing.

This example sets `min_observations: 5` so a handful of curls is enough.
Leave it at the default of 50 in production.

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

## Reputation

```bash
curl -s http://127.0.0.1:9090/metrics | grep sbproxy_agent_reputation_score
```

Every verdict costs its class some reputation: five for a `critical`,
one for a `warn`, nothing for an `info`, out of a hundred. The weight
decays by rolling out of the same 28-day window rather than on a timer,
so a class that stops misbehaving recovers on its own and there is no
scheduled task to own.

Nothing on the request path reads this score. That is deliberate:
deciding what a request should do when its class scores 0.4 is a policy
question nobody has answered, and acting on a number without having
decided the policy is how a gateway starts refusing traffic for reasons
its operator cannot explain. Alert on the gauge instead.

## A restart costs the window

There is no persistence option, so a restart empties 28 days of signal
and the detector is quiet until it has re-learned a baseline. The
alternative is a database the proxy cannot start without.

Practically: read a quiet `sbproxy_anomaly_detected_total` after a
deploy as a detector that is still learning, not as a quiet network. On
a deployment that restarts often, expect it to spend a meaningful part
of its life below `min_observations`.

## Watching it

The "Behavioral Anomalies" and "Agent Reputation" panels on the
`SBProxy Security` dashboard draw both families, and the admin console's
Metrics view carries an Anomalies card. Every `warn` and `critical`
verdict also writes a structured log line with the kind, the severity,
and a reason.

A reason names the class and the dimension, never the request. A
rate-spike reason gives the count and the mean and not the address: the
reason reaches logs and audit records, and the access log already
carries the address in a column of its own.

## See also

- [docs/anomaly-detection.md](../../docs/anomaly-detection.md) - the full reference.
- [docs/headless-detection.md](../../docs/headless-detection.md) - one of the signals this consumes.
- [docs/trust-tiers.md](../../docs/trust-tiers.md) - the tier a request carries, which is read at request time and is a different thing from reputation.
