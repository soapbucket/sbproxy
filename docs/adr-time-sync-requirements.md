# ADR: Time-sync requirements (NTP / PTP) (Wave 3 / A3.5)

*Last modified: 2026-05-01*

## Status

Accepted. Wave 3 substrate. Builds on `adr-billing-hot-path-vs-async.md` (the layering rule), `adr-http-ledger-protocol.md` (A1.2, HMAC nonce timestamp window), `adr-webhook-security.md` (A1.9, Stripe-style timestamp parameter), `adr-observability.md` (A1.4), `adr-admin-action-audit.md` (A1.7), `adr-audit-log-v0.md` (A2.3), and `adr-slo-alert-taxonomy.md` (A1.6). Companion ADRs: A3.3 (EVM reorg resistance) and A3.4 (end-to-end idempotency). Consumed by R3.3 (clock-skew detection in `/readyz`), Q3.14 (clock-skew regression test), and S3.5 (`docs/time-sync.md` operator runbook).

## Context

Wave 1 to Wave 3 introduce several mechanisms that break under clock skew:

- **HMAC nonce timestamps** (A1.2): the LedgerClient request envelope carries a `timestamp` and the ledger rejects values more than 60 s skewed. A proxy with a clock 5 minutes fast cannot talk to the ledger.
- **Quote-token JWS `exp` claims** (A3.2): the proxy rejects expired tokens and accepts unexpired ones based on its own clock vs the token's `exp`. A skewed proxy either rejects valid tokens or accepts replayed tokens past their real expiry.
- **x402 reorg confirmation windows** (A3.3): the confirmation worker queries chain head height to decide if `confirmation_depth` has been reached. If the worker uses wall-clock to estimate "the chain should have N more blocks by now", a skewed clock corrupts the heuristic.
- **MPP webhook `t=` timestamp** (A1.9): Stripe-style webhooks carry a `t=` value that gets compared against the verifier's clock with a 5-minute tolerance. A skewed verifier rejects valid webhooks.
- **Outbound webhook `Sbproxy-Signature` t=** (A1.9): same shape, customer-side. Our skewed signing time triggers the customer's tolerance check.
- **Audit batch `started_at` / `ended_at`** (A2.3): batch boundaries are wall-clock-based. Two flushers with skewed clocks produce overlapping batches.

Without a documented requirement, every operator deploys with the host's default time-sync (which on AWS is "Amazon Time Sync Service via DHCP option 42" by default, but on bare metal or self-hosted is whatever the operator configures, which historically has been "we forgot"). A pre-Wave-3 audit found one staging environment with a 14-minute clock skew that had been silently rejecting Stripe webhooks for three weeks; nothing in the platform alerted on it.

This ADR pins the NTP / PTP requirements, the allowed skew envelope per host pair, the detection mechanism on `/readyz`, the per-mechanism mitigations when skew is detected, the skew-induced failures we accept, and the operator runbook for triage.

## Decision

### NTP requirement

Every host running the proxy, the ledger service, the audit flusher, the confirmation worker, or any other SBproxy component MUST run `chronyd` (Linux) or equivalent NTP client. The minimum configuration:

```
# /etc/chrony/chrony.conf
makestep 1.0 3
maxpoll 10
minpoll 6
rtcsync
leapsectz right/UTC

# Production: low-stratum source.
# AWS: use the local time service (Amazon Time Sync Service).
server 169.254.169.123 prefer iburst minpoll 4 maxpoll 4
# GCP: metadata.google.internal time service.
# Bare metal: vendor's NTP pool plus 2-3 stratum-1 sources for quorum.
pool time.cloudflare.com iburst maxsources 4
```

Key directives:

- `makestep 1.0 3`: step the clock if more than 1 s off after 3 measurements. Without this, chrony slews (gradually adjusts) which is correct for tiny drift but pathological when starting from a large offset.
- `maxpoll 10` / `minpoll 6`: poll between 64 s and 1024 s. Tightens the loop for cloud workloads that may move between hosts.
- A low-stratum source: AWS Time Sync, Google Public NTP, Cloudflare NTP, or for the most demanding deployments PTP-IEEE-1588 against the operator's own grandmaster clock.

Containerised deployments inherit the host's clock; the container should NOT run its own `chronyd`. The Docker image's `/etc/chrony/chrony.conf` is unused (the container reads `clock_gettime(CLOCK_REALTIME)` which the host owns). The Helm chart's pod template does NOT mount a custom NTP config; the operator manages NTP on the node, not in the pod.

Kubernetes-specific note: the kubelet's `kubeReserved.time` is not a thing; clock sync is the node's responsibility. Node-feature-discovery (NFD) labels can surface "node has chrony running" for scheduling; the chart documentation in S3.5 walks the operator through this.

### Allowed skew envelope

| Host pair | Allowed skew | Rationale |
|---|---|---|
| Two SBproxy-controlled hosts (proxy ↔ ledger ↔ audit flusher ↔ confirmation worker) | ±2 minutes | Tight enough to keep HMAC nonce windows usable; loose enough to survive a slow chrony stepping event. |
| SBproxy ↔ third-party facilitator | ±5 minutes | Loose because facilitators are operated by third parties whose time-sync we do not control. |
| SBproxy ↔ Stripe (webhook ingest) | ±5 minutes | Matches Stripe's documented webhook `t=` tolerance. Reciprocal in both directions. |
| SBproxy ↔ customer webhook endpoint | ±5 minutes | Customer endpoints are out of our control; ±5 min is the conventional Stripe-style tolerance. |
| Hosts within an EKS cluster | ±100 ms (typical), ±2 min (hard limit) | Cloud-provider time service typically delivers sub-millisecond skew. ±2 min is the hard alarm threshold. |

The ±2 minute SBproxy-internal envelope is the load-bearing budget. HMAC nonce timestamps tolerate 60 s per A1.2; doubling that to 120 s gives one full 60 s NTP poll cycle of grace before the system goes red. The 60 s ledger-tolerance figure assumes the proxy and the ledger are both synced; if either is more than 60 s off, the request fails with `ledger.timestamp_skewed` which is observable but a hard fail for the affected request.

### Detection: `/readyz` field

Per R3.3, every host's `/readyz` endpoint includes a `clock_skew_seconds` field:

```json
{
  "status": "ok",
  "checks": {
    "ledger": "ok",
    "redis": "ok",
    "postgres": "ok",
    "clock_sync": {
      "status": "ok",
      "skew_seconds": 0.012,
      "ntp_source": "169.254.169.123",
      "last_synced": "2026-05-01T12:00:00.000Z",
      "stratum": 4
    }
  }
}
```

The `clock_skew_seconds` value comes from `chronyc tracking` (System time field) or, where unavailable, from a periodic outbound NTP probe (R3.3 ships an embedded SNTP client that hits the configured pool every 30 s).

Thresholds:

| Skew | `/readyz` check status | `/readyz` overall | Behaviour |
|---|---|---|---|
| < 1 second | `ok` | `ok` | Normal operation. |
| 1 s ≤ skew < 60 s | `degraded` | `ok` | Warning logged; metric incremented. Operations continue. |
| 60 s ≤ skew < 120 s | `degraded` | `ok` | Warning logged + `SBPROXY-CLOCK-SKEW` ticket alert. HMAC nonce window may already be rejecting some requests. |
| skew ≥ 120 s | `failed` | `failed` | `/readyz` returns 503; load balancer drains the host. Page on `SBPROXY-CLOCK-SKEW-CRITICAL`. |

The 120 s hard cutoff matches the SBproxy-internal envelope. A host that crosses it cannot reliably participate in HMAC-signed flows, and pulling it out of the load balancer is the correct response.

The ops dashboard (per A1.4) shows the worst-offender across all hosts as `sbproxy_clock_skew_worst_seconds` (gauge); ticket alert fires at 60 s, page fires at 120 s.

### Mitigations per mechanism

When skew is detected (any nonzero value), each clock-sensitive mechanism applies its own defence so a borderline-skewed host does not fail open or fail closed catastrophically.

#### JWS verification (quote tokens)

Per A3.2, JWS verification rejects tokens whose `iat` is more than `clock_skew_window` seconds in the future. The window is configurable per workspace (default 5 s; tightens to 0 in audit-paranoid mode). Tokens slightly in the past (`now > exp`) are normal; the proxy rejects expired tokens with the standard tolerance.

The asymmetry is deliberate: a token from the future is suspicious (it was signed by a clock we do not trust); a token from the past is just expired. Future-timestamp rejection prevents replay of tokens whose signer had a fast clock that has since corrected.

#### HMAC nonce timestamps (A1.2)

The ledger tolerance is 60 s by design. Per the SBproxy-internal envelope, ±2 min is permitted, so a worst-case combination of "proxy 1 min fast, ledger 1 min slow" produces a 2-min apparent skew at the ledger, which exceeds the tolerance. The mitigation: when the proxy detects its own skew is above 30 s, it adds a `X-Sb-Local-Skew-Seconds` header to ledger requests; the ledger uses this hint to widen the tolerance to 90 s for that call. The hint is advisory; a malicious proxy cannot use it to bypass replay protection because the nonce cache window remains 5 minutes regardless.

#### x402 confirmation windows (A3.3)

The reorg confirmation logic uses **chain time** (block timestamps as reported by the chain RPC), not wall-clock. The depth check is "current chain head block ≥ recorded tx block + confirmation_depth", which is clock-independent. The `chain_max_inclusion_seconds` and `pending_max_age_seconds` thresholds use wall-clock, but they are upper bounds (the worker decides "this tx is taking too long, fail it") rather than tight windows; ±2 min skew on these does not corrupt correctness, only the nominal timing.

This is by design: x402 reorg windows must be clock-independent because chains are public networks that we do not pace, and operator clocks vary. The depth check on block height is the defensible primitive.

#### MPP / Stripe webhook signatures (A1.9)

Stripe's `Stripe-Signature: t=<unix>,v1=<sig>` carries a Unix timestamp. The verifier rejects events whose `t=` is more than `tolerance` seconds in the past or future; default 5 min per A1.9. When the local clock is detected as skewed, the verifier widens the past-side tolerance proportionally (up to 10 min) but keeps the future-side at 5 min. The rationale: a future timestamp is suspicious (clock skew or replay); a past timestamp is more likely to be normal Stripe retry behaviour plus our own clock running fast.

If our skew exceeds 60 s, signed outbound webhooks (`Sbproxy-Signature: t=<unix>,...`) carry a clock-skew warning header (`Sbproxy-Sender-Skew-Seconds: <value>`) that lets customer-side verifiers widen their own tolerance gracefully. This is advisory; customers' verifiers may ignore it. The header lands in the same response as the signature so the customer's signature library (which already has access to all headers) can pick it up.

#### Audit batch boundaries (A2.3)

Audit batches use `started_at` / `ended_at` from the local clock. A flusher with a skewed clock writes batches whose timestamps are wrong but whose internal event ordering (by ULID `event_id`) is still consistent. Per A2.3 the verifier checks that every event's `ts` falls within `[started_at, ended_at]`; under skew, a few events near a flush boundary may fall just outside the window, which the verifier flags as a per-event check failure (exit code 2, not exit code 1) without invalidating the batch's signature.

The Wave 6 Merkle migration (per A2.3) reads batches in `(workspace_id, started_at)` order; under sustained skew the order is mostly correct but with possible reordering near boundaries. The migrator reads the events themselves (which are ULID-ordered, monotonic) and computes a deterministic chain irrespective of batch metadata. Skew does not corrupt the chain.

### Skew-induced failures we accept

Some failures cannot be mitigated locally; we accept them and document the operational response.

- **Facilitator with a fast clock produces settlement proofs we reject.** The facilitator's chain-time block timestamps may diverge from our clock; the depth check is clock-independent so this only matters for the facilitator's own response timestamp on the HTTP envelope. We do not reject facilitator responses on timestamp; we trust the on-chain receipt's `blockNumber`. Net effect: no rejection, no audit miss.
- **Customer endpoint with a slow clock rejects valid webhooks.** The customer's verifier may reject; their endpoint returns a 4xx; our deadletter queue accumulates. The runbook documents this scenario; the customer fixes their NTP and replays from the deadletter via the portal.
- **Stripe retries during our 60 s skew window.** Stripe's webhook retry logic is independent of our clock; if our verifier rejects on timestamp, Stripe retries up to 3 days. Our 60 s window catches transient skew; the underlying issue must be fixed before the 3-day retry budget exhausts.
- **Cross-region replication time differential.** A multi-region deployment has nominal sub-second skew between regions; the ±2 min SBproxy-internal envelope tolerates it. Cross-region active-active is out of scope per A3.4; single-region in Wave 3.

For each of these, the operator triages via the runbook (see below); the audit log captures the rejection so the customer-side reconciliation has a record.

### Operator runbook entry

Per S3.5 (`docs/time-sync.md`) and S3.6 (operator runbook update), the runbook ships with these entries:

**RB-CLOCK-SKEW-DETECT**

Check: `kubectl exec -it sbproxy-pod -- chronyc tracking` (returns System time field; should be < 1 s).

```
sbproxy-prod-1:~$ chronyc tracking
Reference ID    : 7F7F0101 (169.254.169.123)
Stratum         : 4
Ref time (UTC)  : Wed May 01 12:00:00 2026
System time     : 0.000123 seconds slow of NTP time
...
```

If System time is greater than 1 s, escalate to RB-CLOCK-SKEW-FIX.

**RB-CLOCK-SKEW-FIX**

1. Verify the host's NTP source: `chronyc sources -v`. Reachability column should show all sources reachable.
2. If sources are unreachable, the network egress to the NTP source is blocked. Check security-group / firewall rules for UDP 123 outbound.
3. If sources are reachable but skew persists, force a step: `sudo chronyc -a 'burst 4/4'` followed by `sudo chronyc -a makestep`. This may step the clock immediately (which may cause a brief monotonic violation in active processes; the SBproxy components handle this gracefully because all hot-path timing uses `Instant::now()` (monotonic) not `SystemTime::now()`).
4. If step does not resolve, the time source itself may be broken. Switch to a different source: edit `/etc/chrony/chrony.conf`, replace `pool` directive with a known-good vendor pool, restart chronyd: `sudo systemctl restart chronyd`.
5. If the host is unrecoverable (severely skewed RTC, NTP traffic blocked, no working source), drain it: `kubectl drain <node>`. Replace the instance.
6. After fixing, verify `/readyz` shows `clock_skew_seconds < 1` for at least 5 minutes before re-admitting traffic.

**RB-CLOCK-SKEW-RECOVER-REDEMPTIONS**

Some redemptions may have been rejected during the skew window. The audit log captures every rejection:

```
SELECT * FROM admin_audit_events
WHERE action = 'redemption_rejected_clock_skew'
  AND ts > '2026-05-01T11:00:00Z'
  AND tenant_id = 'ws_abc';
```

For each, the agent's client should retry; the proxy's idempotency-key flow per A3.4 deduplicates if the agent does retry within the 24 h ledger window. If the agent does not retry (silent client), the operator can issue a courtesy refund; the audit log captures the operator action.

**RB-CLOCK-SKEW-EMERGENCY-MANUAL-FIX**

For air-gapped or NTP-unreachable hosts, the operator can manually set the clock with `sudo sntp -sS <known-good-server>` (one-shot SNTP step) followed by `sudo hwclock -w` (write to RTC). This is a paged procedure; the audit log captures the operator's `sntp` command via the audit envelope per A1.7 (the auditor records the manual sync as a system event with `actor = AuditActor::Operator { ... }`).

### Configuration shape

```yaml
clock_sync:
  detection:
    interval_seconds: 30
    sntp_pool:                              # used only when chronyc unavailable
      - time.cloudflare.com
      - pool.ntp.org
  thresholds:
    warn_seconds:    1
    alert_seconds:   60
    critical_seconds: 120
  jws_window_seconds: 5                     # accepted future-iat slack
  hmac_self_skew_hint_threshold_seconds: 30
  webhook_outbound_skew_header: true
```

### Metrics

| Metric | Type | Labels |
|---|---|---|
| `sbproxy_clock_skew_seconds` | gauge | `host` (or none in single-host mode) |
| `sbproxy_clock_skew_worst_seconds` | gauge | (none) |
| `sbproxy_clock_skew_check_failures_total` | counter | `reason` (chrony_unavailable, sntp_timeout) |
| `sbproxy_jws_rejected_future_iat_total` | counter | `workspace_id` |
| `sbproxy_ledger_timestamp_skewed_total` | counter | (none, drawn from A1.2 error code) |
| `sbproxy_webhook_in_rejected_total{reason="timestamp_skew"}` | counter | (extends A1.9 metric) |

The `sbproxy_clock_skew_worst_seconds` gauge is the single dashboard panel that summarises clock-sync health across the fleet; ops sets a single ticket alert (60 s) and a single page (120 s) on it.

### What this ADR does NOT decide

- The operator's choice of NTP pool / PTP grandmaster. Operator-owned per environment.
- TAI / leap-second handling beyond `leapsectz right/UTC`. Wave 3 assumes UTC with smeared leap seconds (AWS / GCP standard); a future amendment may pin TAI for high-precision financial use cases.
- Cross-region wall-clock sync for active-active; single-region for Wave 3.
- Forensic timestamp recovery from access logs after a skew incident; the audit log captures rejections, but reconstructing a "true" timestamp for an affected event is out of scope.

## Consequences

- Every SBproxy component depends on a healthy NTP environment. The chart documentation makes this an explicit requirement, not a soft expectation.
- `/readyz` failures at ≥ 120 s skew let the load balancer drain the host automatically. Operators do not need to manually intervene before the host is removed from rotation.
- The 60 s ticket alert + 120 s page split gives ops a chance to fix transient skew without paging; only sustained or severe skew pages.
- Per-mechanism mitigations mean borderline-skewed hosts (1-60 s) keep working; only severely skewed hosts go red. This avoids the all-or-nothing failure mode where a tiny clock drift takes down the gateway.
- The chain-time-based reorg windows (per A3.3) keep x402 settlement clock-independent. Skew on the proxy or ledger does not corrupt reorg correctness.
- The audit log captures clock-skew-induced rejections, so operators can recover affected redemptions after fixing NTP. The recovery is via the standard idempotency-key retry path per A3.4.
- The outbound `Sbproxy-Sender-Skew-Seconds` header is a polite-citizen signal: when our clock is off, customer verifiers can choose to widen their tolerance gracefully. They are not obliged to.
- The ops surface is one gauge (`sbproxy_clock_skew_worst_seconds`) plus two alerts. Low operational overhead for a high-stakes invariant.

## Alternatives considered

**Require PTP (IEEE-1588) instead of NTP.** Considered. PTP gives sub-microsecond accuracy on hardware-supported NICs but requires datacentre-class network infrastructure (boundary clocks, transparent clocks) that cloud providers do not expose. NTP at ±100 ms typical is more than enough for a 60 s tolerance window, and it works everywhere. PTP remains an option for operators whose deployments have it; the configuration is the same shape (`chronyd` peers a PTP source).

**Embed an SNTP client in every component, ignore the host's NTP.** Rejected. A component-internal NTP client races the host's clock and produces inconsistent reads (`SystemTime::now()` is host-clock-bound regardless). The right shape is "host owns clock; component reads `SystemTime::now()` and trusts it; component reports skew via outbound SNTP probe as a sanity check, not as a corrective input".

**Tighten the SBproxy-internal envelope to ±30 s.** Considered. ±30 s would catch skew earlier but would also fail more aggressively on transient chrony stepping events. The 60 s alert + 120 s page envelope catches the same incidents with a less hair-trigger response. Operators who want tighter thresholds can override.

**Reject all timestamps and rely on monotonic ULIDs for ordering.** Rejected. Wall-clock timestamps are required by external protocols (Stripe webhook `t=`, JWS `iat`/`exp`, HMAC nonce) that the proxy cannot opt out of. Monotonic ULIDs handle internal ordering (per A2.3 audit batch event order) but not the external surfaces.

**Accept any skew, document that the operator must keep clocks in sync.** Rejected. This is the pre-Wave-3 status quo. The 14-minute staging skew incident proved that operators cannot be relied on to monitor clock sync without a platform-level signal. The `/readyz` field plus the ticket alert plus the page is the platform-level signal.

**Run our own NTP server.** Rejected. Operators want to use their own time source (compliance reasons, network egress reasons, vendor relationships). The right shape is "use what the operator has, surface skew if it goes wrong".

## References

- `adr-billing-hot-path-vs-async.md`: the layering rule; clock skew on the proxy hot path is a request-budget concern, on the async path is a worker-correctness concern.
- `adr-http-ledger-protocol.md` (A1.2): HMAC nonce timestamp window (60 s); the `X-Sb-Local-Skew-Seconds` hint header.
- `adr-webhook-security.md` (A1.9): Stripe-style `t=` timestamp; outbound `Sbproxy-Sender-Skew-Seconds` header.
- `adr-observability.md` (A1.4): `/readyz` shape; metrics surface.
- `adr-admin-action-audit.md` (A1.7): the audit envelope that captures rejections and operator manual fixes.
- `adr-audit-log-v0.md` (A2.3): batch boundaries under skew; per-event ts check at verify time.
- `adr-slo-alert-taxonomy.md` (A1.6): the `SBPROXY-CLOCK-SKEW` and `SBPROXY-CLOCK-SKEW-CRITICAL` alert names.
- `adr-evm-reorg-resistance.md` (A3.3): chain-time-based reorg windows; clock-independent depth check.
- `adr-end-to-end-idempotency.md` (A3.4): the 24 h / 30-day TTLs that recover affected redemptions after a skew incident.
- `docs/AIGOVERNANCE-BUILD.md` § 6.1 (A3.5), § 6.2 (R3.3 clock-skew detection), § 6.4 (S3.5 time-sync docs, S3.6 runbook), § 6.5 (Q3.14 clock-skew regression).
- `docs/AIGOVERNANCE.md` § 9 (decisions log), § 10 (architectural rules).
- chronyd configuration reference: <https://chrony-project.org/documentation.html>.
- Amazon Time Sync Service: <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/set-time.html>.
- Stripe webhook signing reference: <https://docs.stripe.com/webhooks/signatures>.
- IEEE 1588 (PTP): considered for a future amendment.
