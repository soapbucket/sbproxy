# ADR: eBPF L7 acceleration, spike + go/no-go (WOR-815)
*Last modified: 2026-05-31*

Status: accepted. Recommendation: defer eBPF acceleration past v1.x; ship the userspace fast paths first, revisit when an operator cohort needs the kernel wins badly enough to justify the elevated-privilege footprint. The narrow win for early L3/4 drop on known-bad IPs is the first slice if the decision flips, behind an explicit `linux-ebpf` cargo feature.

## Context

SBproxy's L7 load balancing runs entirely in the Pingora userspace event loop. The XLB paper [arXiv:2602.09473](https://arxiv.org/abs/2602.09473) shows that pushing connection steering into the kernel via eBPF (XDP, sk_lookup, sockmap, classifier programs) can cut p99 latency and CPU on the hot path, at the cost of elevated privileges and a Linux-only deployment surface. The research lane sweep flagged this as an explore-grade opportunity SBproxy could lead on, since the directly comparable rivals (agentgateway, Bifrost, Helicone) all run pure-userspace today.

This ADR captures the spike: where eBPF would actually help SBproxy, what the trade-offs are, and a go/no-go for shipping the prototype.

## eBPF acceleration surfaces, ranked

The Linux kernel offers four entry points relevant to an L7 reverse proxy. Each one helps a different slice of the pipeline.

### 1. XDP / TC ingress: early L3/4 drop (best ROI)

Where it helps: the gateway's first three hops on a known-bad client packet are NIC -> driver -> userspace -> WAF, then WAF rejects. The packet is allocated, parsed, copied, and scheduled before the userspace verdict fires. An XDP program attached to the NIC's RX path can drop packets matching the existing DDoS bounded-LRU + persistent-block store (WOR-811) before the kernel even allocates an skb, which is the cheapest possible drop.

Cost: a synchronization channel between the userspace block store and an eBPF map (LPM trie for CIDRs, hash map for /32s and /128s). Updates happen on every persistent-block insert / TTL expiry. Map size has to be bounded so the kernel never refuses an update; the bounded-LRU in WOR-811 already enforces 50k-100k entries, so the eBPF map mirror is naturally sized.

Quantified win: the SourceForge / Cilium XDP-DROP benchmarks place a small-map XDP drop at <300 ns per packet on x86_64; the equivalent userspace drop pays at least one skb allocation (~600 ns) plus the Pingora dispatch frame (~1-2 us). Expected p99 improvement on a known-bad-flood: 5-15x for the dropped subset, with no impact on legitimate traffic.

### 2. sk_lookup: consistent-hash upstream steering

Where it helps: each new connection picks an upstream via the configured LB strategy (P2C, peak-EWMA, prefix-affinity). On a hot LLM origin (WOR-797 / WOR-798), the per-connection upstream-pick budget is in the low tens of microseconds and is consistently called from a single ring-buffer goroutine. An sk_lookup program can make the upstream choice in kernel space before the userspace accept(), eliminating the userspace accept-then-balance round-trip. This is the XLB paper's core insight.

Cost: the LB strategies currently consume runtime state (token-usage counters for least_token_usage, EWMA for peak_ewma, hash-window for prefix-affinity). Either the eBPF program runs a stripped-down hash-only variant and falls back to userspace for the stateful strategies, or the runtime state lives in shared eBPF maps that userspace updates after every dispatch. The latter is the XLB design and adds a synchronization cost on every request.

Quantified win: XLB reports 25 to 40 percent throughput improvement on connection-bound workloads; latency reduction is smaller because the userspace dispatch path is already short. The win mostly lands on burst arrival patterns.

### 3. sockmap: zero-copy upstream forwarding

Where it helps: once the upstream socket is established, sockmap can splice the downstream and upstream sockets so payload bytes never enter userspace for the duration of the connection. For pure pass-through proxying this is most of the per-connection CPU. SBproxy already pays a lot of per-request transformation cost (WAF, modifiers, observability, billing), so the sockmap win shrinks: only requests that fall through every transform and observability hook benefit.

Quantified win: 30 to 50 percent CPU reduction on the pass-through slice, but the slice is a small fraction of SBproxy's mixed workload. Hard to justify on its own.

### 4. Classifier programs: pre-WAF substring scan

Where it helps: SBproxy's WAF runs ModSecurity-compatible rules with OWASP CRS in userspace. A subset of the regex set (literal substrings, exact paths) can be lifted into an eBPF classifier on the ingress path so a 99-percentile clean request never pays the regex cost on the body. The same approach is what Cloudflare uses for the Workers DDoS filter.

Cost: the eBPF program is verifier-bound; OWASP CRS rules need to be hand-translated into a fixed-size automaton that fits the verifier's 1M instruction budget. Maintenance is heavy.

Quantified win: 5 to 15 percent CPU reduction on the WAF hot path, lower if `valid_tokens` carve-outs already short-circuit most legitimate traffic.

## Privilege and portability trade-offs

The eBPF wins above land on three constraints that contradict SBproxy's "single binary, no required deps" promise.

1. **Elevated privileges.** Loading an eBPF program requires `CAP_BPF` plus `CAP_NET_ADMIN` (XDP) or `CAP_SYS_ADMIN` (sockmap on older kernels). The default `sbproxy` Docker image runs as a non-root user. Either the container drops to the standard non-root + capability set (operator opt-in, breaks the "drop privileges by default" UX) or the kernel-acceleration path is silently disabled when capabilities are missing. The latter is the only acceptable shape; it adds a runtime-feature-detect surface but preserves the default UX.

2. **Linux-only.** The Pingora userspace path runs unchanged on Linux, macOS (dev / CI), and FreeBSD (some operators). eBPF is Linux-only. The feature has to be strictly additive: every code path that the eBPF surface accelerates must keep its userspace fallback, and the macOS / FreeBSD builds compile without the eBPF crates. That means a `#[cfg(target_os = "linux")]` gate around every entry point plus a graceful "eBPF unavailable" log on startup for non-Linux hosts.

3. **Kernel-version drift.** The eBPF verifier and helper surface change kernel-by-kernel. sk_lookup is Linux 5.9+; certain BTF features are 5.13+; LSM hooks are 5.7+. SBproxy's stated minimum is "any reasonably current Linux"; pinning a minimum kernel version on the eBPF feature is acceptable, but the bar moves once a year as old LTS distros drop out.

4. **Loader tooling.** A modern eBPF program compiles via `clang -target bpf` and ships either as a separate `.o` (BPF CO-RE) or embedded via the `aya` crate. `aya` is the only mature Rust-native option; it does not need a C toolchain at build time but does pull in a non-trivial dependency tree. The single-binary promise survives, but the build matrix grows.

## Spike summary: why defer

Putting the four surfaces against the three constraints:

| Surface | Win | Operator surface cost | Verdict |
|---|---|---|---|
| XDP / TC drop for known-bad IPs | 5-15x on the dropped subset | One sync channel + cap-detect | First slice if go |
| sk_lookup upstream steering | 25-40% on connection-bound workloads | Big LB-state surface change | Only with funded design partner |
| sockmap zero-copy forwarding | 30-50% on pass-through, small slice | Skips every transform / metric / billing path | No |
| Classifier WAF pre-scan | 5-15% on WAF hot path | OWASP CRS hand-translation per rule | No |

The XDP early-drop surface is the only one that pays for itself without a substantial design partnership and without compromising the observability + billing promises SBproxy makes on every other path. Even there, the win lands on a narrow workload (sustained known-bad-IP traffic) where the userspace bounded-LRU is already pretty cheap.

Concretely, SBproxy has a stack of unshipped userspace wins that are bigger and cheaper than any eBPF slice:

* Pingora's own connection-pool and TLS-session-cache settings are not fully tuned for the LLM workload.
* The semantic cache OSS slice (WOR-796) shifted a lot of CPU to embeddings; further cost savings ride on the embedding-batching path, not the kernel.
* The agent-budget + cost-quality routing (WOR-797) shapes token spend, not CPU.

Recommendation: defer the eBPF feature past v1.x. Revisit when (a) a design partner is willing to fund the elevated-privilege Linux-only deployment surface, or (b) the userspace XDP-equivalent (the persistent-block path) becomes the documented p99 hot spot in an actual operator workload.

## Go-decision plan (deferred)

If the decision flips, the first slice ships behind a `linux-ebpf` cargo feature, gated to Linux 5.13+ (current LTS coverage), and limited to early L3/4 drop. Concrete moves:

1. `crates/sbproxy-ebpf` (new): houses the `aya` loader, the LPM-trie + hash maps, and the runtime sync to `sbproxy-modules::policy::ddos`'s bounded-LRU.
2. Cap-detection on startup: probe `CAP_BPF` + `CAP_NET_ADMIN`; on miss, log once and fall back to userspace silently.
3. Two-tier map: `/32` and `/128` hash map for exact matches, LPM trie for CIDR ranges. The DDoS bounded-LRU is the source of truth; the eBPF maps are a derived projection updated on insert / TTL expiry.
4. Benchmark gate: a `cargo bench` in `benches/ebpf_drop.rs` that compares the userspace vs eBPF drop path on a 100k-RPS synthetic flood; ship only if the p99 win is >=3x on the dropped subset.
5. CI: the eBPF feature compiles only on Linux runners and skips on macOS/FreeBSD; the non-eBPF default build is the gated CI surface so the feature is strictly additive.

The remaining three surfaces (sk_lookup, sockmap, WAF pre-scan) stay on the backlog without their own ADRs until the early-drop slice ships and the operator response is measured.

## Open questions

* What is the actual p99 hot spot in a live SBproxy deployment? The XLB paper assumes connection-bound workloads; SBproxy's hot mix today is mostly request-bound (AI dispatch, semantic-cache lookup). Without a production p99 trace, the eBPF wins are paper wins.
* Does the kubernetes-operator deployment story tolerate the cap-set drift? K8s pods routinely drop everything; restoring `CAP_BPF` + `CAP_NET_ADMIN` is a `securityContext` change that ops teams may push back on.

## See also

* WOR-815 (this ticket).
* WOR-811 (WAF persistent block + OWASP CRS) - the upstream of the XDP early-drop surface.
* WOR-797 / WOR-798 (cost / quality routing, peak-EWMA LB) - the sk_lookup surface would have to mirror this state into kernel maps.
* WOR-496 (agentgateway + Bifrost benchmark tracker) - confirms no rival has shipped this yet; the OSS-leadership window is open if SBproxy decides to take it.
* XLB paper: [arXiv:2602.09473](https://arxiv.org/abs/2602.09473).
* `aya` Rust eBPF loader: [https://github.com/aya-rs/aya](https://github.com/aya-rs/aya).
