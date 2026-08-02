# Engine strategy tripwires: quarterly review

Ticket: WOR-1860 (Backlog, Priority 3, due 2026-10-05). This is the first
review; the ticket calls for one every quarter. Review date: 2026-07-27.

The standing verdict is leverage-first: no first-party forward pass, lean
on mistral.rs (embedded engine), vLLM, SGLang, and llama.cpp as managed
subprocess/uv/container engines. That answer is conditional on the
surrounding ecosystem, so each tripwire below is checked against primary
sources rather than assumed still true.

## Tripwire 1: mistral.rs bus-factor / release-gap

**Status: has NOT fired, but the release-gap condition it names is
present and has widened, not narrowed, since the ticket was filed.**

Checked crates.io directly: the `mistralrs` crate's published version
history stops at 0.8.1 (2026-04-02); no newer release has been published
to crates.io. Checked GitHub releases for `EricLBuehler/mistral.rs`: the
project has kept shipping on GitHub through the same window -- v0.8.20
(06-21), v0.8.21 (06-22), v0.8.22 (06-22), v0.8.23 (06-25), and v0.9.0
(07-07) -- meaning at least five point releases plus a minor version bump
never reached crates.io. sbproxy's own `Cargo.toml` already pins the
embedded-engine dependency to the v0.9.0 git tag rather than a crates.io
version, with a comment explaining exactly this gap. That workaround is
fine as a stopgap but is itself evidence the tripwire condition is real:
sbproxy is already depending on a git tag instead of a published crate
because of it.

This is not yet "PRs stop landing" or "Eric Buehler steps back" (found no
evidence of either; the release cadence above is actually a sign of an
actively maintained project, just one whose release *packaging* discipline
does not include crates.io). Recommend downgrading the response from "pin
harder, fork, or fund" to just "pin harder" (continue tracking git tags,
not crates.io) for now, and re-escalate only if a future review finds the
git-tag cadence itself has slowed, which would combine both signals.

## Tripwire 2: CubeCL/burn-lm flash-attention + GGUF quant parity

**Status: has not fired.**

`tracel-ai/burn-lm` exists and is an active, named project ("democratizing
large model inference and training on any device," built on the Burn
framework and CubeCL, the same team's GPU-kernel-in-Rust compute
language). Tracel raised a $3M seed round (announced August 2025) to fund
this work, which is a funding-durability signal worth noting. This review
found no published benchmark or release note claiming flash-attention
parity with hand-tuned CUDA kernels plus GGUF quantized execution on a
stable (non-nightly) toolchain; both halves of the named condition remain
open. Re-check next quarter; burn-lm is young enough that this could move
quickly.

## Tripwire 3: NVIDIA cuda-oxide stabilization

**Status: has not fired, and per NVIDIA's own stated timeline is not
expected to fire for 1-2 more years.**

cuda-oxide (`NVlabs/cuda-oxide`) reached v0.2 in June 2026 (37 PRs from 23
contributors since the initial May 2026 drop), which is real momentum. It
remains pinned to a specific nightly Rust toolchain
(`nightly-2026-04-03`), requires `rustc-dev`/`rust-src` components, and is
explicitly alpha with expected API breakage. Coverage found no update to
the B300 BF16 benchmark figure already cited in the ticket
(1,833 TFLOPS geomean) or to its Linux-only constraint. Typical
alpha-to-production timelines put this at beta in 2027 and
production-viable in 2027-2028, per third-party analysis; nothing found
this review contradicts that. No action; re-check next quarter for a
stable-Rust-toolchain milestone specifically, since that is the concrete
signal that would change the calculus (today it competes with nvcc/PTX
tooling on capability, not yet on toolchain risk).

## Tripwire 4: a serving wedge subprocess engines cannot cover

**Status: has not fired.** No edge/CPU single-binary story emerged this
review that vLLM (GPU), SGLang (GPU), or llama.cpp (CPU/Metal/CUDA
subprocess) cannot already serve through sbproxy's existing managed-engine
drivers. The embedded mistral.rs engine already covers the
single-binary/zero-external-process case for the models it supports. No
action.

## Standing checks

- **vLLM lane stays safetensors-only:** still true. GGUF support in vLLM
  remains an out-of-tree plugin per the RFC referenced in the ticket
  (#39583); sbproxy's vLLM driver does not route GGUF to it, and llama.cpp
  remains the GGUF path. No drift found.
- **llama-server router mode vs. sbproxy's own supervisor:** out of scope
  for this pass (needs a direct read of llama.cpp's current router-mode
  docs against `runtime_manager.rs`'s placement/rollout logic, which is a
  larger comparison than this quarterly check budget covers). Carry
  forward to the next review as a named action item rather than letting it
  silently drop.

## Summary for next review

No tripwire has fired; the leverage-first verdict stands. The one item
trending toward its threshold is mistral.rs's crates.io lag, which has
neither improved nor triggered the harder responses (fork/fund) -- next
review should explicitly re-check whether the git-tag-pinning workaround
is still sufficient or whether the gap has started affecting sbproxy
directly (a needed mistral.rs fix landing on GitHub but not reachable
without bumping the pinned tag and re-validating). Next review due by
2026-10-05 per the ticket's cadence, or sooner if a tripwire's evidence
changes materially.
