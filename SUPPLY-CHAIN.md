# SBproxy Supply Chain

*Last modified: 2026-08-08*

The long-form companion to `SECURITY.md`, intended for security teams, procurement reviewers, and anyone whose job is to answer the question "can we trust this binary?"

The short answer is: yes, and here is exactly how to verify it without trusting us.

---

## What this document covers

1. What we sign, what we publish, and where
2. How to verify a release end to end (binaries, images, SBOM, provenance)
3. How to verify in air-gapped or offline environments
4. How dependencies are managed and updated
5. How our own build pipeline is hardened
6. What we promise about reproducibility today and what is on the roadmap
7. Incident response

If you are looking for the disclosure policy or supported version table, see `SECURITY.md`.

---

## 1. What we sign

Every git tag matching `v*.*.*` triggers the release workflow defined at `.github/workflows/release.yml`. The workflow builds natively on GitHub-hosted runners (Ubuntu x86\_64, Ubuntu arm64, and macOS arm64; no cross-compilation), produces signed artifacts, and publishes them to:

| Artifact | Location |
|---|---|
| Binaries (tarballs) | GitHub Releases on `soapbucket/sbproxy` |
| Cosign signature bundles | Same GitHub Release, alongside each tarball |
| Container images | `docker.io/soapbucket/sbproxy` and `ghcr.io/soapbucket/sbproxy` (same digest; cosign-signed on both) |
| CycloneDX SBOM | GitHub Release asset (`sbom.cyclonedx.json`) and cosign attestation on the image |
| SLSA build provenance | GitHub native attestation (visible via `gh attestation` and the API) |

The signing identity is **keyless** (Sigstore via GitHub OIDC). There are no private keys for SBproxy maintainers to manage or lose, and no scenario in which a leaked maintainer credential alone produces a valid release signature. Every signing event is recorded in the public Sigstore Rekor transparency log at https://rekor.sigstore.dev/.

The expected cert identity for any official release tag `vX.Y.Z` is:

```
https://github.com/soapbucket/sbproxy/.github/workflows/release.yml@refs/tags/vX.Y.Z
```

The OIDC issuer is always:

```
https://token.actions.githubusercontent.com
```

If a signature presents any other identity or issuer, **it is not an official SBproxy release**, regardless of where you downloaded the artifact from.

---

## 2. End-to-end verification

This is the procedure to verify a release before running the binary in production. It assumes you have the [cosign](https://docs.sigstore.dev/cosign/installation/) CLI, the [GitHub CLI](https://cli.github.com/), and [syft](https://github.com/anchore/syft) installed.

```bash
VERSION=1.5.0
PLATFORM=linux_amd64                  # or linux_arm64, darwin_arm64
TAG="v${VERSION}"
BASE="https://github.com/soapbucket/sbproxy/releases/download/${TAG}"
IDENTITY="https://github.com/soapbucket/sbproxy/.github/workflows/release.yml@refs/tags/${TAG}"
ISSUER="https://token.actions.githubusercontent.com"
```

### 2.1 Binary signature

```bash
curl -fsSL -o sbproxy.tar.gz        "${BASE}/sbproxy_${PLATFORM}.tar.gz"
curl -fsSL -o sbproxy.tar.gz.bundle "${BASE}/sbproxy_${PLATFORM}.tar.gz.cosign.bundle"

cosign verify-blob \
  --bundle sbproxy.tar.gz.bundle \
  --certificate-identity "${IDENTITY}" \
  --certificate-oidc-issuer "${ISSUER}" \
  sbproxy.tar.gz
```

A successful verification prints `Verified OK`. The `.cosign.bundle` file contains the certificate, the signature, and the Rekor inclusion proof so that this verification works **without internet egress** to Sigstore (see section 3).

### 2.2 Container image signature

```bash
cosign verify docker.io/soapbucket/sbproxy:${VERSION} \
  --certificate-identity "${IDENTITY}" \
  --certificate-oidc-issuer "${ISSUER}"
```

This pulls the image manifest, fetches the cosign signature stored in the OCI registry alongside the image, and verifies the certificate chain back to the Sigstore root and the Rekor transparency log entry.

For multi-platform manifests, the verification covers each platform-specific image.

Container images are published for `v1.2.0` and later; earlier tags shipped binaries only. The same image is also pushed to `ghcr.io/soapbucket/sbproxy` at the same digest.

### 2.3 SBOM

The SBOM ships in two forms. Pick whichever fits your tooling.

**As a release asset:**

```bash
curl -fsSL -o sbom.cyclonedx.json "${BASE}/sbom.cyclonedx.json"
jq '.metadata.component.name, .metadata.component.version, (.components | length)' sbom.cyclonedx.json
```

**As a cosign attestation on the image:**

```bash
cosign verify-attestation \
  --type cyclonedx \
  --certificate-identity "${IDENTITY}" \
  --certificate-oidc-issuer "${ISSUER}" \
  docker.io/soapbucket/sbproxy:${VERSION} \
  | jq -r '.payload' | base64 -d | jq '.predicate.metadata.component, (.predicate.components | length)'
```

The SBOM is in CycloneDX JSON format. It enumerates every Rust crate (with version and license), every binary dependency, and the source tree state at build time. Use it to feed your dependency-tracking system (Dependency-Track, GUAC, in-house) or to grep for a specific CVE-affected package.

### 2.4 SLSA build provenance

```bash
gh attestation verify sbproxy.tar.gz --repo soapbucket/sbproxy
```

This proves that the artifact was produced by a specific workflow run on a specific commit, on a GitHub-hosted runner, with the inputs and environment recorded in the in-toto attestation. The attestation is also visible via the GitHub Attestations API, which is keyed by the artifact's SHA-256 digest:

```bash
gh api "/repos/soapbucket/sbproxy/attestations/sha256:$(shasum -a 256 sbproxy.tar.gz | awk '{print $1}')"
```

A successful provenance verification means the artifact came out of the `release.yml` workflow run associated with the tag. Combined with the signature (section 2.1), it means: the artifact was built by our workflow, and the workflow signed it. Both must be true for trust to hold.

### 2.5 Smoke-test the binary

After cryptographic verification, run the binary itself:

```bash
tar xzf sbproxy.tar.gz
./sbproxy --version
./sbproxy --config /path/to/your/sb.yml --check
```

`--check` validates the configuration without binding to ports. Use it in CI to catch config regressions before deploy.

---

## 3. Air-gapped and offline verification

The cosign signature bundle and the SLSA attestation include enough material to verify entirely offline, **provided you have done a one-time bootstrap** to obtain the Sigstore trust roots.

### 3.1 One-time bootstrap (online)

On a machine with internet egress, fetch the Sigstore root trust bundle and ship it to your air-gapped environment:

```bash
cosign initialize \
  --mirror https://tuf-repo-cdn.sigstore.dev \
  --root https://tuf-repo-cdn.sigstore.dev/root.json
# The trust material is now under ~/.sigstore/. Snapshot and ship.
tar czf sigstore-trust.tar.gz -C ~ .sigstore
```

Refresh the bootstrap every six months or when Sigstore rotates roots (announced at https://blog.sigstore.dev/).

### 3.2 Offline verification

In the air-gapped environment, restore the trust bundle and run the same verification commands:

```bash
tar xzf sigstore-trust.tar.gz -C ~

# Use the local Sigstore mirror for offline verify
export TUF_ROOT="${HOME}/.sigstore"

cosign verify-blob \
  --bundle sbproxy.tar.gz.bundle \
  --certificate-identity "https://github.com/soapbucket/sbproxy/.github/workflows/release.yml@refs/tags/v1.5.0" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --offline \
  sbproxy.tar.gz
```

The `--offline` flag tells cosign to use the Rekor inclusion proof embedded in the bundle rather than calling out to the Rekor API. This works because the proof is part of the bundle.

For SLSA provenance, `gh attestation verify` normally calls the GitHub API. If the verifying machine cannot reach api.github.com, fetch the attestation bundle and the Sigstore trusted root on a connected machine:

```bash
gh attestation download sbproxy.tar.gz --repo soapbucket/sbproxy
# Writes sha256:<digest>.jsonl, named after the artifact digest
gh attestation trusted-root > trusted-root.jsonl
```

Then verify on the air-gapped machine entirely from local files:

```bash
gh attestation verify sbproxy.tar.gz \
  --repo soapbucket/sbproxy \
  --bundle "sha256:<digest>.jsonl" \
  --custom-trusted-root trusted-root.jsonl
```

With `--bundle` and `--custom-trusted-root` supplied, `gh` performs no network calls; the bundle carries the certificate, signature, and Rekor inclusion proof, and the trusted root anchors the chain.

---

## 4. Dependency management

The SBOM tells you what is in any given release. This section tells you how dependencies got there.

### 4.1 What we depend on

The Rust gateway depends on a vetted set of crates. The Cargo.lock file is committed and updated via dependency-update PRs reviewed by maintainers. The full graph is enumerated in every published SBOM. Notable categories:

- HTTP runtime: `tokio`, `hyper`, `pingora`
- TLS: `rustls`
- Cryptography: `ring`, `sha2`, `ed25519-dalek`, `aws-lc-rs`
- Serialization: `serde`, `serde_yaml`, `serde_json`
- Tracing and metrics: `tracing`, `prometheus`
- Scripting bridges: `mlua`, `rquickjs` (sandboxed)
- ML/embedding sidecars: handled in a separate process with their own dependency surface

There are **no Python or Node runtime dependencies** in the gateway hot path. The Lua and JavaScript scripting modules execute user-provided code in sandboxes; they do not pull external module ecosystems at runtime.

The admin dashboard is the one npm surface, and it is a build-time input rather than a runtime one. `ui/` is a Vue and Vite single-page app with its own `package-lock.json`. It compiles to static assets that the `embed-admin-ui` cargo feature bakes into the release binary, so no Node process runs in production, but npm packages do contribute bytes to a shipped artifact. Section 4.3 covers how that lockfile gets scanned.

### 4.2 Update policy

- **Patch and minor security updates** to direct dependencies are automated via Renovate (configured in `.github/renovate.json`), reviewed and merged by maintainers within 7 business days, and shipped in the next patch release.
- **Major version bumps** to direct dependencies are done deliberately, with manual review, and are not auto-applied.
- **Transitive dependencies** are pinned via `Cargo.lock`. They update only when a direct dependency's `Cargo.toml` declares it.
- **Renovate's own configuration** is reviewed in PR like any other change. SHA-pinning of GitHub Actions is enforced via `helpers:pinGitHubActionDigests`.

### 4.3 Vendor and audit posture

- We do not vendor dependencies into the repo (no `vendor/` directory) because it obscures provenance. The SBOM and Cargo.lock are the canonical record.
- We do not consume crates from non-`crates.io` sources without explicit reviewer approval.

#### What is scanned, by ecosystem

Two ecosystems ship in the release binary, so two scanners run. Both live in the `supply chain` job in `.github/workflows/ci.yml`, and that job is deliberately unconditional: it carries no path filter, so it re-evaluates the whole dependency surface on every pull request and every push to `main`. An advisory published against a dependency nobody touched still turns the next run red.

| Ecosystem | Manifest | Scanner | Database | Fails the build on |
|---|---|---|---|---|
| Rust crates | root `Cargo.lock` | `cargo deny check --all-features`, configured by `deny.toml` | RustSec advisory database | any advisory at any severity, any unmaintained crate anywhere in the graph, any license outside the allowlist, any source outside the allowlist |
| npm | `ui/package-lock.json` | `npm audit --package-lock-only` | GitHub advisory database | high and critical only |

The npm step runs lockfile-only, with no `npm ci` and no `node_modules`. Because `npm ci` installs exactly what the lockfile pins, auditing the lockfile and auditing the installed tree are the same audit.

#### Thresholds, and why they differ

The Rust gate has no severity floor. Every RustSec advisory fails, including `unmaintained` findings that are not vulnerabilities at all, and including advisories against build-time proc macros. That bar is affordable because the crate graph is one we curate directly and the finding rate is low.

The npm gate is set to `high`, meaning high and critical fail while moderate and below only print. The dashboard's lockfile is 112 development dependencies against 27 production ones, nearly all of it build tooling, and a tree shaped like that carries a steady background of moderate advisories in packages that never reach a browser. Gating on moderate would make the lane a recurring chore, and a gate that gets routed around is worth less than a narrower one that gets respected.

The threshold raises the bar; it does not narrow the scope. The audit still covers the development tree, because a compromised bundler or test runner is a real path into a shipped artifact.

#### Ignore policy

There is no blanket suppression and no severity-based exemption. A finding either fails the build or is ignored by advisory ID with a written justification. Every entry in the `deny.toml` `[advisories] ignore` list carries four things:

1. The advisory ID.
2. The full transitive path, naming the direct dependency that pulls the crate in.
3. Why it does not apply, which is either a reachability argument about our code or a statement that no patched version resolves against our graph, with the specific conflict named.
4. The condition that removes the entry, usually an upstream release we are waiting on.

Entries are deleted once `cargo-deny` reports that no crate matches the advisory criteria, which is how we find out an upstream fixed something. Three entries were removed that way in August 2026.

#### Known coverage limits

Three gaps, stated here rather than left for a reviewer to discover.

**GitHub's advisory database is a superset of RustSec.** It ingests every RustSec advisory and also carries GitHub-reviewed Rust advisories that were never assigned a RUSTSEC ID. `cargo-deny` reads RustSec only, so those are structurally invisible to it, and an `ignore` entry naming an ID the database does not contain would match nothing. Advisories in that category are triaged as comments alongside the ignore list in `deny.toml`, with the same four elements required of a real entry. Dependabot is what surfaces them.

**Lockfiles outside the root workspace are not gated.** The repository carries several: the benchmark harnesses under `sbproxy-bench/harness/`, the synthetic bench, and a test fixture. Each is its own cargo workspace, and `cargo deny check` at the repository root reads the root workspace only. That scaffolding is built by no release job and ships in no artifact, so it is deliberately out of scope for a merge-blocking gate. Dependabot still raises alerts against those files, which is why the open alert count runs higher than the number of distinct advisories behind it. `scripts/check-nested-lockfiles.sh` keeps them resolvable; it does not scan them.

**Advisory drift on an idle repository is caught by Dependabot, not by CI.** CI evaluates on push and pull request. Dependabot scans the default branch continuously and is the earlier signal when no one is committing.

---

## 5. Build pipeline hardening

The release workflow itself is part of the supply chain. The following invariants are enforced:

- **Third-party GitHub Actions use explicit reviewed versions.** The workflow currently uses major-version tags such as `actions/checkout@v5`; updates are visible in review.
- **Job-level minimum permissions.** The binary release job has `contents: write`, `id-token: write`, and `attestations: write`. The separate image job also has `packages: write`. Other jobs inherit `contents: read` unless they declare a narrower publish need. No job uses `permissions: write-all`.
- **Hosted runners only.** SLSA Level 3 requires this. Self-hosted runners are not used for release jobs.
- **Publish secrets are scoped to the steps that need them.** Release and registry credentials are not set as workflow-wide environment variables.
- **No interactive prompts in CI.** Every command is non-interactive; every flag is explicit.
- **Branch protection on `main`.** Force-push and deletion are disabled. Changes require PR review and a passing CI run before merge.
- **Tag protection on `v*` tags.** Only specific roles can create release tags.
- **Provenance includes the workflow file SHA.** A change to `release.yml` is visible in the next release's attestation.

The full release workflow is at `.github/workflows/release.yml`. Read it. The point of the supply-chain story is that the pipeline itself is auditable.

---

## 6. Reproducible builds

We make a graded set of claims here. We are honest about which are stronger.

### 6.1 What we guarantee today

- **Fixed toolchain channel** via `dtolnay/rust-toolchain` (`stable`) in CI, with the minimum supported version declared in `Cargo.toml` (`rust-version`). Two builders on the same channel build against the same compiler release. An exact, workspace-wide version pin is not committed today; see 6.2.
- **Pinned dependency graph** via committed `Cargo.lock` and the `--locked` flag. Two builders see the same crate versions and the same transitive resolution.
- **Pinned action versions** via SHA. Two builders see the same workflow logic.
- **`-Cstrip=symbols`** to remove debug symbols and reduce sources of nondeterminism in the binary.

This means: if you build from the same source, with the same toolchain, on a similar host, you should produce a binary whose SBOM matches ours and whose dependency graph matches ours exactly. The SBOM is the practical reproducibility artifact for most buyer audits.

### 6.2 What we do not yet guarantee

- **Bit-for-bit identical binaries** across builders. Achieving this requires removing every source of nondeterminism (timestamp embeds, file ordering, codegen unit nondeterminism). It is a multi-week project. We have not done it yet. The `reproducible build probe` workflow now builds the release binary twice on independent GitHub-hosted runners and uploads the SHA-256 comparison report as an artifact, but the probe is informational until the diff reaches zero.
- **An exact pinned toolchain version** across every lane. We build on a fixed `stable` channel and declare an MSRV, but do not commit a `rust-toolchain.toml` pinning one version, because the fuzzing lane runs on nightly. Converging every lane onto a single pinned toolchain is part of the bit-for-bit work above.

If your security policy requires bit-for-bit reproducibility today, talk to us. We will work with you on a bridge: independent rebuild from a tagged source, SBOM and dependency-graph comparison, and a written attestation that the dependency surface matches.

---

## 7. Incident response

The supply-chain story exists because incidents happen. Here is how we respond.

### 7.1 If a release is compromised

**Definition:** a published release that contains code we did not intend, or that was signed under circumstances that violated the pipeline's invariants (secret leak, action compromise, runner takeover).

**Our actions, in order:**

1. **Issue a public security advisory** on GitHub at https://github.com/soapbucket/sbproxy/security/advisories within 24 hours of confirmation.
2. **Yank the affected version from package indices** (Homebrew, Docker `:latest`, Cargo if applicable). Existing pulls of the affected artifact remain available because deletion makes forensics harder; the advisory directs users to the safe replacement.
3. **Cut a fixed release** with a higher patch number. We do not re-tag a known-compromised version.
4. **Publish a post-mortem** within 7 days of the advisory, naming the root cause and the changes to the pipeline. This includes an updated entry in `SUPPLY-CHAIN.md` itself if the threat model gained a new scenario.
5. **Notify affected customers directly** via the support contact on file.

We do **not** silently rebuild and re-push under the same version. Every signing event is in the Rekor transparency log; pretending it didn't happen is impossible and dishonest.

### 7.2 If a maintainer is compromised

A compromised maintainer credential, on its own, cannot produce a valid release signature. The signing identity is the workflow path on a tagged commit, signed by a GitHub-issued OIDC token, which the compromised maintainer cannot forge from their laptop.

A compromised maintainer with sufficient repo permissions could push a malicious commit and tag it. Detections:

- Branch protection requires PR review on `main`. A solo malicious commit cannot land without review.
- Tag protection restricts who can create release tags.
- Every release workflow run is visible publicly. Anomalous runs (off-hours, unexpected commit ranges, unusual durations) are flagged in our internal monitoring and in the public Actions tab.
- Buyers verifying signatures see the cert identity, which includes the tag and the commit SHA. A surprise tag from a known maintainer is observable.

If you suspect maintainer compromise, file a security report. We will coordinate.

### 7.3 If Sigstore or GitHub itself is compromised

This is a category of risk we cannot fully mitigate but can constrain:

- The Rekor transparency log has multiple monitors, including the open-source Sigstore community and several auditing services. A backdated or forged log entry would be detected.
- GitHub OIDC tokens are short-lived and bound to the workflow run. A long-running compromise of the GitHub OIDC issuer would invalidate the entire ecosystem, not just SBproxy; it is a public infrastructure incident.

---

## 8. Public auditability

Anyone, including parties we have never spoken to, can verify the following without any cooperation from us:

- The release artifact's signature (Rekor public log)
- The image's signature (Rekor public log)
- The SBOM (CycloneDX, downloadable)
- The build provenance (GitHub native attestation API, public)
- The workflow file that produced the release (`.github/workflows/release.yml` at the tagged commit)
- The dependency graph (`Cargo.lock` at the tagged commit)
- The diff between any two releases (git history, public)

This is the point. The supply chain is verifiable end to end without our cooperation, because cooperation is exactly the link in the chain we are removing.

---

## 9. Reporting and contact

- **Security issues:** security@soapbucket.com
  - PGP public key: https://sbproxy.dev/.well-known/pgp-key.txt
  - Primary fingerprint: `4C28 5392 FE49 C61D 94F1  02B6 6EFA 300A 32BF E26C`
  - Encryption subkey:   `140E DCF4 2C2B E3EF CA79  2D44 A76A 9BE3 914E 08C5`
  - Issued 2026-05-04, expires 2028-05-03. Cross-reference at https://sbproxy.dev/security.
- **Supply-chain questions or audit support:** security@soapbucket.com, subject line "Supply chain audit"
- **Public advisories:** https://github.com/soapbucket/sbproxy/security/advisories
- **Sigstore Rekor lookups:** https://rekor.sigstore.dev/
- **GitHub attestation API:** `gh api /repos/soapbucket/sbproxy/attestations/sha256:<artifact-digest>`
