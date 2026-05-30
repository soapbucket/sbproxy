//! RFC 9530 `Content-Digest` request-body verification (WOR-805).
//!
//! Verifies an inbound `Content-Digest:` (or, since PR2, the
//! `Repr-Digest:`) header against the SHA-256 or SHA-512 of the
//! request body before forwarding to upstream. On mismatch, malformed
//! header, or unsupported algorithm, the proxy rejects with a
//! configurable HTTP status (default 400). Optional pass-through when
//! the header is absent: `on_missing: skip` is for origins that mix
//! integrity-required and integrity-optional traffic;
//! `on_missing: require` (the default) is the safer posture for
//! integrity-critical inboxes (webhook receivers, agent endpoints).
//!
//! The check itself runs in `request_body_filter` once the body is
//! fully buffered (the policy is paired with a `ContentDigestEnforcer`
//! that sets `ctx.validate_request_body = true`). The parser /
//! verifier surface comes from [`sbproxy_middleware::digest`], which
//! has been in tree for the egress-signer work and is tested against
//! the RFC 9530 §2 canonical vector. This policy is the body-filter
//! glue that turns those primitives into a per-origin reject path.
//!
//! ## PR2 additions (WOR-805 follow-ups)
//!
//! * `Repr-Digest` parallel handling. Per RFC 9530 §2 the two headers
//!   carry the same digest semantics over slightly different
//!   representations; for inbound traffic where we do not decode
//!   `Content-Encoding`, they are interchangeable. The policy
//!   honours either header (`Content-Digest` checked first; falls
//!   back to `Repr-Digest`).
//! * `ctx.content_digest_verified` flag set on the `Verified` outcome
//!   so downstream phases (HTTP Message Signatures audit, billing
//!   surfaces) can attest that the body matches the signed digest
//!   component without re-hashing the body themselves.
//!
//! ## Still deferred
//!
//! * RFC 9530 §6.4 trailer-section digests. Pingora 0.8's
//!   `ProxyHttp` trait does not expose an `request_trailer_filter`
//!   hook, only `response_trailer_filter`; reading inbound request
//!   trailers requires either upgrading Pingora or extending its
//!   API. Documented limitation; clients that send the digest in
//!   the trailer section currently get treated as if the header is
//!   absent (so `on_missing: require` rejects them, which is the
//!   safer default).

use serde::Deserialize;

use sbproxy_middleware::digest::{parse_content_digest, Algorithm};

/// What the policy does when the request has no `Content-Digest`
/// header at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnMissing {
    /// Reject with `missing_status` (default). The safer posture for
    /// integrity-critical surfaces: a request without a digest cannot
    /// be verified, so we refuse it.
    #[default]
    Require,
    /// Allow the request through. Opt-in for origins that mix
    /// integrity-required and integrity-optional traffic; the
    /// operator promises the absence of a digest is acceptable.
    Skip,
}

/// Verify the inbound `Content-Digest` header against the request
/// body. See module-level docs for the rationale and references.
pub struct ContentDigestPolicy {
    /// Algorithms accepted in the header. Defaults to the two active
    /// entries in the RFC 9530 IANA registry (`sha-256`, `sha-512`).
    /// Entries outside this set are treated as `UnsupportedAlgorithm`
    /// even if the underlying parser knows them; this lets an
    /// operator narrow the accepted set (e.g. `[sha-256]` to refuse
    /// `sha-512` for cost reasons).
    pub algorithms: Vec<Algorithm>,
    /// What to do when the request has no `Content-Digest` header.
    pub on_missing: OnMissing,
    /// HTTP status returned on mismatch, malformed header, or
    /// unsupported algorithm.
    pub status: u16,
    /// HTTP status returned when the header is absent and
    /// `on_missing == Require`. Defaults to `status` if unset.
    pub missing_status: u16,
    /// Optional response body to send on rejection. When unset, the
    /// proxy returns a small JSON `{error, detail}` envelope.
    pub error_body: Option<String>,
    /// `Content-Type` for the rejection body. Defaults to
    /// `application/json`.
    pub error_content_type: String,
    /// Cap on body bytes the policy will buffer for verification.
    /// Above this, the body filter rejects with 413 rather than
    /// accumulating unboundedly. Defaults to 10 MiB.
    pub max_body_bytes: usize,
}

impl std::fmt::Debug for ContentDigestPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContentDigestPolicy")
            .field("algorithms", &self.algorithms)
            .field("on_missing", &self.on_missing)
            .field("status", &self.status)
            .field("max_body_bytes", &self.max_body_bytes)
            .finish()
    }
}

/// Outcome of running [`ContentDigestPolicy::verify`] against a
/// request body. Maps onto the body filter's reject branches.
#[derive(Debug, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// Header present, algorithm in the accepted set, digest matches.
    /// The body filter forwards the request unchanged.
    Verified,
    /// Header absent and `on_missing == Skip`. Pass through.
    Skipped,
    /// Header absent and `on_missing == Require`. Reject with
    /// `missing_status`.
    MissingRequired,
    /// Header present but the parser could not decode it (malformed
    /// structured-fields dictionary, missing colon-wrapping, etc.).
    /// Reject with `status`.
    Malformed,
    /// Header present, but no entry used an algorithm in the
    /// configured `algorithms` set. Reject with `status`.
    UnsupportedAlgorithm,
    /// Header present and parseable, but the decoded digest does not
    /// match the body. Reject with `status`. The body is intact; the
    /// rejection itself is what matters.
    Mismatch,
}

impl ContentDigestPolicy {
    /// Build from a generic JSON config value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        #[derive(Deserialize)]
        struct Raw {
            #[serde(default)]
            algorithms: Option<Vec<String>>,
            #[serde(default)]
            on_missing: OnMissing,
            #[serde(default = "default_status")]
            status: u16,
            #[serde(default)]
            missing_status: Option<u16>,
            #[serde(default)]
            error_body: Option<String>,
            #[serde(default = "default_error_content_type")]
            error_content_type: String,
            #[serde(default = "default_max_body_bytes")]
            max_body_bytes: usize,
        }
        fn default_status() -> u16 {
            400
        }
        fn default_error_content_type() -> String {
            "application/json".to_string()
        }
        fn default_max_body_bytes() -> usize {
            10 * 1024 * 1024
        }

        let raw: Raw = serde_json::from_value(value)
            .map_err(|e| anyhow::anyhow!("invalid content_digest policy config: {e}"))?;

        // Resolve the algorithms list: explicit None or empty list
        // means "accept the active registry set".
        let algorithms = match raw.algorithms {
            None => vec![Algorithm::Sha256, Algorithm::Sha512],
            Some(list) if list.is_empty() => vec![Algorithm::Sha256, Algorithm::Sha512],
            Some(list) => list
                .iter()
                .map(|token| {
                    Algorithm::parse(token).ok_or_else(|| {
                        anyhow::anyhow!(
                            "content_digest.algorithms: unknown / deprecated algorithm '{token}'; \
                             accepted values are 'sha-256' and 'sha-512' (the RFC 9530 active set)"
                        )
                    })
                })
                .collect::<Result<Vec<_>, _>>()?,
        };
        if raw.max_body_bytes == 0 {
            anyhow::bail!("content_digest.max_body_bytes must be > 0");
        }
        let missing_status = raw.missing_status.unwrap_or(raw.status);
        Ok(Self {
            algorithms,
            on_missing: raw.on_missing,
            status: raw.status,
            missing_status,
            error_body: raw.error_body,
            error_content_type: raw.error_content_type,
            max_body_bytes: raw.max_body_bytes,
        })
    }

    /// Run the verification against an in-hand request body.
    ///
    /// `header_value` is the raw inbound `Content-Digest` header
    /// (`None` when absent); `body` is the buffered request body.
    pub fn verify(&self, header_value: Option<&str>, body: &[u8]) -> VerifyOutcome {
        let header = match header_value {
            Some(h) => h,
            None => {
                return match self.on_missing {
                    OnMissing::Require => VerifyOutcome::MissingRequired,
                    OnMissing::Skip => VerifyOutcome::Skipped,
                };
            }
        };
        let entries = match parse_content_digest(header) {
            Ok(e) => e,
            Err(_) => return VerifyOutcome::Malformed,
        };
        // Find the first entry whose algorithm is in our accepted
        // set, then verify the body against its digest. If no entry
        // uses an accepted algorithm, treat as unsupported.
        let accepted = entries
            .iter()
            .find(|(alg, _)| self.algorithms.contains(alg));
        let (alg, expected) = match accepted {
            Some(pair) => pair,
            None => return VerifyOutcome::UnsupportedAlgorithm,
        };
        let actual = compute_alg(*alg, body);
        if constant_time_eq(&actual, expected) {
            VerifyOutcome::Verified
        } else {
            VerifyOutcome::Mismatch
        }
    }

    /// Build the rejection envelope `(status, body, content_type)`
    /// for the given outcome. Matches the shape `validator_failed`
    /// expects on `RequestContext`.
    pub fn rejection_envelope(&self, outcome: VerifyOutcome) -> Option<(u16, String, String)> {
        let (status, detail) = match outcome {
            VerifyOutcome::Verified | VerifyOutcome::Skipped => return None,
            VerifyOutcome::MissingRequired => (
                self.missing_status,
                "Content-Digest header required but absent",
            ),
            VerifyOutcome::Malformed => (
                self.status,
                "Content-Digest header is malformed per RFC 9530 structured-fields syntax",
            ),
            VerifyOutcome::UnsupportedAlgorithm => (
                self.status,
                "Content-Digest header uses an algorithm not in the configured accept set",
            ),
            VerifyOutcome::Mismatch => (
                self.status,
                "Content-Digest value does not match the request body",
            ),
        };
        let body = self.error_body.clone().unwrap_or_else(|| {
            serde_json::json!({
                "error": "content_digest verification failed",
                "detail": detail,
            })
            .to_string()
        });
        Some((status, body, self.error_content_type.clone()))
    }
}

fn compute_alg(alg: Algorithm, body: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256, Sha512};
    match alg {
        Algorithm::Sha256 => Sha256::digest(body).to_vec(),
        Algorithm::Sha512 => Sha512::digest(body).to_vec(),
    }
}

/// Constant-time equality so a timing side channel does not leak
/// digest bytes. The digest values are public integrity tags, so
/// technically this is belt-and-suspenders, but the cost is zero and
/// the existing egress signer uses the same pattern.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy_default() -> ContentDigestPolicy {
        ContentDigestPolicy::from_config(serde_json::json!({})).expect("default")
    }

    #[test]
    fn from_config_defaults_match_documented() {
        let p = policy_default();
        assert_eq!(p.algorithms, vec![Algorithm::Sha256, Algorithm::Sha512]);
        assert_eq!(p.on_missing, OnMissing::Require);
        assert_eq!(p.status, 400);
        assert_eq!(p.missing_status, 400);
        assert_eq!(p.max_body_bytes, 10 * 1024 * 1024);
        assert_eq!(p.error_content_type, "application/json");
    }

    #[test]
    fn from_config_rejects_unknown_algorithm() {
        let err = ContentDigestPolicy::from_config(serde_json::json!({
            "algorithms": ["md5"]
        }))
        .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("md5"),
            "error must name the offender; got: {msg}"
        );
        assert!(
            msg.contains("sha-256") && msg.contains("sha-512"),
            "error should list accepted values; got: {msg}"
        );
    }

    #[test]
    fn from_config_zero_max_body_bytes_is_rejected() {
        let err = ContentDigestPolicy::from_config(serde_json::json!({ "max_body_bytes": 0 }))
            .unwrap_err();
        assert!(format!("{err}").contains("max_body_bytes"));
    }

    #[test]
    fn verify_rfc_9530_canonical_vector_passes() {
        // RFC 9530 §2 canonical vector:
        //   body = {"hello": "world"}
        //   sha-256 digest = X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=
        // Same vector pinned in sbproxy-middleware's digest tests; we
        // re-use it here to lock the body-filter glue against the same
        // standard.
        let p = policy_default();
        let body = b"{\"hello\": \"world\"}";
        let header = "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:";
        assert_eq!(p.verify(Some(header), body), VerifyOutcome::Verified);
    }

    #[test]
    fn verify_tampered_body_yields_mismatch() {
        let p = policy_default();
        let header = "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:";
        // Same header, different body.
        let tampered = b"{\"hello\": \"WORLD\"}";
        assert_eq!(p.verify(Some(header), tampered), VerifyOutcome::Mismatch);
    }

    #[test]
    fn verify_malformed_header_yields_malformed() {
        let p = policy_default();
        // No colon-wrapping; not a structured-fields byte sequence.
        assert_eq!(
            p.verify(Some("sha-256=garbage"), b"hi"),
            VerifyOutcome::Malformed
        );
    }

    #[test]
    fn verify_unsupported_algorithm_when_narrowed() {
        // Operator-narrowed accept list excludes sha-512; the header
        // only carries sha-512, so the policy must refuse rather than
        // silently accept a different algorithm or fall through.
        let p = ContentDigestPolicy::from_config(serde_json::json!({
            "algorithms": ["sha-256"]
        }))
        .unwrap();
        // sha-512 of "hi" is well-known; the value below is the
        // base64 of SHA-512("hi"), but the exact value does not
        // matter for this assertion -- only that the algorithm is
        // out of the accept set.
        let header = "sha-512=:LGmRGZKEFhmYAyk6+yt8aJ/E2K9X9IbXLwGyu0F4rW/uxw0X7d4ekJzL6w7/p9KFugXyPzCEMQ8oW6ne7DPMlA==:";
        assert_eq!(
            p.verify(Some(header), b"hi"),
            VerifyOutcome::UnsupportedAlgorithm
        );
    }

    #[test]
    fn verify_missing_header_require_returns_missing_required() {
        let p = policy_default();
        assert_eq!(p.verify(None, b"hi"), VerifyOutcome::MissingRequired);
    }

    #[test]
    fn verify_missing_header_skip_returns_skipped() {
        let p =
            ContentDigestPolicy::from_config(serde_json::json!({ "on_missing": "skip" })).unwrap();
        assert_eq!(p.verify(None, b"hi"), VerifyOutcome::Skipped);
    }

    #[test]
    fn verify_repr_digest_with_same_value_passes() {
        // WOR-805 PR2: the policy itself is header-agnostic — it
        // takes a header value and a body. The body-filter wire site
        // looks up `Content-Digest` first, then `Repr-Digest`, so a
        // request that only carries the latter is verified through
        // the same code path. This test pins the policy half of the
        // contract: identical body + identical digest value passes
        // regardless of which header carried it.
        let p = policy_default();
        let body = b"{\"hello\": \"world\"}";
        let header = "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:";
        assert_eq!(p.verify(Some(header), body), VerifyOutcome::Verified);
    }

    #[test]
    fn rejection_envelope_shapes() {
        let p = policy_default();
        // Verified / Skipped have no envelope (the body filter
        // forwards the request unchanged).
        assert!(p.rejection_envelope(VerifyOutcome::Verified).is_none());
        assert!(p.rejection_envelope(VerifyOutcome::Skipped).is_none());
        // Each rejection outcome maps to a JSON envelope tagged with
        // a stable detail string and the configured content type.
        for outcome in [
            VerifyOutcome::MissingRequired,
            VerifyOutcome::Malformed,
            VerifyOutcome::UnsupportedAlgorithm,
            VerifyOutcome::Mismatch,
        ] {
            let (status, body, ct) = p.rejection_envelope(outcome).expect("envelope");
            assert!(status >= 400);
            assert_eq!(ct, "application/json");
            assert!(body.contains("content_digest verification failed"));
        }
    }
}
