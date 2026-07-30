//! Extraction of a minted virtual key from inbound request headers.
//!
//! Pure and synchronous: this decides *which* header carries a token and what
//! that token is, and does no store I/O. Resolution against the key plane
//! happens in the caller. Kept out of `request_phase.rs` so the ordering,
//! scheme-stripping, and ambiguity rules are testable without a `Session`.
//!
//! The header a key arrives in belongs to the calling tool, not to the key: an
//! Anthropic SDK sends `x-api-key`, Azure sends `api-key`, and an internal tool
//! sends whatever its author picked. Sweeping a configured list is what lets a
//! minted key be presented by a tool nobody is going to rewrite.

use sbproxy_config::types::{KeyInboundConfig, NativeKeyPolicyConfig};

/// Values scanned per header name before the rest are ignored.
///
/// A request may legally repeat a header. Bounding the scan keeps a
/// pathological request carrying thousands of `authorization` lines from
/// turning the sweep into a denial of service.
pub const MAX_VALUES_PER_HEADER: usize = 8;

/// What the sweep found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SweepOutcome {
    /// No candidate header carried a well-shaped token. The caller falls
    /// through to the origin's configured auth provider.
    None,
    /// Exactly one distinct token was present.
    Found {
        /// Lowercase name of the header it came from. The caller strips this
        /// header before the request goes upstream, so the proxy's own key
        /// never reaches an origin.
        header: String,
        /// The token, scheme prefix already removed.
        token: String,
    },
    /// Two candidate headers carried different well-shaped tokens. The caller
    /// denies rather than letting configuration order silently pick one.
    Ambiguous,
}

/// One non-empty credential presented through a configured inbound carrier.
///
/// The value borrows the request header so callers can resolve overlapping
/// legacy/configured/native credential shapes without copying secret material
/// into another long-lived structure.
pub struct PresentedCredential<'a> {
    /// Lowercase configured header name.
    pub header: String,
    /// Scheme-stripped credential value.
    pub value: &'a str,
}

/// Return every non-empty credential on the configured inbound carriers.
///
/// Unlike [`sweep_headers`], this does not filter by minted-token shape. AI
/// dispatch uses it only after the canonical minted sweep has returned
/// `NotPresent`, to resolve legacy stored and exact configured credentials
/// before falling back to provider-native admission.
pub fn presented_credentials<'a>(
    headers: &'a http::HeaderMap,
    cfg: &KeyInboundConfig,
) -> Vec<PresentedCredential<'a>> {
    let mut presented = Vec::new();
    for entry in &cfg.headers {
        let lower = entry.name.trim().to_ascii_lowercase();
        let Ok(name) = http::header::HeaderName::from_bytes(lower.as_bytes()) else {
            continue;
        };
        for raw in headers.get_all(&name).iter().take(MAX_VALUES_PER_HEADER) {
            let Ok(value) = raw.to_str() else {
                continue;
            };
            let value = value.trim();
            let candidate = if entry.scheme.is_empty() {
                value
            } else {
                match strip_scheme(value, &entry.scheme) {
                    Some(rest) => rest,
                    None => continue,
                }
            };
            if !candidate.is_empty() {
                presented.push(PresentedCredential {
                    header: lower.clone(),
                    value: candidate,
                });
            }
        }
    }
    presented
}

/// Sweep `headers` for a minted token, in the order `cfg.headers` lists.
///
/// The first well-shaped token wins. Scanning continues across the remaining
/// configured headers only to detect a conflicting second token; an identical
/// repeat is not a conflict, because clients commonly set both `authorization`
/// and a vendor header defensively.
pub fn sweep_headers(headers: &http::HeaderMap, cfg: &KeyInboundConfig) -> SweepOutcome {
    let mut found: Option<(String, String)> = None;

    for entry in &cfg.headers {
        let lower = entry.name.trim().to_ascii_lowercase();
        let Ok(name) = http::header::HeaderName::from_bytes(lower.as_bytes()) else {
            // Rejected at config load; skip rather than panic on a hand-built
            // config in a test.
            continue;
        };
        for raw in headers.get_all(&name).iter().take(MAX_VALUES_PER_HEADER) {
            let Ok(value) = raw.to_str() else {
                // Not UTF-8, so it cannot be one of our ASCII tokens.
                continue;
            };
            let value = value.trim();
            let candidate = if entry.scheme.is_empty() {
                value
            } else {
                match strip_scheme(value, &entry.scheme) {
                    Some(rest) => rest,
                    None => continue,
                }
            };
            if sbproxy_keystore::crypto::parse_minted_token(candidate).is_none() {
                continue;
            }
            match &found {
                None => found = Some((lower.clone(), candidate.to_string())),
                // The same token in two headers is one intent, not a conflict.
                Some((_, existing)) if existing == candidate => {}
                Some(_) => return SweepOutcome::Ambiguous,
            }
        }
    }

    match found {
        Some((header, token)) => SweepOutcome::Found { header, token },
        None => SweepOutcome::None,
    }
}

/// Whether a request that produced [`SweepOutcome::None`] must be refused.
///
/// Off by default, so turning the sweep on changes nothing for an existing
/// route: a request with no minted key falls through to whatever auth the
/// origin already configured. Enabling it makes the proxy the only door on an
/// origin that has no other auth provider, where the default would otherwise
/// admit unauthenticated traffic.
pub fn requires_minted_key(cfg: &KeyInboundConfig) -> bool {
    cfg.require
}

/// Attribute a native (non-minted) inbound credential to a provider.
///
/// Runs only when [`sweep_headers`] found no minted key, so it can never
/// shadow the governed path. First matching rule wins, mirroring the sweep's
/// ordering semantics. Returns `None` for a request whose credentials match
/// no rule, and the caller admits it unattributed: refusing here would break
/// the pass-through this attribution exists to observe.
pub fn resolve_provider_hint(
    headers: &http::HeaderMap,
    hints: &[sbproxy_config::types::ProviderHintConfig],
) -> Option<String> {
    matching_provider_credential(headers, hints, None).map(|(provider, _)| provider)
}

/// Return the caller-owned credential for one already-authorized provider.
///
/// The returned value borrows the request header and omits the configured
/// authentication scheme. Callers should keep it request-local and must never
/// log or serialize it.
pub fn resolve_native_provider_credential<'a>(
    headers: &'a http::HeaderMap,
    hints: &[sbproxy_config::types::ProviderHintConfig],
    provider: &str,
) -> Option<&'a str> {
    matching_provider_credential(headers, hints, Some(provider)).map(|(_, credential)| credential)
}

fn matching_provider_credential<'a>(
    headers: &'a http::HeaderMap,
    hints: &[sbproxy_config::types::ProviderHintConfig],
    expected_provider: Option<&str>,
) -> Option<(String, &'a str)> {
    for hint in hints {
        if expected_provider.is_some_and(|expected| !hint.provider.eq_ignore_ascii_case(expected)) {
            continue;
        }
        let lower = hint.header.trim().to_ascii_lowercase();
        let Ok(name) = http::header::HeaderName::from_bytes(lower.as_bytes()) else {
            // Rejected at config load; skip a hand-built bad rule.
            continue;
        };
        if let Some(also) = hint.also_header.as_deref() {
            let also_lower = also.trim().to_ascii_lowercase();
            let Ok(also_name) = http::header::HeaderName::from_bytes(also_lower.as_bytes()) else {
                continue;
            };
            if !headers.contains_key(&also_name) {
                continue;
            }
        }
        for raw in headers.get_all(&name).iter().take(MAX_VALUES_PER_HEADER) {
            let Ok(value) = raw.to_str() else {
                continue;
            };
            let value = value.trim();
            let candidate = if hint.scheme.is_empty() {
                value
            } else {
                match strip_scheme(value, &hint.scheme) {
                    Some(rest) => rest,
                    None => continue,
                }
            };
            if candidate.is_empty() {
                continue;
            }
            // A minted key is never a native credential, whatever rule it
            // would otherwise satisfy.
            if sbproxy_keystore::crypto::parse_minted_token(candidate).is_some() {
                continue;
            }
            if candidate.starts_with(&hint.value_prefix) {
                return Some((hint.provider.clone(), candidate));
            }
        }
    }
    None
}

/// Admission result for a caller-owned native provider key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeKeyPolicyDecision {
    /// No configured provider hint recognized a native credential.
    NotPresent,
    /// The credential's provider is explicitly admitted.
    Allowed {
        /// Canonical provider label resolved by the matching hint.
        provider: String,
    },
    /// A provider was recognized but no operator policy was available.
    PolicyMissing {
        /// Canonical provider label resolved by the matching hint.
        provider: String,
    },
    /// The operator policy does not admit the recognized provider.
    ProviderDenied {
        /// Canonical provider label resolved by the matching hint.
        provider: String,
    },
}

/// Resolve and authorize a caller-owned native provider key.
///
/// A minted token is excluded by [`resolve_provider_hint`] and therefore
/// always remains on the higher-precedence governed path. Recognized native
/// credentials require an explicit policy; absence is a closed failure rather
/// than permission to spend an operator credential.
pub fn resolve_native_key_policy(
    headers: &http::HeaderMap,
    cfg: &KeyInboundConfig,
) -> NativeKeyPolicyDecision {
    let Some(provider) = resolve_provider_hint(headers, &cfg.provider_hints) else {
        return NativeKeyPolicyDecision::NotPresent;
    };
    match cfg.native_key_policy.as_ref() {
        Some(policy) if policy.allows(&provider) => NativeKeyPolicyDecision::Allowed { provider },
        Some(_) => NativeKeyPolicyDecision::ProviderDenied { provider },
        None => NativeKeyPolicyDecision::PolicyMissing { provider },
    }
}

/// Lower the operator's native-key defaults into the same secret-free record
/// shape used by minted-key governance.
///
/// The stable id is scoped to tenant, origin, and provider. It is safe for
/// metrics and quota buckets because it contains only operator-controlled
/// labels, never any part of the caller-owned credential.
pub fn native_policy_record(
    policy: &NativeKeyPolicyConfig,
    tenant_id: &str,
    origin: &str,
    provider: &str,
) -> sbproxy_keystore::record::KeyRecord {
    let now = chrono::Utc::now();
    let key_id = format!(
        "native:{}:{}:{}",
        tenant_id.trim(),
        origin.trim().to_ascii_lowercase(),
        provider.trim().to_ascii_lowercase()
    );
    let mut record = sbproxy_keystore::record::KeyRecord::new(key_id, "", now);
    record.name = Some(format!("native:{}", provider.trim().to_ascii_lowercase()));
    record.max_requests_per_minute = policy.max_requests_per_minute;
    record.max_tokens_per_minute = policy.max_tokens_per_minute;
    if policy.max_budget_tokens.is_some() || policy.max_budget_usd.is_some() {
        record.budget = Some(sbproxy_keystore::record::RecordBudget {
            max_tokens: policy.max_budget_tokens,
            max_cost_usd: policy.max_budget_usd,
        });
    }
    record.allowed_models.clone_from(&policy.allowed_models);
    record.blocked_models.clone_from(&policy.blocked_models);
    record
        .require_pii_redaction
        .clone_from(&policy.require_pii_redaction);
    record.tenant_id = Some(tenant_id.to_string());
    record.source = sbproxy_keystore::record::RecordSource::Config;
    record
}

/// Strip `scheme` from the front of `value`, case-insensitively, returning the
/// remainder trimmed.
///
/// `None` when the value does not carry the scheme, which is how `Basic ...`
/// is skipped on a `Bearer`-configured header.
fn strip_scheme<'a>(value: &'a str, scheme: &str) -> Option<&'a str> {
    let head = value.get(..scheme.len())?;
    if head.eq_ignore_ascii_case(scheme) {
        Some(value[scheme.len()..].trim_start())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbproxy_config::types::{InboundHeaderConfig, KeyInboundConfig, NativeKeyPolicyConfig};

    fn token() -> String {
        format!("sbp_{}_{}", "0".repeat(16), "a".repeat(64))
    }

    fn other_token() -> String {
        format!("sbp_{}_{}", "1".repeat(16), "b".repeat(64))
    }

    fn cfg() -> KeyInboundConfig {
        KeyInboundConfig::default()
    }

    fn headers(pairs: &[(&str, &str)]) -> http::HeaderMap {
        let mut map = http::HeaderMap::new();
        for (k, v) in pairs {
            map.append(
                http::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                http::HeaderValue::from_str(v).unwrap(),
            );
        }
        map
    }

    #[test]
    fn finds_a_token_in_a_raw_value_header() {
        let h = headers(&[("x-api-key", &token())]);
        match sweep_headers(&h, &cfg()) {
            SweepOutcome::Found { header, token: t } => {
                assert_eq!(header, "x-api-key");
                assert_eq!(t, token());
            }
            other => panic!("expected Found, got {other:?}"),
        }
    }

    #[test]
    fn strips_the_scheme_case_insensitively() {
        for prefix in ["Bearer ", "bearer ", "BEARER "] {
            let h = headers(&[("authorization", &format!("{prefix}{}", token()))]);
            assert!(
                matches!(sweep_headers(&h, &cfg()), SweepOutcome::Found { .. }),
                "{prefix:?} must be stripped"
            );
        }
    }

    #[test]
    fn presents_non_minted_credentials_from_every_configured_carrier() {
        let mut cfg = cfg();
        cfg.headers = vec![
            InboundHeaderConfig {
                name: "Authorization".to_string(),
                scheme: "Bearer ".to_string(),
            },
            InboundHeaderConfig {
                name: "X-Api-Key".to_string(),
                scheme: String::new(),
            },
            InboundHeaderConfig {
                name: "X-Custom-Key".to_string(),
                scheme: "Token ".to_string(),
            },
        ];
        let headers = headers(&[
            ("authorization", "Bearer configured-auth"),
            ("x-api-key", "configured-api"),
            ("x-custom-key", "tOkEn configured-custom"),
        ]);

        let presented = presented_credentials(&headers, &cfg);
        let values: Vec<_> = presented
            .iter()
            .map(|credential| (credential.header.as_str(), credential.value))
            .collect();
        assert_eq!(
            values,
            [
                ("authorization", "configured-auth"),
                ("x-api-key", "configured-api"),
                ("x-custom-key", "configured-custom"),
            ]
        );
    }

    #[test]
    fn ignores_a_mismatched_scheme() {
        let h = headers(&[("authorization", &format!("Basic {}", token()))]);
        assert_eq!(sweep_headers(&h, &cfg()), SweepOutcome::None);
    }

    #[test]
    fn scans_every_value_of_a_repeated_header() {
        let h = headers(&[("x-api-key", "not-a-token"), ("x-api-key", &token())]);
        assert!(matches!(
            sweep_headers(&h, &cfg()),
            SweepOutcome::Found { .. }
        ));
    }

    #[test]
    fn caps_the_values_scanned_per_header() {
        let mut pairs: Vec<(&str, &str)> = vec![("x-api-key", "filler"); MAX_VALUES_PER_HEADER];
        let t = token();
        pairs.push(("x-api-key", t.as_str()));
        let h = headers(&pairs);
        assert_eq!(
            sweep_headers(&h, &cfg()),
            SweepOutcome::None,
            "a token past the cap is not scanned"
        );
    }

    #[test]
    fn two_different_tokens_are_ambiguous() {
        let h = headers(&[("x-api-key", &token()), ("x-sb-api", &other_token())]);
        assert_eq!(sweep_headers(&h, &cfg()), SweepOutcome::Ambiguous);
    }

    #[test]
    fn the_same_token_in_two_headers_resolves() {
        let h = headers(&[("x-api-key", &token()), ("x-sb-api", &token())]);
        assert!(matches!(
            sweep_headers(&h, &cfg()),
            SweepOutcome::Found { .. }
        ));
    }

    #[test]
    fn trims_padding_and_ignores_empty_values() {
        let padded = headers(&[("x-api-key", &format!("  {}  ", token()))]);
        assert!(matches!(
            sweep_headers(&padded, &cfg()),
            SweepOutcome::Found { .. }
        ));
        assert_eq!(
            sweep_headers(&headers(&[("x-api-key", "   ")]), &cfg()),
            SweepOutcome::None
        );
    }

    #[test]
    fn a_provider_key_is_not_a_candidate() {
        // The whole point of the sbp_ prefix: sweeping x-api-key must not
        // mistake a caller's real Anthropic key for one of ours.
        let h = headers(&[("x-api-key", "sk-ant-api03-abcdefghijklmnopqrstuvwxyz")]);
        assert_eq!(sweep_headers(&h, &cfg()), SweepOutcome::None);
    }

    #[test]
    fn an_empty_header_list_disables_the_sweep() {
        let h = headers(&[("x-api-key", &token())]);
        let off = KeyInboundConfig {
            headers: vec![],
            require: false,
            provider_hints: Vec::new(),
            native_key_policy: None,
        };
        assert_eq!(sweep_headers(&h, &off), SweepOutcome::None);
    }

    #[test]
    fn sweep_order_follows_configuration_not_arrival() {
        let t = token();
        let h = headers(&[("x-sb-api", &t), ("x-api-key", &t)]);
        let ordered = KeyInboundConfig {
            headers: vec![
                InboundHeaderConfig {
                    name: "x-sb-api".into(),
                    scheme: String::new(),
                },
                InboundHeaderConfig {
                    name: "x-api-key".into(),
                    scheme: String::new(),
                },
            ],
            require: false,
            provider_hints: Vec::new(),
            native_key_policy: None,
        };
        match sweep_headers(&h, &ordered) {
            SweepOutcome::Found { header, .. } => assert_eq!(header, "x-sb-api"),
            other => panic!("expected Found, got {other:?}"),
        }
    }

    #[test]
    fn a_short_value_does_not_panic_on_the_scheme_slice() {
        // `strip_scheme` slices by the scheme's byte length; a value shorter
        // than that, or one whose boundary is mid-codepoint, must return None.
        let h = headers(&[("authorization", "Be"), ("x-api-key", "é")]);
        assert_eq!(sweep_headers(&h, &cfg()), SweepOutcome::None);
    }
    #[test]
    fn anthropic_native_headers_attribute_to_anthropic() {
        let defaults = KeyInboundConfig::default();
        let h = headers(&[("x-api-key", "sk-ant-api03-abcdefghijklmnop")]);
        assert_eq!(
            resolve_provider_hint(&h, &defaults.provider_hints).as_deref(),
            Some("anthropic")
        );
        // Same key on the bearer path.
        let h = headers(&[("authorization", "Bearer sk-ant-api03-abcdefghijklmnop")]);
        assert_eq!(
            resolve_provider_hint(&h, &defaults.provider_hints).as_deref(),
            Some("anthropic")
        );
        // A non-prefixed x-api-key still attributes when the SDK version
        // header rides along.
        let h = headers(&[
            ("x-api-key", "some-opaque-key"),
            ("anthropic-version", "2023-06-01"),
        ]);
        assert_eq!(
            resolve_provider_hint(&h, &defaults.provider_hints).as_deref(),
            Some("anthropic")
        );
    }

    #[test]
    fn specific_prefixes_win_over_the_loose_openai_rule() {
        // sk-ant- and sk-or- both start with sk-, so ordering is what keeps
        // them from attributing to OpenAI.
        let defaults = KeyInboundConfig::default();
        for (value, expect) in [
            ("Bearer sk-ant-api03-x", "anthropic"),
            ("Bearer sk-or-v1-x", "openrouter"),
            ("Bearer sk-proj-x", "openai"),
            ("Bearer sk-plainkey", "openai"),
        ] {
            let h = headers(&[("authorization", value)]);
            assert_eq!(
                resolve_provider_hint(&h, &defaults.provider_hints).as_deref(),
                Some(expect),
                "{value}"
            );
        }
    }

    #[test]
    fn authorized_native_credential_is_extracted_only_for_its_provider() {
        let defaults = KeyInboundConfig::default();
        let h = headers(&[("authorization", "Bearer sk-caller-owned-canary")]);

        assert_eq!(
            resolve_native_provider_credential(&h, &defaults.provider_hints, "OPENAI"),
            Some("sk-caller-owned-canary")
        );
        assert_eq!(
            resolve_native_provider_credential(&h, &defaults.provider_hints, "anthropic"),
            None
        );
    }

    #[test]
    fn minted_credentials_are_never_extracted_as_native_provider_keys() {
        let defaults = KeyInboundConfig::default();
        let h = headers(&[("authorization", &format!("Bearer {}", token()))]);

        assert_eq!(
            resolve_native_provider_credential(&h, &defaults.provider_hints, "openai"),
            None
        );
    }

    #[test]
    fn an_unrecognized_credential_is_unattributed_not_refused() {
        let defaults = KeyInboundConfig::default();
        let h = headers(&[("authorization", "Bearer some-opaque-jwt")]);
        assert_eq!(resolve_provider_hint(&h, &defaults.provider_hints), None);
        let h = headers(&[]);
        assert_eq!(resolve_provider_hint(&h, &defaults.provider_hints), None);
    }

    #[test]
    fn a_minted_key_never_attributes_as_a_native_credential() {
        // sbp_ tokens are ours; even a rule that would match them by prefix
        // must not turn a governed key into native attribution.
        let defaults = KeyInboundConfig::default();
        let h = headers(&[("x-api-key", &token()), ("anthropic-version", "2023-06-01")]);
        assert_eq!(resolve_provider_hint(&h, &defaults.provider_hints), None);
    }

    #[test]
    fn a_recognized_native_key_requires_an_explicit_allowing_policy() {
        let h = headers(&[("authorization", "Bearer sk-caller-owned")]);
        let mut cfg = KeyInboundConfig::default();

        assert_eq!(
            resolve_native_key_policy(&h, &cfg),
            NativeKeyPolicyDecision::PolicyMissing {
                provider: "openai".to_string()
            }
        );

        cfg.native_key_policy = Some(NativeKeyPolicyConfig {
            allowed_providers: vec!["anthropic".to_string()],
            ..NativeKeyPolicyConfig::default()
        });
        assert_eq!(
            resolve_native_key_policy(&h, &cfg),
            NativeKeyPolicyDecision::ProviderDenied {
                provider: "openai".to_string()
            }
        );

        cfg.native_key_policy = Some(NativeKeyPolicyConfig {
            allowed_providers: vec![" OpenAI ".to_string()],
            ..NativeKeyPolicyConfig::default()
        });
        assert_eq!(
            resolve_native_key_policy(&h, &cfg),
            NativeKeyPolicyDecision::Allowed {
                provider: "openai".to_string()
            }
        );
    }

    #[test]
    fn non_native_traffic_does_not_require_a_native_key_policy() {
        let cfg = KeyInboundConfig::default();
        assert_eq!(
            resolve_native_key_policy(&headers(&[("authorization", "Bearer an-opaque-jwt")]), &cfg),
            NativeKeyPolicyDecision::NotPresent
        );
        assert_eq!(
            resolve_native_key_policy(&headers(&[]), &cfg),
            NativeKeyPolicyDecision::NotPresent
        );
    }

    #[test]
    fn minted_keys_never_enter_native_policy_resolution() {
        let cfg = KeyInboundConfig {
            native_key_policy: Some(NativeKeyPolicyConfig {
                allowed_providers: vec!["anthropic".to_string()],
                ..NativeKeyPolicyConfig::default()
            }),
            ..KeyInboundConfig::default()
        };
        let h = headers(&[("x-api-key", &token()), ("anthropic-version", "2023-06-01")]);
        assert_eq!(
            resolve_native_key_policy(&h, &cfg),
            NativeKeyPolicyDecision::NotPresent
        );
    }

    #[test]
    fn native_policy_record_carries_key_record_governance_without_a_secret() {
        let policy = NativeKeyPolicyConfig {
            allowed_providers: vec!["openai".to_string()],
            max_requests_per_minute: Some(12),
            max_tokens_per_minute: Some(3456),
            max_budget_tokens: Some(7890),
            max_budget_usd: Some(1.25),
            allowed_models: vec!["gpt-5".to_string()],
            blocked_models: vec!["gpt-4".to_string()],
            require_pii_redaction: vec!["email".to_string()],
        };

        let record = native_policy_record(&policy, "tenant-a", "api.example", "openai");
        assert_eq!(record.key_id, "native:tenant-a:api.example:openai");
        assert!(record.secret_hash.is_empty());
        assert_eq!(record.max_requests_per_minute, Some(12));
        assert_eq!(record.max_tokens_per_minute, Some(3456));
        assert_eq!(
            record.budget,
            Some(sbproxy_keystore::record::RecordBudget {
                max_tokens: Some(7890),
                max_cost_usd: Some(1.25),
            })
        );
        assert_eq!(record.allowed_models, ["gpt-5"]);
        assert_eq!(record.blocked_models, ["gpt-4"]);
        assert_eq!(record.require_pii_redaction, ["email"]);
        assert_eq!(record.tenant_id.as_deref(), Some("tenant-a"));

        let effective =
            crate::key_policy::key_record_to_effective_policy(&record, "tenant-a").unwrap();
        assert_eq!(effective.key_id, record.key_id);
        assert_eq!(effective.max_requests_per_minute, Some(12));
        assert_eq!(effective.require_pii_redaction, ["email"]);
    }
}
