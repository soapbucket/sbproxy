//! Dynamic-dispatch plugin traits.
//!
//! Built-in modules use enum dispatch and do not implement these traits;
//! the traits exist for the `Plugin(Box<dyn T>)` fallback variant in the
//! module enums, which third-party plugins register through.

use std::future::Future;
use std::pin::Pin;

use anyhow::Result;

/// Outcome of an action handler - either proxied upstream or responded directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionOutcome {
    /// Request should be proxied to the upstream returned by upstream_peer.
    Proxy,
    /// Response was written directly (static, redirect, echo, etc.).
    Responded,
}

/// Origin of a subject resolved by an auth provider.
///
/// Mirrors the `UserIdSource` enum the observability layer stamps on
/// each event; this copy lives here so the plugin trait stays free of
/// any observability-crate dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthSubjectSource {
    /// Subject came from a request header (e.g. `X-User-Id` or the
    /// username portion of HTTP Basic / Digest credentials).
    Header,
    /// Subject came from a verified JWT `sub` claim.
    Jwt,
    /// Subject came from a forward-auth response header the upstream
    /// trust gateway returned.
    ForwardAuth,
}

/// Auth decision returned by an [`AuthProvider`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthDecision {
    /// Request is allowed to proceed.
    ///
    /// The struct fields carry an optional resolved subject so
    /// downstream observability can stamp `user_id` without re-running
    /// auth. Providers that authenticate without identifying an
    /// end-user (API key, bearer token shared between callers, bot
    /// auth) leave both fields `None`.
    Allow {
        /// Resolved end-user identifier (JWT `sub`, basic-auth
        /// username, forward-auth response header, etc.). `None` when
        /// the provider identified the request as authorized but did
        /// not bind it to a specific subject.
        sub: Option<String>,
        /// Where `sub` came from. `None` when `sub` is also `None`.
        source: Option<AuthSubjectSource>,
    },
    /// Request is denied with the given HTTP status and message.
    Deny {
        /// HTTP status code returned to the client.
        status: u16,
        /// Human-readable denial reason returned in the response body.
        message: String,
    },
    /// Request is denied with custom response headers attached.
    ///
    /// Used by providers that need to surface protocol-mandated
    /// challenge headers on a 401 / 403 response. The canonical use
    /// is the OAuth 2.0 Protected Resource Metadata response (RFC
    /// 9728), where the resource server points clients at the
    /// authorization server discovery document via a `WWW-Authenticate:
    /// Bearer resource_metadata="..."` header.
    ///
    /// Header names follow [RFC 7230 §3.2] (token chars only); values
    /// follow [RFC 7230 §3.2.6] (visible US-ASCII, no CR/LF). Order is
    /// preserved so providers emitting a multi-value `WWW-Authenticate`
    /// chain can keep the entries in source order.
    DenyWithHeaders {
        /// HTTP status code returned to the client.
        status: u16,
        /// Human-readable denial reason returned in the response body.
        message: String,
        /// `(name, value)` pairs to append to the response.
        headers: Vec<(String, String)>,
    },
}

impl AuthDecision {
    /// Construct an `Allow` decision with no resolved subject. Use
    /// this from providers that authenticate the request but do not
    /// identify a specific end-user (API key, bearer token, bot
    /// auth, noop).
    pub const fn allow_anonymous() -> Self {
        Self::Allow {
            sub: None,
            source: None,
        }
    }

    /// Construct an `Allow` decision with a resolved subject and the
    /// label describing where it came from.
    pub fn allow_with_subject(sub: impl Into<String>, source: AuthSubjectSource) -> Self {
        Self::Allow {
            sub: Some(sub.into()),
            source: Some(source),
        }
    }
}

/// Policy decision returned by a [`PolicyEnforcer`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    /// Request is allowed to proceed.
    Allow,
    /// Request is denied with the given HTTP status and message.
    Deny {
        /// HTTP status code returned to the client.
        status: u16,
        /// Human-readable denial reason returned in the response body.
        message: String,
    },
    /// Request is allowed AND the listed response headers MUST be
    /// appended on the way out. Used by policies that signal metadata
    /// to the client without blocking the request: API versioning
    /// emitting `Sunset` / `Deprecation` per RFC 8594, PII detection
    /// emitting `X-PII-Masked` when the body was rewritten, etc.
    ///
    /// Header names follow [RFC 7230 §3.2] (token chars only); values
    /// follow [RFC 7230 §3.2.6] (visible US-ASCII, no CR/LF).
    AllowWithHeaders {
        /// `(name, value)` pairs to append to the response.
        headers: Vec<(String, String)>,
    },
    /// Request is held pending human-in-the-loop approval.
    ///
    /// See `docs/adr-policy-verdict-shape.md` for the full design
    /// contract. The OSS dispatcher routes `Confirm` through the
    /// existing [`PolicyDecision::AllowWithHeaders`] mechanism by
    /// forwarding the request with `X-Policy-Confirm: <reason>` stamped
    /// on the response; OSS does not park the request. The enterprise
    /// interceptor handles parking before the OSS bridge fires: it
    /// queues the request for approver review, optionally posts to
    /// `webhook_url`, and resumes or synthesises a deny on `expires_at`.
    ///
    /// Marked `#[non_exhaustive]` so future fields (priority, queue
    /// hint, audit binding) can be added without breaking external
    /// constructors.
    #[non_exhaustive]
    Confirm {
        /// Human-readable summary of why approval is required, surfaced
        /// in the confirmation portal and on the OSS
        /// `X-Policy-Confirm` header.
        reason: String,
        /// URL the proxy posts to when notifying the approver. `None`
        /// falls back to the tenant's default notification channel.
        webhook_url: Option<url::Url>,
        /// Deadline after which the dispatcher treats no approval as an
        /// implicit deny. `None` means no automatic expiry.
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    },
}

impl PolicyDecision {
    /// Construct a [`PolicyDecision::Confirm`] from the three OSS
    /// fields.
    ///
    /// `#[non_exhaustive]` blocks struct-literal construction of
    /// `Confirm` from outside the defining crate. This constructor
    /// is the supported entry point so plugin authors and the
    /// dispatcher in `sbproxy-core` can build a Confirm verdict
    /// without depending on the variant's internal field set.
    /// Future fields (priority, queue hint, audit binding) land
    /// here with sensible defaults so existing call sites stay
    /// green.
    pub fn confirm(
        reason: impl Into<String>,
        webhook_url: Option<url::Url>,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Self {
        Self::Confirm {
            reason: reason.into(),
            webhook_url,
            expires_at,
        }
    }
}

/// Third-party action handler (dynamic dispatch).
///
/// Implementations handle incoming requests and decide whether to proxy
/// them upstream or respond directly.
pub trait ActionHandler: Send + Sync + 'static {
    /// Returns the handler type identifier (e.g. "my-custom-action").
    fn handler_type(&self) -> &'static str;

    /// Handle an incoming request.
    fn handle(
        &self,
        req: &mut http::Request<bytes::Bytes>,
        ctx: &mut dyn std::any::Any,
    ) -> Pin<Box<dyn Future<Output = Result<ActionOutcome>> + Send + '_>>;
}

/// Third-party auth provider (dynamic dispatch).
///
/// Implementations authenticate incoming requests against an external
/// or custom auth system.
pub trait AuthProvider: Send + Sync + 'static {
    /// Returns the auth type identifier (e.g. "my-custom-auth").
    fn auth_type(&self) -> &'static str;

    /// Authenticate an incoming request.
    fn authenticate(
        &self,
        req: &http::Request<bytes::Bytes>,
        ctx: &mut dyn std::any::Any,
    ) -> Pin<Box<dyn Future<Output = Result<AuthDecision>> + Send + '_>>;
}

/// Third-party policy enforcer (dynamic dispatch).
///
/// Implementations enforce custom policies (rate limiting, geo-blocking, etc.).
pub trait PolicyEnforcer: Send + Sync + 'static {
    /// Returns the policy type identifier (e.g. "my-custom-policy").
    fn policy_type(&self) -> &'static str;

    /// Enforce the policy against an incoming request.
    fn enforce(
        &self,
        req: &http::Request<bytes::Bytes>,
        ctx: &mut dyn std::any::Any,
    ) -> Pin<Box<dyn Future<Output = Result<PolicyDecision>> + Send + '_>>;
}

/// Per-invocation context threaded into [`TransformHandler::apply`].
///
/// Exists so third-party transforms can reach shared pipeline state
/// (hooks, origin identity) without every implementer paying for the
/// boilerplate of plumbing each field through its own signature. New
/// pipeline capabilities can be added here without churning the trait.
///
/// `hooks` is intentionally type-erased as `dyn Any + Send + Sync` to
/// keep this crate independent of the crate that owns the hook
/// bundle. Transforms that need hook access downcast to the concrete
/// hooks type; transforms that don't care simply ignore the field.
pub struct TransformContext<'a> {
    /// Origin identity (typically the hostname or origin_id) for the
    /// request currently being processed. Empty when unavailable.
    pub origin: &'a str,
    /// Type-erased hook bundle. `None` when no hooks are registered.
    /// Downcast to the concrete hooks type to use.
    pub hooks: Option<&'a (dyn std::any::Any + Send + Sync)>,
}

impl<'a> TransformContext<'a> {
    /// Convenience constructor for transforms that do not care about
    /// hooks (tests, OSS code paths). Equivalent to
    /// `TransformContext { origin, hooks: None }`.
    pub fn new(origin: &'a str) -> Self {
        Self {
            origin,
            hooks: None,
        }
    }

    /// Empty context (origin = "", hooks = None). Handy for callers
    /// that have no per-request state to thread through, e.g. legacy
    /// call sites still being migrated.
    pub fn empty() -> Self {
        Self {
            origin: "",
            hooks: None,
        }
    }
}

/// Third-party transform handler (dynamic dispatch).
///
/// Implementations transform request or response bodies
/// (e.g. custom encoding, field masking).
pub trait TransformHandler: Send + Sync + 'static {
    /// Returns the transform type identifier (e.g. "my-custom-transform").
    fn transform_type(&self) -> &'static str;

    /// Apply the transform to a body buffer.
    ///
    /// `ctx` threads per-invocation state (origin identity, optional
    /// hook bundle) through the trait so transforms that need to
    /// delegate to classification / cache / quality hooks can do so
    /// without hard-coding cross-crate types into the trait signature.
    /// Transforms that don't care about hooks simply ignore `ctx`.
    fn apply<'a>(
        &'a self,
        body: &'a mut bytes::BytesMut,
        content_type: Option<&'a str>,
        ctx: &'a TransformContext<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;
}

/// Request enricher - adds data to request context (GeoIP, UA parsing, etc.).
pub trait RequestEnricher: Send + Sync + 'static {
    /// Returns the enricher name (e.g. "geoip", "ua-parser").
    fn name(&self) -> &'static str;

    /// Enrich the request context with additional data.
    fn enrich(
        &self,
        req: &http::Request<bytes::Bytes>,
        ctx: &mut dyn std::any::Any,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Confirm carries reason + optional webhook + optional expiry.
    /// A past `expires_at` must compare as already elapsed; the
    /// dispatcher relies on this to synthesise an immediate deny per
    /// `docs/adr-policy-verdict-shape.md`.
    #[test]
    fn confirm_variant_round_trip() {
        let allow = PolicyDecision::Allow;
        let deny = PolicyDecision::Deny {
            status: 403,
            message: "blocked".to_string(),
        };
        let allow_headers = PolicyDecision::AllowWithHeaders {
            headers: vec![("X-Foo".to_string(), "bar".to_string())],
        };

        let past = chrono::Utc::now() - chrono::Duration::seconds(60);
        let confirm = PolicyDecision::Confirm {
            reason: "high-spend AI request requires approval".to_string(),
            webhook_url: Some(
                "https://approvals.example/inbound"
                    .parse::<url::Url>()
                    .expect("static webhook url parses"),
            ),
            expires_at: Some(past),
        };

        // All four constructors compile and round-trip.
        let _ = (&allow, &deny, &allow_headers, &confirm);

        // Past `expires_at` is detectable via simple comparison; this
        // is what the dispatcher uses to short-circuit to Deny.
        if let PolicyDecision::Confirm { expires_at, .. } = &confirm {
            let exp = expires_at.expect("expires_at was set Some(past)");
            assert!(
                exp < chrono::Utc::now(),
                "past expires_at must compare as elapsed"
            );
        } else {
            panic!("confirm variant did not match");
        }
    }

    /// Load-bearing exhaustiveness check. If a future PR adds a new
    /// variant to `PolicyDecision` without updating this match, the
    /// compiler refuses to build the test. That refusal is the point:
    /// every dispatcher in the workspace will need an analogous update,
    /// and this test is the canary that fails first.
    #[test]
    fn policy_decision_match_is_exhaustive() {
        fn label(d: &PolicyDecision) -> &'static str {
            match d {
                PolicyDecision::Allow => "allow",
                PolicyDecision::Deny { .. } => "deny",
                PolicyDecision::AllowWithHeaders { .. } => "allow_with_headers",
                PolicyDecision::Confirm { .. } => "confirm",
            }
        }

        assert_eq!(label(&PolicyDecision::Allow), "allow");
        assert_eq!(
            label(&PolicyDecision::Deny {
                status: 403,
                message: String::new(),
            }),
            "deny"
        );
        assert_eq!(
            label(&PolicyDecision::AllowWithHeaders {
                headers: Vec::new(),
            }),
            "allow_with_headers"
        );
        assert_eq!(
            label(&PolicyDecision::Confirm {
                reason: String::new(),
                webhook_url: None,
                expires_at: None,
            }),
            "confirm"
        );
    }
}
