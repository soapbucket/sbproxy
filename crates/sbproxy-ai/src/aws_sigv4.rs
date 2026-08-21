//! AWS Signature Version 4 request signing for the AI egress path.
//!
//! Bedrock and SageMaker do not accept a static bearer token. Every
//! request carries an `Authorization: AWS4-HMAC-SHA256 ...` header
//! computed over a canonical form of that exact request, so the
//! signature is only valid for the method, host, path, signed headers,
//! and body bytes that actually go on the wire. That is why signing
//! happens at the transport choke point (`client::send_governed`)
//! rather than anywhere upstream of it: anything that mutates the
//! request after the signature is computed invalidates it, and the
//! failure looks like an authentication error rather than a bug.
//!
//! # Design decision: where the signing region comes from
//!
//! The ticket left this unmade, so the field decided it. The signing
//! region is an **explicit, required `region:` key**. It is never
//! inferred from the endpoint host, and overriding the endpoint never
//! changes it.
//!
//! That is what the AWS SDKs do. The `bedrock-runtime` endpoint
//! ruleset's endpoint-override branch returns
//! `{"url": {"ref": "Endpoint"}, "properties": {}, "headers": {}}`:
//! no `authSchemes`, therefore no `signingRegion`, so an operator who
//! points the SDK at a VPC endpoint still signs with the client's
//! configured region. AWS's own PrivateLink documentation shows both
//! being passed together
//! (`boto3.client("bedrock-runtime", region_name="us-east-1",
//! endpoint_url="https://{vpce-id}.bedrock-runtime.us-east-1.vpce.amazonaws.com")`),
//! and botocore raises `NoRegionError` when the region is missing no
//! matter what the endpoint says. Every gateway that fronts Bedrock
//! agrees: Kong's `kong/llm/drivers/bedrock.lua` builds the URL from
//! `config.region` and lets `upstream_url` override the URL alone;
//! APISIX's `ai-transport/auth-aws.lua` takes the region as an explicit
//! argument and errors with `"missing or invalid region for SigV4
//! signing"` when it is empty; Envoy's `aws_request_signing` filter
//! takes `region` separately from `host_rewrite`. LiteLLM's
//! `_get_aws_region_name` is the one implementation that guesses, and
//! even it reads the model ARN rather than the endpoint, then falls
//! back to a hardcoded `us-west-2`. Silently signing for the wrong
//! region produces a 403 that reads like a permissions problem, so
//! that fallback is the part not to copy.
//!
//! References: botocore
//! `botocore/data/bedrock-runtime/2023-09-30/endpoint-rule-set-1.json`;
//! <https://docs.aws.amazon.com/bedrock/latest/userguide/vpc-interface-endpoints.html>;
//! <https://smithy.io/2.0/aws/aws-auth.html> (`aws.auth#sigv4`, whose
//! `name` member supplies the credential-scope service name).
//!
//! The one convenience this buys: the provider catalog's default base
//! URLs are the templates `https://bedrock-runtime.{region}.amazonaws.com`
//! and `https://runtime.sagemaker.{region}.amazonaws.com`. When an
//! `aws_sigv4:` block is present, [`crate::provider::ProviderConfig::effective_base_url`]
//! substitutes `region` into that placeholder, the same way APISIX's
//! `host_template = "bedrock-runtime.%s.amazonaws.com"` does, so
//! `base_url` stays optional for the public regional endpoint and stays
//! authoritative when set for a VPC endpoint.
//!
//! # Design decision: refresh margins
//!
//! Short-lived credentials are refreshed on two windows, copied from
//! botocore's `RefreshableCredentials`:
//! `_DEFAULT_ADVISORY_REFRESH_TIMEOUT = 15 * 60` and
//! `_DEFAULT_MANDATORY_REFRESH_TIMEOUT = 10 * 60`
//! (<https://github.com/boto/botocore/blob/develop/botocore/credentials.py>).
//! Inside the advisory window a refresh is attempted, and a refresh
//! that fails while the cached credential is still outside the
//! mandatory window is logged and the cached credential keeps serving.
//! That five-minute overlap is what turns an STS blip into a log line
//! instead of an outage. The Rust SDK's own `DEFAULT_BUFFER_TIME` of 10
//! seconds is tuned for IMDS-style identities refreshed on every
//! operation and is far too tight for a gateway holding one-hour
//! `AssumeRole` sessions.
//!
//! # Design decision: streaming bodies are refused, not unsigned
//!
//! `UNSIGNED-PAYLOAD` is documented for Amazon S3 only, and no
//! `bedrock-runtime` operation registers the unsigned-payload
//! middleware in the AWS SDKs. Bedrock's streaming operations
//! (`ConverseStream`, `InvokeModelWithResponseStream`) stream the
//! *response*; the request is an ordinary buffered JSON document. So a
//! request body this signer cannot read is a bug somewhere upstream,
//! not a case to paper over, and [`AwsSigV4Error::UnbufferedBody`]
//! fails the attempt closed rather than sending a signature that does
//! not cover the bytes.
//!
//! # Design decision: clock skew is measured, not guessed
//!
//! AWS rejects a signature whose `x-amz-date` is too far from its own
//! clock, and on Bedrock that arrives as a 403 that is not obviously
//! different from a bad key. [`AwsSigV4Signer::record_response_timing`]
//! implements the AWS SDKs' clock-skew correction: on a client-error
//! response it reads the `Date` response header, estimates the local
//! clock's offset against the round trip's midpoint, and once the
//! offset passes four minutes (the Go SDK's `skewThreshold`) it records
//! it, warns, and applies the correction to every subsequent signature.
//! Measurements from a cached response (`Age` present) or from a round
//! trip longer than fifteen minutes (`maxTrustedRequestDuration`) are
//! discarded. A wrong key never moves the measured offset; a skewed
//! clock does, so the WARN line distinguishes the two.

use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::time::{Duration, SystemTime};

use arc_swap::ArcSwapOption;
use aws_credential_types::provider::{ProvideCredentials, SharedCredentialsProvider};
use aws_credential_types::Credentials;
use aws_sigv4::http_request::{sign, SignableBody, SignableRequest, SigningSettings};
use aws_sigv4::sign::v4;
use sbproxy_vault::SecretString;
use schemars::r#gen::SchemaGenerator;
use schemars::schema::Schema;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::warn;

/// Advisory refresh window: inside it a refresh is attempted, and a
/// failure is survivable while the cached credential is still valid.
/// botocore's `_DEFAULT_ADVISORY_REFRESH_TIMEOUT`.
const DEFAULT_ADVISORY_REFRESH_SECS: u64 = 900;

/// Mandatory refresh window: inside it a refresh failure is fatal to
/// the attempt, because the credential is about to stop working
/// anyway. botocore's `_DEFAULT_MANDATORY_REFRESH_TIMEOUT`.
const MANDATORY_REFRESH_SECS: u64 = 600;

/// Offset past which the local clock is treated as skewed and the
/// correction is applied to subsequent signatures. The AWS Go SDK's
/// `skewThreshold` in `aws/retry/middleware.go`.
const CLOCK_SKEW_THRESHOLD_SECS: i64 = 240;

/// A round trip longer than this makes the `Date`-header midpoint
/// estimate worthless, so the sample is dropped. The Go SDK's
/// `maxTrustedRequestDuration`.
const MAX_TRUSTED_ROUND_TRIP_SECS: u64 = 900;

/// Hard bound on the correction the skew estimator may apply, so a
/// malformed or hostile `Date` header cannot push every signature out
/// of AWS's acceptance window.
const MAX_CLOCK_CORRECTION_SECS: i64 = 3600;

/// Headers this scheme owns. They are stripped before the canonical
/// request is built so that signing the same request object twice (a
/// same-origin redirect replays it) cannot fold a stale timestamp or a
/// stale signature into the new canonical form.
const OWNED_HEADERS: [&str; 4] = [
    "authorization",
    "x-amz-date",
    "x-amz-security-token",
    "x-amz-content-sha256",
];

/// Headers that never enter the canonical request because the HTTP
/// client, not this code, decides their final value. `authorization`,
/// `user-agent`, `x-amzn-trace-id`, and `transfer-encoding` are already
/// excluded by `SigningSettings::default`; these two are the ones
/// reqwest and hyper add or rewrite between `build()` and the wire.
const UNSIGNABLE_HEADERS: [&str; 2] = ["accept-encoding", "connection"];

/// A configuration string holding a credential.
///
/// Wraps [`SecretString`], so its `Debug` renders `[REDACTED]` and the
/// bytes are zeroed on drop. It has no `Display` and no `Serialize`, so
/// there is no formatting path that could print it and no way for it to
/// reach an admin JSON dump. Deserializes from a
/// plain YAML/JSON string, which means `${VAR}` interpolation and
/// `vault://` / `awssm://` provider URIs resolve into it exactly as
/// they do for any other string-valued config key.
#[derive(Clone)]
pub struct ConfigSecret(SecretString);

impl ConfigSecret {
    /// Borrow the plaintext. Every call site is a place a credential
    /// leaves protected storage, so keep them few and never log the
    /// result.
    pub fn expose(&self) -> &str {
        self.0.expose()
    }

    /// Whether the configured value is the empty string, which is
    /// almost always an unset environment variable rather than an
    /// intentional empty credential.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Replace the protected value with a dereferenced secret.
    ///
    /// Called by the config loader once it has resolved a `vault://`,
    /// `awssm://`, `secret://`, or `file:` reference. Assigning drops
    /// the previous `SecretString`, which zeroes the reference text on
    /// the way out.
    pub fn set_resolved(&mut self, resolved: &str) {
        self.0 = SecretString::new(resolved);
    }
}

impl fmt::Debug for ConfigSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<'de> Deserialize<'de> for ConfigSecret {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // serde hands us an owned `String`; that intermediate buffer is
        // not zeroed, which is a limitation of deserializing through
        // serde at all rather than of this type. Everything downstream
        // of here is protected.
        let plaintext = String::deserialize(deserializer)?;
        Ok(Self(SecretString::new(&plaintext)))
    }
}

impl JsonSchema for ConfigSecret {
    fn is_referenceable() -> bool {
        false
    }

    fn schema_name() -> String {
        "ConfigSecret".to_string()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        String::json_schema(generator)
    }
}

/// Where a provider's AWS credentials come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AwsCredentialSource {
    /// The standard AWS credential provider chain: environment
    /// variables, the shared config and credentials files, an OIDC web
    /// identity token (EKS IRSA), the ECS task role, and finally the
    /// EC2 instance profile. This is the default and the right answer
    /// for anything running inside AWS, because the chain refreshes
    /// short-lived credentials on its own.
    #[default]
    DefaultChain,
    /// A long-lived access key pair supplied by config. `session_token`
    /// may carry an already-issued short-lived credential, but SBproxy
    /// cannot renew one it was handed: use `assume_role` or
    /// `default_chain` for credentials that expire.
    Static,
    /// STS `AssumeRole`, with the base identity coming from the default
    /// chain. The session is renewed before it expires, so a role
    /// session is the supported way to run on short-lived credentials.
    AssumeRole,
}

impl AwsCredentialSource {
    /// Stable label for error text. Never a credential value.
    fn label(self) -> &'static str {
        match self {
            Self::DefaultChain => "default_chain",
            Self::Static => "static",
            Self::AssumeRole => "assume_role",
        }
    }
}

/// How one provider's AWS credentials are obtained.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AwsCredentialsConfig {
    /// Which credential source backs this provider. Defaults to the
    /// standard AWS provider chain.
    #[serde(default)]
    pub source: AwsCredentialSource,
    /// AWS access key ID. Required by, and only read by, `static`.
    #[serde(default)]
    pub access_key_id: Option<String>,
    /// AWS secret access key. Required by, and only read by, `static`.
    /// Resolve it through `${VAR}`, `vault://`, or `awssm://` rather
    /// than writing it into the config file.
    #[serde(default)]
    pub secret_access_key: Option<ConfigSecret>,
    /// Session token accompanying an already-issued short-lived key
    /// pair. Only read by `static`. A token supplied this way expires
    /// on AWS's schedule and SBproxy has no way to renew it.
    #[serde(default)]
    pub session_token: Option<ConfigSecret>,
    /// Role ARN to assume. Required by, and only read by,
    /// `assume_role`.
    #[serde(default)]
    pub role_arn: Option<String>,
    /// External ID demanded by the role's trust policy. Only read by
    /// `assume_role`. Held as a credential, so no SBproxy code path
    /// formats it, but note that the process-wide log redactor keys off
    /// a fixed list of credential field names that does not include
    /// this one (`external_id` is also a non-secret payment identifier
    /// elsewhere in the product, so widening that list would mask
    /// reconciliation IDs). Supply it as a `${VAR}` or `vault://`
    /// reference so the literal never sits in the config file.
    #[serde(default)]
    pub external_id: Option<ConfigSecret>,
    /// Role session name recorded in CloudTrail. Only read by
    /// `assume_role`; defaults to `sbproxy`.
    #[serde(default)]
    pub session_name: Option<String>,
    /// Requested role session length in seconds. Only read by
    /// `assume_role`; unset takes the role's own default (one hour on
    /// most roles).
    #[serde(default)]
    pub session_duration_secs: Option<u64>,
    /// Named profile in the shared AWS config files. Read by
    /// `default_chain` and by the base identity `assume_role` starts
    /// from.
    #[serde(default)]
    pub profile: Option<String>,
}

/// Sign this provider's requests with AWS Signature Version 4.
///
/// Presence of this block is what selects the signer. Absent it, the
/// provider's `api_key` is forwarded verbatim in the catalog's auth
/// header, which is the pre-existing bearer-token behavior and never
/// reaches this code at all. The two are mutually exclusive: a
/// provider entry sets `api_key` or `aws_sigv4`, never both.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AwsSigV4Config {
    /// AWS region used for the credential scope, for example
    /// `us-east-1`. Required, and independent of `base_url`: pointing
    /// `base_url` at a VPC endpoint or a private hostname does not
    /// change the region a signature is scoped to, exactly as an AWS
    /// SDK's `endpoint_url` override does not. When `base_url` is
    /// unset, this value also fills the `{region}` placeholder in the
    /// provider catalog's default endpoint.
    pub region: String,
    /// Signing service name in the credential scope. Defaults to
    /// `bedrock` for a `bedrock` provider and `sagemaker` for a
    /// `sagemaker` provider; set it explicitly for any other AWS
    /// service fronted through a provider entry.
    #[serde(default)]
    pub service: Option<String>,
    /// How to obtain the AWS credentials. Unset uses the standard AWS
    /// credential provider chain.
    #[serde(default)]
    pub credentials: Option<AwsCredentialsConfig>,
    /// Seconds before expiry at which a short-lived credential is
    /// refreshed. Defaults to 900. A refresh that fails inside this
    /// window is retried on the next request and logged, and the
    /// cached credential keeps serving until 600 seconds remain, at
    /// which point a refresh failure fails the request.
    #[serde(default)]
    pub refresh_margin_secs: Option<u64>,
}

impl AwsSigV4Config {
    /// The signing service name for this block on a provider of type
    /// `provider_type`, or an error naming what to set when the
    /// provider type carries no AWS default.
    fn resolved_service(&self, provider_type: &str) -> Result<String, AwsSigV4Error> {
        if let Some(service) = self.service.as_deref().map(str::trim) {
            if !service.is_empty() {
                return Ok(service.to_string());
            }
        }
        match provider_type {
            "bedrock" | "aws_bedrock" => Ok("bedrock".to_string()),
            "sagemaker" | "aws_sagemaker" => Ok("sagemaker".to_string()),
            other => Err(AwsSigV4Error::Config(format!(
                "provider type {other:?} has no default AWS signing service; \
                 set `aws_sigv4.service` explicitly"
            ))),
        }
    }

    /// Reject a block that cannot produce a signature before anything
    /// dials AWS with it.
    ///
    /// # Errors
    ///
    /// Returns the operator-facing reason the block was refused. The
    /// message names keys, never values.
    pub fn validate(&self, provider_type: &str) -> Result<(), AwsSigV4Error> {
        if self.region.trim().is_empty() {
            return Err(AwsSigV4Error::Config(
                "`region` is required and must not be empty; it is the credential scope \
                 and is never inferred from `base_url`"
                    .to_string(),
            ));
        }
        self.resolved_service(provider_type)?;
        if let Some(margin) = self.refresh_margin_secs {
            if margin < MANDATORY_REFRESH_SECS {
                return Err(AwsSigV4Error::Config(format!(
                    "`refresh_margin_secs` must be at least {MANDATORY_REFRESH_SECS}; \
                     a margin inside the mandatory-refresh window leaves no room to \
                     survive a failed refresh"
                )));
            }
        }
        let credentials = match self.credentials.as_ref() {
            Some(credentials) => credentials,
            None => return Ok(()),
        };
        let secret_present = credentials
            .secret_access_key
            .as_ref()
            .is_some_and(|secret| !secret.is_empty());
        let key_present = credentials
            .access_key_id
            .as_deref()
            .is_some_and(|key| !key.trim().is_empty());
        let role_present = credentials
            .role_arn
            .as_deref()
            .is_some_and(|arn| !arn.trim().is_empty());
        match credentials.source {
            AwsCredentialSource::Static => {
                if !key_present || !secret_present {
                    return Err(AwsSigV4Error::Config(
                        "`credentials.source: static` requires both \
                         `access_key_id` and a non-empty `secret_access_key`"
                            .to_string(),
                    ));
                }
                if role_present {
                    return Err(AwsSigV4Error::Config(
                        "`credentials.role_arn` is only read by \
                         `credentials.source: assume_role`"
                            .to_string(),
                    ));
                }
            }
            AwsCredentialSource::AssumeRole => {
                if !role_present {
                    return Err(AwsSigV4Error::Config(
                        "`credentials.source: assume_role` requires `role_arn`".to_string(),
                    ));
                }
                if key_present || secret_present {
                    return Err(AwsSigV4Error::Config(
                        "`credentials.source: assume_role` takes its base identity from \
                         the default credential chain; remove `access_key_id` and \
                         `secret_access_key`"
                            .to_string(),
                    ));
                }
            }
            AwsCredentialSource::DefaultChain => {
                if key_present || secret_present || role_present {
                    return Err(AwsSigV4Error::Config(
                        "`credentials.source: default_chain` reads none of \
                         `access_key_id`, `secret_access_key`, or `role_arn`; \
                         set `source: static` or `source: assume_role` instead"
                            .to_string(),
                    ));
                }
            }
        }
        Ok(())
    }

    /// Every credential-bearing field in this block, for the config
    /// loader's secret-reference resolution pass.
    ///
    /// A `vault://`, `awssm://`, `secret://`, or `file:` reference is
    /// just text until something dereferences it. Without this hook the
    /// reference string itself would become the signing key, and AWS
    /// would answer `SignatureDoesNotMatch`, which reads like a wrong
    /// key rather than like a reference nobody resolved. The loader
    /// treats an unresolvable reference as a hard error, so a reference
    /// can never reach the wire verbatim.
    pub fn credential_secrets_mut(&mut self) -> Vec<&mut ConfigSecret> {
        let Some(credentials) = self.credentials.as_mut() else {
            return Vec::new();
        };
        [
            credentials.secret_access_key.as_mut(),
            credentials.session_token.as_mut(),
            credentials.external_id.as_mut(),
        ]
        .into_iter()
        .flatten()
        .collect()
    }
}

/// Why a request could not be signed.
///
/// Every variant carries configuration keys, region and service names,
/// or an AWS SDK diagnostic. No variant carries a credential value.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AwsSigV4Error {
    /// The `aws_sigv4:` block cannot produce a signature as written.
    #[error("aws_sigv4: {0}")]
    Config(String),
    /// The credential source did not yield credentials.
    #[error(
        "aws_sigv4: {source_kind} credentials for {region}/{service} are unavailable: {reason}"
    )]
    Credentials {
        /// Which source was asked, as a stable label.
        source_kind: &'static str,
        /// Signing region, for locating the provider entry.
        region: String,
        /// Signing service, for locating the provider entry.
        service: String,
        /// The AWS SDK's diagnostic, which carries no key material.
        reason: String,
    },
    /// The request body is not a buffer this code can hash, so the
    /// payload hash of the canonical request would not cover what is
    /// sent.
    #[error(
        "aws_sigv4: cannot sign a request whose body is a stream; SigV4 hashes the \
         payload and `UNSIGNED-PAYLOAD` is an Amazon S3 extension that \
         bedrock-runtime does not accept"
    )]
    UnbufferedBody,
    /// The canonical request could not be built or the signature could
    /// not be applied.
    #[error("aws_sigv4: signing {region}/{service} failed: {reason}")]
    Signing {
        /// Signing region.
        region: String,
        /// Signing service.
        service: String,
        /// The signer's diagnostic.
        reason: String,
    },
}

/// One resolved credential plus the instants that govern its reuse.
struct CachedCredentials {
    credentials: Credentials,
    /// Refresh is attempted at or after this instant. `None` for a
    /// credential that never expires.
    refresh_at: Option<SystemTime>,
    /// A refresh failure at or after this instant fails the request.
    /// `None` for a credential that never expires.
    fail_at: Option<SystemTime>,
}

/// Which credential provider backs the cache.
enum CredentialBacking {
    /// A fixed key pair. Never refreshed because there is nothing to
    /// refresh it from.
    Static(Credentials),
    /// An AWS SDK provider consulted whenever the cache goes stale.
    Provider(SharedCredentialsProvider),
}

impl fmt::Debug for CredentialBacking {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // `Credentials` has a redacting `Debug`, but there is
            // nothing here worth printing either way.
            Self::Static(_) => f.write_str("Static"),
            Self::Provider(_) => f.write_str("Provider"),
        }
    }
}

/// Signs one provider's outbound requests with AWS SigV4.
///
/// Holds the credential cache, so one signer is built per provider
/// entry and shared across every request to it. The cache lives for
/// the life of the [`crate::client::AiClient`] that built it; a config
/// reload replaces that client wholesale, which is what invalidates a
/// signer whose `aws_sigv4:` block changed.
pub struct AwsSigV4Signer {
    region: String,
    service: String,
    /// Stable label for the configured credential source, used in
    /// error text so an operator can tell which block failed.
    source_kind: &'static str,
    backing: CredentialBacking,
    cached: ArcSwapOption<CachedCredentials>,
    /// Single-flights the refresh so a burst of requests arriving on a
    /// stale credential produces one `AssumeRole` call, not one per
    /// request.
    refresh_lock: tokio::sync::Mutex<()>,
    advisory: Duration,
    mandatory: Duration,
    /// Measured offset of the local clock against AWS, in seconds.
    /// Added to the wall clock when stamping `x-amz-date`.
    clock_offset_secs: AtomicI64,
    /// Whether the skew WARN has already been emitted, so a persistent
    /// skew produces one line rather than one per request.
    skew_warned: AtomicBool,
}

impl fmt::Debug for AwsSigV4Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AwsSigV4Signer")
            .field("region", &self.region)
            .field("service", &self.service)
            .field("backing", &self.backing)
            .field(
                "clock_offset_secs",
                &self.clock_offset_secs.load(Ordering::Relaxed),
            )
            .finish()
    }
}

impl AwsSigV4Signer {
    /// Build a signer for one provider entry.
    ///
    /// Validates the block, resolves the signing service from
    /// `provider_type` when `service` is unset, and constructs the
    /// credential provider. No credential is fetched here: the first
    /// request pays for that, so a provider whose role cannot be
    /// assumed does not stall the config that names it.
    ///
    /// # Errors
    ///
    /// Returns [`AwsSigV4Error::Config`] for a block that cannot
    /// produce a signature and [`AwsSigV4Error::Credentials`] when the
    /// AWS SDK refuses to construct the provider.
    pub async fn build(
        config: &AwsSigV4Config,
        provider_type: &str,
    ) -> Result<Self, AwsSigV4Error> {
        config.validate(provider_type)?;
        let region = config.region.trim().to_string();
        let service = config.resolved_service(provider_type)?;
        let credentials = config.credentials.clone().unwrap_or_default();
        let source_kind = credentials.source.label();
        let backing = build_backing(&region, &credentials).await?;
        let advisory = Duration::from_secs(
            config
                .refresh_margin_secs
                .unwrap_or(DEFAULT_ADVISORY_REFRESH_SECS),
        );
        Ok(Self {
            region,
            service,
            source_kind,
            backing,
            cached: ArcSwapOption::empty(),
            refresh_lock: tokio::sync::Mutex::new(()),
            advisory,
            mandatory: Duration::from_secs(MANDATORY_REFRESH_SECS),
            clock_offset_secs: AtomicI64::new(0),
            skew_warned: AtomicBool::new(false),
        })
    }

    /// Sign `request` in place, stamping it with the current corrected
    /// clock.
    ///
    /// # Errors
    ///
    /// See [`AwsSigV4Error`]. A failure fails the attempt; there is no
    /// unsigned fallback.
    pub async fn sign_request(&self, request: &mut reqwest::Request) -> Result<(), AwsSigV4Error> {
        self.sign_request_at(request, self.signing_time()).await
    }

    /// Sign `request` in place as of `at`.
    ///
    /// Split out from [`Self::sign_request`] so a test can pin the
    /// timestamp and therefore the signature. Production always passes
    /// the skew-corrected wall clock.
    ///
    /// # Errors
    ///
    /// See [`AwsSigV4Error`].
    pub async fn sign_request_at(
        &self,
        request: &mut reqwest::Request,
        at: SystemTime,
    ) -> Result<(), AwsSigV4Error> {
        let credentials = self.credentials().await?;

        // Idempotence. `send_governed` replays the same request object
        // on a same-origin redirect, so a second application must
        // rebuild the canonical request from a clean slate rather than
        // fold in the timestamp and signature the first one left.
        for name in OWNED_HEADERS {
            request.headers_mut().remove(name);
        }

        let method = request.method().as_str().to_string();
        let uri = request.url().as_str().to_string();

        // Hash the body here rather than handing the bytes to the
        // signer, so nothing borrows the request across the mutation
        // that applies the result. `Precomputed` takes exactly the
        // lowercase hex SHA-256 the canonical request wants.
        let payload_hash = match request.body() {
            None => sha256_hex(&[]),
            Some(body) => match body.as_bytes() {
                Some(bytes) => sha256_hex(bytes),
                None => return Err(AwsSigV4Error::UnbufferedBody),
            },
        };

        // Only headers whose value is stable between here and the wire
        // may enter SignedHeaders. `host` is added by the signer from
        // the URI; `content-length` and `accept-encoding` are written
        // by hyper after this point and are deliberately left out.
        let headers: Vec<(String, String)> = request
            .headers()
            .iter()
            .filter(|(name, _)| !UNSIGNABLE_HEADERS.contains(&name.as_str()))
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (name.as_str().to_string(), value.to_string()))
            })
            .collect();

        let identity = credentials.into();
        // The defaults are the AWS SDK's own: header-location signature,
        // double URI-path encoding (every service except S3), dot-segment
        // normalization, session token included in the canonical request,
        // and `authorization` / `user-agent` / `x-amzn-trace-id` /
        // `transfer-encoding` excluded because a proxy may rewrite them.
        let settings = SigningSettings::default();
        let params: aws_sigv4::http_request::SigningParams<'_> = v4::SigningParams::builder()
            .identity(&identity)
            .region(&self.region)
            .name(&self.service)
            .time(at)
            .settings(settings)
            .build()
            .map_err(|error| self.signing_error(&error))?
            .into();

        let signable = SignableRequest::new(
            &method,
            uri.as_str(),
            headers.iter().map(|(n, v)| (n.as_str(), v.as_str())),
            SignableBody::Precomputed(payload_hash),
        )
        .map_err(|error| self.signing_error(&error))?;

        let (instructions, _signature) = sign(signable, &params)
            .map_err(|error| self.signing_error(&error))?
            .into_parts();
        let (signed_headers, query_params) = instructions.into_parts();
        if !query_params.is_empty() {
            // Unreachable with `SignatureLocation::Headers`, and the
            // honest response to reaching it is to refuse rather than
            // send a request whose query string lost the signature.
            return Err(AwsSigV4Error::Signing {
                region: self.region.clone(),
                service: self.service.clone(),
                reason: "signer produced query parameters for a header-location signature"
                    .to_string(),
            });
        }
        for header in signed_headers {
            let name = reqwest::header::HeaderName::from_bytes(header.name().as_bytes())
                .map_err(|error| self.signing_error(&error))?;
            let mut value = reqwest::header::HeaderValue::from_str(header.value())
                .map_err(|error| self.signing_error(&error))?;
            // Every header this scheme writes is credential-bearing or
            // credential-adjacent. Marking them sensitive keeps them
            // out of header dumps and makes `strip_sensitive_headers`
            // drop them on a cross-origin redirect, where the signature
            // is worthless anyway and the next hop re-signs.
            value.set_sensitive(true);
            request.headers_mut().insert(name, value);
        }
        Ok(())
    }

    /// Feed one upstream response back to the signer so it can correct
    /// the local clock.
    ///
    /// Only client-error responses are sampled: a successful request
    /// proves the clock was inside AWS's window, and a 5xx says nothing
    /// about authentication. `round_trip` is the elapsed time of the
    /// exchange, used to place the server's `Date` at the midpoint.
    pub fn record_response_timing(
        &self,
        status: reqwest::StatusCode,
        headers: &reqwest::header::HeaderMap,
        round_trip: Duration,
    ) {
        if !status.is_client_error() {
            return;
        }
        if headers.contains_key(reqwest::header::AGE) {
            // A cached response's `Date` describes when the cache
            // stored it, not the origin's clock now.
            return;
        }
        if round_trip > Duration::from_secs(MAX_TRUSTED_ROUND_TRIP_SECS) {
            return;
        }
        let Some(server_time) = headers
            .get(reqwest::header::DATE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| chrono::DateTime::parse_from_rfc2822(value).ok())
        else {
            return;
        };
        let Ok(local_now) = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) else {
            return;
        };
        // The `Date` was stamped somewhere inside the exchange; the
        // midpoint is the least-wrong estimate of the local instant it
        // corresponds to.
        let local_at_response = local_now.as_secs() as i64 - (round_trip.as_secs() as i64) / 2;
        let offset = server_time.timestamp() - local_at_response;
        if offset.abs() < CLOCK_SKEW_THRESHOLD_SECS {
            return;
        }
        let clamped = offset.clamp(-MAX_CLOCK_CORRECTION_SECS, MAX_CLOCK_CORRECTION_SECS);
        self.clock_offset_secs.store(clamped, Ordering::Relaxed);
        if !self.skew_warned.swap(true, Ordering::Relaxed) {
            warn!(
                region = %self.region,
                service = %self.service,
                status = status.as_u16(),
                offset_secs = clamped,
                "this host's clock differs from AWS by more than the SigV4 acceptance \
                 window, which is one way a correct key still gets a 403. Correcting \
                 subsequent signatures by the measured offset so traffic recovers; fix \
                 NTP here, since a correction is a workaround"
            );
        }
    }

    /// The wall clock with the measured AWS offset applied.
    fn signing_time(&self) -> SystemTime {
        let offset = self.clock_offset_secs.load(Ordering::Relaxed);
        let now = SystemTime::now();
        let shift = Duration::from_secs(offset.unsigned_abs());
        let corrected = if offset >= 0 {
            now.checked_add(shift)
        } else {
            now.checked_sub(shift)
        };
        corrected.unwrap_or(now)
    }

    /// The current credential, refreshing it when the advisory window
    /// has opened.
    async fn credentials(&self) -> Result<Credentials, AwsSigV4Error> {
        let provider = match &self.backing {
            CredentialBacking::Static(credentials) => return Ok(credentials.clone()),
            CredentialBacking::Provider(provider) => provider,
        };

        let now = SystemTime::now();
        if let Some(entry) = self.cached.load_full() {
            if !refresh_due(&entry, now) {
                return Ok(entry.credentials.clone());
            }
        }

        // Single-flight. Whoever holds the lock refreshes; everyone else
        // re-reads the cache after it and finds the fresh value.
        let _guard = self.refresh_lock.lock().await;
        let existing = self.cached.load_full();
        if let Some(entry) = existing.as_ref() {
            if !refresh_due(entry, SystemTime::now()) {
                return Ok(entry.credentials.clone());
            }
        }

        match provider.provide_credentials().await {
            Ok(credentials) => {
                let entry = CachedCredentials {
                    credentials: credentials.clone(),
                    refresh_at: credentials
                        .expiry()
                        .and_then(|expiry| expiry.checked_sub(self.advisory)),
                    fail_at: credentials
                        .expiry()
                        .and_then(|expiry| expiry.checked_sub(self.mandatory)),
                };
                self.cached.store(Some(std::sync::Arc::new(entry)));
                Ok(credentials)
            }
            Err(error) => {
                // A refresh failure is only an outage once the cached
                // credential has crossed into the mandatory window.
                // Before that, keep serving and say so.
                if let Some(entry) = existing {
                    if !mandatory_due(&entry, SystemTime::now()) {
                        warn!(
                            region = %self.region,
                            service = %self.service,
                            error = %error,
                            "AWS credential refresh failed; the cached credential is still \
                             valid, so requests continue and the refresh is retried on the \
                             next one"
                        );
                        return Ok(entry.credentials.clone());
                    }
                }
                Err(AwsSigV4Error::Credentials {
                    source_kind: self.source_kind,
                    region: self.region.clone(),
                    service: self.service.clone(),
                    reason: error.to_string(),
                })
            }
        }
    }

    fn signing_error(&self, error: &dyn std::error::Error) -> AwsSigV4Error {
        AwsSigV4Error::Signing {
            region: self.region.clone(),
            service: self.service.clone(),
            reason: error.to_string(),
        }
    }
}

#[async_trait::async_trait]
impl crate::client::OutboundSigner for AwsSigV4Signer {
    fn scheme(&self) -> &'static str {
        "aws_sigv4"
    }

    async fn sign(&self, request: &mut reqwest::Request) -> anyhow::Result<()> {
        self.sign_request(request).await.map_err(anyhow::Error::new)
    }

    fn observe_response(
        &self,
        status: reqwest::StatusCode,
        headers: &reqwest::header::HeaderMap,
        round_trip: Duration,
    ) {
        self.record_response_timing(status, headers, round_trip);
    }
}

/// Whether the advisory refresh window has opened on a cached entry.
fn refresh_due(entry: &CachedCredentials, now: SystemTime) -> bool {
    match entry.refresh_at {
        None => false,
        Some(at) => now >= at,
    }
}

/// Whether the mandatory refresh window has opened, past which a
/// refresh failure has to fail the request.
fn mandatory_due(entry: &CachedCredentials, now: SystemTime) -> bool {
    match entry.fail_at {
        None => false,
        Some(at) => now >= at,
    }
}

/// Lowercase hex SHA-256, the payload-hash encoding the canonical
/// request specifies.
fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Construct the credential provider named by `credentials`.
async fn build_backing(
    region: &str,
    credentials: &AwsCredentialsConfig,
) -> Result<CredentialBacking, AwsSigV4Error> {
    let aws_region = aws_config::Region::new(region.to_string());
    match credentials.source {
        AwsCredentialSource::Static => {
            let access_key_id = credentials
                .access_key_id
                .as_deref()
                .map(str::trim)
                .unwrap_or_default();
            let secret = credentials
                .secret_access_key
                .as_ref()
                .map(ConfigSecret::expose)
                .unwrap_or_default();
            let session_token = credentials
                .session_token
                .as_ref()
                .map(|token| ConfigSecret::expose(token).to_string());
            Ok(CredentialBacking::Static(Credentials::new(
                access_key_id,
                secret,
                session_token,
                None,
                "sbproxy-ai-static",
            )))
        }
        AwsCredentialSource::DefaultChain => {
            let mut chain =
                aws_config::default_provider::credentials::DefaultCredentialsChain::builder()
                    .region(aws_region);
            if let Some(profile) = trimmed(credentials.profile.as_deref()) {
                chain = chain.profile_name(profile);
            }
            Ok(CredentialBacking::Provider(SharedCredentialsProvider::new(
                chain.build().await,
            )))
        }
        AwsCredentialSource::AssumeRole => {
            let role_arn = trimmed(credentials.role_arn.as_deref()).ok_or_else(|| {
                AwsSigV4Error::Config(
                    "`credentials.source: assume_role` requires `role_arn`".to_string(),
                )
            })?;
            let mut base = aws_config::defaults(aws_config::BehaviorVersion::latest())
                .region(aws_region.clone());
            if let Some(profile) = trimmed(credentials.profile.as_deref()) {
                base = base.profile_name(profile);
            }
            let base = base.load().await;
            let mut builder = aws_config::sts::AssumeRoleProvider::builder(role_arn)
                .region(aws_region)
                .session_name(trimmed(credentials.session_name.as_deref()).unwrap_or("sbproxy"))
                .configure(&base);
            if let Some(external_id) = credentials.external_id.as_ref() {
                if !external_id.is_empty() {
                    builder = builder.external_id(external_id.expose());
                }
            }
            if let Some(seconds) = credentials.session_duration_secs {
                builder = builder.session_length(Duration::from_secs(seconds));
            }
            Ok(CredentialBacking::Provider(SharedCredentialsProvider::new(
                builder.build().await,
            )))
        }
    }
}

/// A non-empty trimmed view of an optional configured string.
fn trimmed(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The example access key pair AWS publishes in its signing
    /// documentation. Not a credential: `AKIDEXAMPLE` is a documented
    /// placeholder that exists in every AWS SDK's test suite.
    const DOC_ACCESS_KEY_ID: &str = "AKIDEXAMPLE";
    const DOC_SECRET_ACCESS_KEY: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";

    /// `2015-08-30T12:36:00Z`, the timestamp of the worked example in
    /// AWS's "Create a signed AWS API request" documentation.
    const DOC_EPOCH_SECS: u64 = 1_440_938_160;
    /// `2026-01-01T00:00:00Z`, the timestamp of the Bedrock vectors.
    const BEDROCK_EPOCH_SECS: u64 = 1_767_225_600;

    /// The complete `Authorization` header AWS publishes for its
    /// `iam:ListUsers` worked example. Derived from the specification,
    /// not from this code: canonical request digest
    /// `f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59`
    /// over
    ///
    /// ```text
    /// GET
    /// /
    /// Action=ListUsers&Version=2010-05-08
    /// content-type:application/x-www-form-urlencoded; charset=utf-8
    /// host:iam.amazonaws.com
    /// x-amz-date:20150830T123600Z
    ///
    /// content-type;host;x-amz-date
    /// e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    /// ```
    const AWS_DOC_AUTHORIZATION: &str = "AWS4-HMAC-SHA256 \
Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, \
SignedHeaders=content-type;host;x-amz-date, \
Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7";

    /// A Bedrock `Converse` request signed under the same
    /// specification. The canonical request is
    ///
    /// ```text
    /// POST
    /// /model/anthropic.claude-3-5-sonnet-20241022-v2%3A0/converse
    ///
    /// content-type:application/json
    /// host:bedrock-runtime.us-east-1.amazonaws.com
    /// x-amz-date:20260101T000000Z
    ///
    /// content-type;host;x-amz-date
    /// 951c7e624de080b9f6191a29b31ae52e7c4ff7bf6febe7393f4fc09ba56832c8
    /// ```
    ///
    /// Note the `%3A`: the credential-scope canonicalization
    /// URI-encodes the already-encoded path a second time for every
    /// service except S3, so the colon in the Bedrock model ID is
    /// escaped in the canonical request and literal on the wire.
    const BEDROCK_AUTHORIZATION: &str = "AWS4-HMAC-SHA256 \
Credential=AKIDEXAMPLE/20260101/us-east-1/bedrock/aws4_request, \
SignedHeaders=content-type;host;x-amz-date, \
Signature=69bc46a45a526cfe15b5ef361667907b9eb218a76ea8adf9e1d61152894c5d58";

    /// The same request signed with a session token, which enters the
    /// canonical request as `x-amz-security-token` and therefore
    /// changes `SignedHeaders` as well as the signature.
    const BEDROCK_AUTHORIZATION_WITH_TOKEN: &str = "AWS4-HMAC-SHA256 \
Credential=AKIDEXAMPLE/20260101/us-east-1/bedrock/aws4_request, \
SignedHeaders=content-type;host;x-amz-date;x-amz-security-token, \
Signature=39f3b56128bdae161b422f03928bdfee8bd6befbd13672d138b6fb3f6d76e2c4";

    const SESSION_TOKEN: &str = "FQoGZXIvYXdzEXAMPLESESSIONTOKEN";

    const BEDROCK_URL: &str = "https://bedrock-runtime.us-east-1.amazonaws.com\
/model/anthropic.claude-3-5-sonnet-20241022-v2:0/converse";

    const CONVERSE_BODY: &[u8] =
        br#"{"messages":[{"role":"user","content":[{"text":"ping"}]}],"inferenceConfig":{"maxTokens":16}}"#;

    fn epoch(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn static_signer(region: &str, service: &str, session_token: Option<&str>) -> AwsSigV4Signer {
        AwsSigV4Signer {
            region: region.to_string(),
            service: service.to_string(),
            source_kind: AwsCredentialSource::Static.label(),
            backing: CredentialBacking::Static(Credentials::new(
                DOC_ACCESS_KEY_ID,
                DOC_SECRET_ACCESS_KEY,
                session_token.map(str::to_string),
                None,
                "test",
            )),
            cached: ArcSwapOption::empty(),
            refresh_lock: tokio::sync::Mutex::new(()),
            advisory: Duration::from_secs(DEFAULT_ADVISORY_REFRESH_SECS),
            mandatory: Duration::from_secs(MANDATORY_REFRESH_SECS),
            clock_offset_secs: AtomicI64::new(0),
            skew_warned: AtomicBool::new(false),
        }
    }

    fn bedrock_request() -> reqwest::Request {
        let mut request = reqwest::Request::new(
            reqwest::Method::POST,
            reqwest::Url::parse(BEDROCK_URL).expect("fixture URL parses"),
        );
        request.headers_mut().insert(
            reqwest::header::CONTENT_TYPE,
            reqwest::header::HeaderValue::from_static("application/json"),
        );
        *request.body_mut() = Some(reqwest::Body::from(CONVERSE_BODY.to_vec()));
        request
    }

    fn authorization(request: &reqwest::Request) -> String {
        request
            .headers()
            .get(reqwest::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string()
    }

    #[tokio::test]
    async fn signature_matches_the_aws_documented_worked_example() {
        // The whole point of this vector: the expected value is
        // published by AWS for this exact request, so agreeing with it
        // proves the canonicalization rather than proving that the code
        // agrees with itself.
        let signer = static_signer("us-east-1", "iam", None);
        let mut request = reqwest::Request::new(
            reqwest::Method::GET,
            reqwest::Url::parse("https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08")
                .expect("fixture URL parses"),
        );
        request.headers_mut().insert(
            reqwest::header::CONTENT_TYPE,
            reqwest::header::HeaderValue::from_static(
                "application/x-www-form-urlencoded; charset=utf-8",
            ),
        );
        signer
            .sign_request_at(&mut request, epoch(DOC_EPOCH_SECS))
            .await
            .expect("signing succeeds");
        assert_eq!(authorization(&request), AWS_DOC_AUTHORIZATION);
        assert_eq!(
            request
                .headers()
                .get("x-amz-date")
                .and_then(|v| v.to_str().ok()),
            Some("20150830T123600Z")
        );
    }

    #[tokio::test]
    async fn bedrock_converse_signature_matches_the_spec_derived_fixture() {
        let signer = static_signer("us-east-1", "bedrock", None);
        let mut request = bedrock_request();
        signer
            .sign_request_at(&mut request, epoch(BEDROCK_EPOCH_SECS))
            .await
            .expect("signing succeeds");
        assert_eq!(authorization(&request), BEDROCK_AUTHORIZATION);
        // The colon stays literal on the wire; only the canonical
        // request escapes it.
        assert!(request.url().path().contains("v2:0"));
    }

    #[tokio::test]
    async fn session_token_enters_the_canonical_request() {
        let signer = static_signer("us-east-1", "bedrock", Some(SESSION_TOKEN));
        let mut request = bedrock_request();
        signer
            .sign_request_at(&mut request, epoch(BEDROCK_EPOCH_SECS))
            .await
            .expect("signing succeeds");
        assert_eq!(authorization(&request), BEDROCK_AUTHORIZATION_WITH_TOKEN);
        assert_eq!(
            request
                .headers()
                .get("x-amz-security-token")
                .and_then(|v| v.to_str().ok()),
            Some(SESSION_TOKEN)
        );
    }

    #[tokio::test]
    async fn signing_is_idempotent_so_a_replayed_request_is_not_double_stamped() {
        // `send_governed` re-signs the same request object on a
        // same-origin redirect. Without stripping the headers this
        // scheme owns, the second canonical request would contain the
        // first attempt's `x-amz-date` and the signature would not
        // match what is sent.
        let signer = static_signer("us-east-1", "bedrock", Some(SESSION_TOKEN));
        let mut request = bedrock_request();
        signer
            .sign_request_at(&mut request, epoch(BEDROCK_EPOCH_SECS))
            .await
            .expect("first signing succeeds");
        signer
            .sign_request_at(&mut request, epoch(BEDROCK_EPOCH_SECS))
            .await
            .expect("second signing succeeds");
        assert_eq!(authorization(&request), BEDROCK_AUTHORIZATION_WITH_TOKEN);
    }

    #[tokio::test]
    async fn a_second_attempt_never_reuses_the_first_attempts_signature() {
        // The provider retry loop rebuilds the request per attempt, so
        // the signature is recomputed from a clean object. This pins the
        // stronger property, which holds even if some future caller
        // hands back a request that was already signed: a used request
        // signed at time T produces exactly what a fresh request signed
        // at time T produces, and a signature from an earlier attempt
        // never survives into a later one.
        let signer = static_signer("us-east-1", "bedrock", None);
        let first_attempt = epoch(BEDROCK_EPOCH_SECS);
        let second_attempt = epoch(BEDROCK_EPOCH_SECS + 60);

        let mut used = bedrock_request();
        signer
            .sign_request_at(&mut used, first_attempt)
            .await
            .expect("first attempt signs");
        let stale = authorization(&used);

        signer
            .sign_request_at(&mut used, second_attempt)
            .await
            .expect("second attempt signs");
        let retried = authorization(&used);

        let mut fresh = bedrock_request();
        signer
            .sign_request_at(&mut fresh, second_attempt)
            .await
            .expect("a fresh request signs");

        assert_ne!(stale, retried, "the second attempt gets its own signature");
        assert_eq!(
            retried,
            authorization(&fresh),
            "a replayed request must sign exactly as a freshly built one does"
        );
        assert_eq!(
            used.headers()
                .get("x-amz-date")
                .and_then(|v| v.to_str().ok()),
            Some("20260101T000100Z"),
            "the timestamp is the second attempt's, not the first's"
        );
    }

    #[tokio::test]
    async fn a_signature_is_bound_to_the_host_and_path() {
        let signer = static_signer("us-east-1", "bedrock", None);
        let mut request = bedrock_request();
        signer
            .sign_request_at(&mut request, epoch(BEDROCK_EPOCH_SECS))
            .await
            .expect("signing succeeds");
        let original = authorization(&request);

        let mut moved = bedrock_request();
        *moved.url_mut() = reqwest::Url::parse(
            "https://vpce-0123.bedrock-runtime.us-east-1.vpce.amazonaws.com\
/model/anthropic.claude-3-5-sonnet-20241022-v2:0/converse",
        )
        .expect("fixture URL parses");
        signer
            .sign_request_at(&mut moved, epoch(BEDROCK_EPOCH_SECS))
            .await
            .expect("signing succeeds");
        assert_ne!(
            original,
            authorization(&moved),
            "host is part of the canonical request, so a redirected hop must re-sign"
        );
    }

    #[tokio::test]
    async fn a_signature_is_bound_to_the_body_bytes() {
        let signer = static_signer("us-east-1", "bedrock", None);
        let mut request = bedrock_request();
        signer
            .sign_request_at(&mut request, epoch(BEDROCK_EPOCH_SECS))
            .await
            .expect("signing succeeds");
        let original = authorization(&request);

        let mut mutated = bedrock_request();
        *mutated.body_mut() = Some(reqwest::Body::from(
            br#"{"messages":[{"role":"user","content":[{"text":"pong"}]}],"inferenceConfig":{"maxTokens":16}}"#
                .to_vec(),
        ));
        signer
            .sign_request_at(&mut mutated, epoch(BEDROCK_EPOCH_SECS))
            .await
            .expect("signing succeeds");
        assert_ne!(
            original,
            authorization(&mutated),
            "the payload hash covers the body, so any later body mutation breaks the signature"
        );
    }

    #[tokio::test]
    async fn a_streaming_body_is_refused_rather_than_signed_unsigned() {
        let signer = static_signer("us-east-1", "bedrock", None);
        let mut request = bedrock_request();
        let stream = futures::stream::once(async {
            Ok::<_, std::io::Error>(bytes::Bytes::from_static(b"chunk"))
        });
        *request.body_mut() = Some(reqwest::Body::wrap_stream(stream));
        let error = signer
            .sign_request_at(&mut request, epoch(BEDROCK_EPOCH_SECS))
            .await
            .expect_err("an unbuffered body cannot be signed");
        assert!(matches!(error, AwsSigV4Error::UnbufferedBody));
        assert!(request
            .headers()
            .get(reqwest::header::AUTHORIZATION)
            .is_none());
    }

    #[test]
    fn config_secret_never_renders_its_value() {
        let secret = ConfigSecret(SecretString::new(DOC_SECRET_ACCESS_KEY));
        assert_eq!(format!("{secret:?}"), "[REDACTED]");
        let credentials = AwsCredentialsConfig {
            source: AwsCredentialSource::Static,
            access_key_id: Some(DOC_ACCESS_KEY_ID.to_string()),
            secret_access_key: Some(secret),
            session_token: Some(ConfigSecret(SecretString::new(SESSION_TOKEN))),
            external_id: Some(ConfigSecret(SecretString::new("external"))),
            ..AwsCredentialsConfig::default()
        };
        let rendered = format!("{credentials:?}");
        assert!(
            !rendered.contains(DOC_SECRET_ACCESS_KEY)
                && !rendered.contains(SESSION_TOKEN)
                && !rendered.contains("external"),
            "credential values must not survive a Debug render: {rendered}"
        );
    }

    #[test]
    fn signer_debug_never_renders_a_credential() {
        let signer = static_signer("us-east-1", "bedrock", Some(SESSION_TOKEN));
        let rendered = format!("{signer:?}");
        assert!(!rendered.contains(SESSION_TOKEN));
        assert!(!rendered.contains(DOC_SECRET_ACCESS_KEY));
    }

    fn config(yaml: &str) -> AwsSigV4Config {
        serde_yaml::from_str(yaml).expect("fixture config parses")
    }

    #[test]
    fn region_is_required_and_never_inferred() {
        let error = config("region: \"  \"")
            .validate("bedrock")
            .expect_err("a blank region is refused");
        assert!(format!("{error}").contains("`region` is required"));
    }

    #[test]
    fn service_defaults_from_the_provider_type() {
        assert_eq!(
            config("region: us-east-1")
                .resolved_service("bedrock")
                .expect("bedrock has a default"),
            "bedrock"
        );
        assert_eq!(
            config("region: us-east-1")
                .resolved_service("sagemaker")
                .expect("sagemaker has a default"),
            "sagemaker"
        );
        let error = config("region: us-east-1")
            .resolved_service("openai")
            .expect_err("a non-AWS provider type has no default");
        assert!(format!("{error}").contains("aws_sigv4.service"));
    }

    #[test]
    fn credential_sources_reject_the_fields_they_do_not_read() {
        let cases = [
            (
                "region: us-east-1\ncredentials:\n  source: static\n",
                "access_key_id",
            ),
            (
                "region: us-east-1\ncredentials:\n  source: assume_role\n",
                "role_arn",
            ),
            (
                "region: us-east-1\ncredentials:\n  source: default_chain\n  access_key_id: AKIDEXAMPLE\n",
                "default_chain",
            ),
            (
                "region: us-east-1\ncredentials:\n  source: assume_role\n  role_arn: arn:aws:iam::1:role/r\n  access_key_id: AKIDEXAMPLE\n",
                "default credential chain",
            ),
        ];
        for (yaml, needle) in cases {
            let error = config(yaml)
                .validate("bedrock")
                .expect_err("the block names a field its source does not read");
            let rendered = format!("{error}");
            assert!(
                rendered.contains(needle),
                "expected {needle:?} in the refusal, got {rendered}"
            );
        }
    }

    #[test]
    fn a_complete_static_block_and_a_complete_assume_role_block_both_validate() {
        config("region: us-east-1\ncredentials:\n  source: static\n  access_key_id: AKIDEXAMPLE\n  secret_access_key: shh\n")
            .validate("bedrock")
            .expect("a complete static block is accepted");
        config("region: us-east-1\ncredentials:\n  source: assume_role\n  role_arn: arn:aws:iam::1:role/r\n  external_id: shh\n")
            .validate("sagemaker")
            .expect("a complete assume_role block is accepted");
        config("region: us-east-1")
            .validate("bedrock")
            .expect("the bare block is accepted");
    }

    #[test]
    fn a_refresh_margin_inside_the_mandatory_window_is_refused() {
        let error = config("region: us-east-1\nrefresh_margin_secs: 60")
            .validate("bedrock")
            .expect_err("a margin below the mandatory window is refused");
        assert!(format!("{error}").contains("refresh_margin_secs"));
    }

    #[test]
    fn the_default_credential_source_is_the_aws_chain() {
        let parsed = config("region: us-east-1");
        assert!(parsed.credentials.is_none());
        assert_eq!(
            AwsCredentialsConfig::default().source,
            AwsCredentialSource::DefaultChain
        );
        assert_eq!(AwsCredentialSource::DefaultChain.label(), "default_chain");
    }

    #[test]
    fn refresh_windows_follow_the_botocore_two_tier_rule() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);
        let entry = |remaining: u64| CachedCredentials {
            credentials: Credentials::new(
                "a",
                "b",
                None,
                Some(now + Duration::from_secs(remaining)),
                "t",
            ),
            refresh_at: (now + Duration::from_secs(remaining))
                .checked_sub(Duration::from_secs(DEFAULT_ADVISORY_REFRESH_SECS)),
            fail_at: (now + Duration::from_secs(remaining))
                .checked_sub(Duration::from_secs(MANDATORY_REFRESH_SECS)),
        };
        // Comfortably valid: no refresh, no failure.
        assert!(!refresh_due(&entry(1800), now));
        assert!(!mandatory_due(&entry(1800), now));
        // Inside the advisory window only: refresh, but a failure is
        // survivable because the credential still works.
        assert!(refresh_due(&entry(800), now));
        assert!(!mandatory_due(&entry(800), now));
        // Inside the mandatory window: a failed refresh has to fail the
        // request.
        assert!(refresh_due(&entry(300), now));
        assert!(mandatory_due(&entry(300), now));
        // A credential with no expiry is never refreshed.
        let forever = CachedCredentials {
            credentials: Credentials::new("a", "b", None, None, "t"),
            refresh_at: None,
            fail_at: None,
        };
        assert!(!refresh_due(&forever, now));
        assert!(!mandatory_due(&forever, now));
    }

    #[test]
    fn clock_skew_is_measured_from_the_date_header_and_bounded() {
        let signer = static_signer("us-east-1", "bedrock", None);
        let mut headers = reqwest::header::HeaderMap::new();
        // A Date far in the future relative to any real clock.
        headers.insert(
            reqwest::header::DATE,
            reqwest::header::HeaderValue::from_static("Fri, 01 Jan 2100 00:00:00 GMT"),
        );
        signer.record_response_timing(
            reqwest::StatusCode::FORBIDDEN,
            &headers,
            Duration::from_millis(50),
        );
        assert_eq!(
            signer.clock_offset_secs.load(Ordering::Relaxed),
            MAX_CLOCK_CORRECTION_SECS,
            "an absurd Date must be clamped, never applied verbatim"
        );

        // A success says nothing about the clock and must not move it.
        let fresh = static_signer("us-east-1", "bedrock", None);
        fresh.record_response_timing(reqwest::StatusCode::OK, &headers, Duration::from_millis(50));
        assert_eq!(fresh.clock_offset_secs.load(Ordering::Relaxed), 0);

        // A cached response's Date is not evidence about the origin.
        let cached = static_signer("us-east-1", "bedrock", None);
        let mut cached_headers = headers.clone();
        cached_headers.insert(
            reqwest::header::AGE,
            reqwest::header::HeaderValue::from_static("120"),
        );
        cached.record_response_timing(
            reqwest::StatusCode::FORBIDDEN,
            &cached_headers,
            Duration::from_millis(50),
        );
        assert_eq!(cached.clock_offset_secs.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn a_measured_skew_shifts_the_signature_timestamp() {
        let signer = static_signer("us-east-1", "bedrock", None);
        signer.clock_offset_secs.store(600, Ordering::Relaxed);
        let corrected = signer.signing_time();
        let uncorrected = SystemTime::now();
        let delta = corrected
            .duration_since(uncorrected)
            .expect("a positive offset moves the clock forward");
        assert!(delta >= Duration::from_secs(590) && delta <= Duration::from_secs(610));
    }
}
