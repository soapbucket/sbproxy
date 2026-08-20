//! WOR-2519: `ldap_auth` provider, directory-bind authentication.
//!
//! The client presents HTTP Basic credentials; the provider composes a
//! bind DN from a configured attribute plus `base_dn` and attempts an
//! LDAP simple bind against the directory with the supplied password.
//! The bind result is the only signal used: the password is never
//! stored, never forwarded upstream, and never logged.
//!
//! # Bind model
//!
//! This is the direct-bind (DN template) model used by Apache APISIX's
//! `ldap-auth` plugin: DN = `<uid_attribute>=<username>,<base_dn>`,
//! with `uid_attribute` defaulting to `cn`. The alternative
//! search-then-bind model (bind as a service account, search for the
//! user's entry by filter, then bind as the found DN), used by nginx's
//! LDAP auth reference implementation and by most IdP LDAP federation
//! backends, supports directories whose login attribute is not part of
//! the entry DN, but requires managing a standing service-account
//! credential and doubles the round-trips per request. Direct bind
//! covers the confirmed target deployments and keeps this provider
//! credential-free at rest; search-then-bind can be added later as an
//! additive config shape without breaking this one.
//!
//! # Security posture
//!
//! * A plaintext `ldap://` URL without StartTLS is refused at config
//!   load unless `allow_insecure: true` is set explicitly. The refusal
//!   is the default because a simple bind transmits the password in
//!   the clear (RFC 4513 section 6.3.1 calls out this exposure).
//! * An empty password is refused before any dial. RFC 4513 section
//!   5.1.2 defines a name-plus-empty-password simple bind as an
//!   *unauthenticated* bind, which directories commonly accept with a
//!   success result code; treating that success as proof of identity
//!   is the classic LDAP auth bypass.
//! * The username is escaped per RFC 4514 before DN composition so a
//!   crafted username cannot splice additional RDNs (for example
//!   `alice,cn=admin`) into the bind DN.
//! * Directory unreachable fails closed: the caller maps it to a
//!   refusal, never an allow. This provider adds a network round-trip
//!   to the request hot path (unlike every other built-in auth type
//!   except `forward_auth`); the deliberate decision recorded on
//!   WOR-2519 is to accept that latency rather than cache bind
//!   results, because a bind-result cache is a password-equivalence
//!   cache: it would extend a credential's validity past a
//!   directory-side revocation or password change.

use std::time::Duration;

use base64::Engine as _;
use serde::Deserialize;
use tracing::{debug, warn};

/// Default seconds allowed for the connect + bind exchange.
pub const DEFAULT_LDAP_TIMEOUT_SECS: u64 = 5;

/// Default directory attribute the username is matched against when
/// composing the bind DN. `cn` mirrors Apache APISIX's `ldap-auth`
/// default for the same knob.
pub const DEFAULT_UID_ATTRIBUTE: &str = "cn";

/// Outcome of one directory-bind authentication attempt.
///
/// The variants separate the axes the caller must not conflate: a
/// caller that offered no credentials is neutral, a caller whose
/// credentials the directory refused offered an invalid proof, and a
/// directory that could not be consulted is a backend failure that
/// must fail closed (refuse, never allow).
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LdapBindOutcome {
    /// The directory accepted the bind. `username` is the value that
    /// was matched against `uid_attribute`, surfaced so the caller can
    /// stamp it as the authenticated subject.
    Allowed {
        /// Username the directory authenticated (the client-supplied
        /// Basic username, post-validation).
        username: String,
    },
    /// The request carried no decodable `Authorization: Basic` header.
    NoCredentials,
    /// Credentials were offered and refused: wrong password, unknown
    /// user, a username the DN cannot be composed from, or an empty
    /// password (refused locally per RFC 4513 section 5.1.2 without
    /// consulting the directory).
    InvalidCredentials,
    /// The directory could not be consulted: dial failure, timeout,
    /// TLS failure, or a directory-side result code that is not an
    /// authentication verdict. Callers must refuse the request.
    DirectoryUnavailable,
}

/// LDAP directory-bind authentication provider (`type: ldap_auth`).
///
/// See the module docs for the bind model and the security posture.
#[derive(Debug, Clone)]
pub struct LdapAuthProvider {
    /// Directory URL: `ldap://host[:port]` or `ldaps://host[:port]`.
    pub url: String,
    /// Base DN appended to the composed RDN, for example
    /// `ou=users,dc=example,dc=org`.
    pub base_dn: String,
    /// Attribute the username is bound under when composing the DN.
    /// Defaults to [`DEFAULT_UID_ATTRIBUTE`].
    pub uid_attribute: String,
    /// Upgrade an `ldap://` connection with StartTLS before the bind.
    /// Invalid together with an `ldaps://` URL (implicit TLS and
    /// StartTLS are mutually exclusive on one connection).
    pub use_tls: bool,
    /// Verify the directory's TLS certificate (default `true`). When
    /// verification is on, the URL host must match the certificate,
    /// the same caveat APISIX documents for its `tls_verify` knob.
    pub tls_verify: bool,
    /// Accept a plaintext `ldap://` connection with no StartTLS.
    /// Default `false`: the config is refused at load time instead.
    pub allow_insecure: bool,
    /// Deadline in seconds for the whole connect + bind exchange.
    /// Defaults to [`DEFAULT_LDAP_TIMEOUT_SECS`].
    pub timeout_secs: u64,
}

/// Serde shape for [`LdapAuthProvider::from_config`]. Kept separate so
/// validation runs after deserialization and every refusal names the
/// offending field.
#[derive(Deserialize)]
struct RawLdapConfig {
    url: String,
    base_dn: String,
    #[serde(default)]
    uid_attribute: Option<String>,
    #[serde(default)]
    use_tls: bool,
    #[serde(default = "default_tls_verify")]
    tls_verify: bool,
    #[serde(default)]
    allow_insecure: bool,
    #[serde(default)]
    timeout_secs: Option<u64>,
}

fn default_tls_verify() -> bool {
    true
}

impl LdapAuthProvider {
    /// Build an `LdapAuthProvider` from a generic JSON config value,
    /// refusing insecure or contradictory shapes at load time:
    ///
    /// * URL scheme must be `ldap` or `ldaps`.
    /// * `ldap://` with neither `use_tls: true` (StartTLS) nor an
    ///   explicit `allow_insecure: true` is refused.
    /// * `ldaps://` together with `use_tls: true` is refused as
    ///   contradictory.
    /// * `base_dn` must be non-empty; `uid_attribute` must be a valid
    ///   LDAP attribute descriptor (RFC 4512 section 2.5) so the
    ///   composed DN stays well-formed.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        let raw: RawLdapConfig = serde_json::from_value(value)?;

        let parsed = url::Url::parse(&raw.url)
            .map_err(|e| anyhow::anyhow!("ldap_auth: invalid url: {e}"))?;
        let scheme = parsed.scheme();
        if scheme != "ldap" && scheme != "ldaps" {
            anyhow::bail!("ldap_auth: url scheme must be ldap:// or ldaps:// (got {scheme}://)");
        }
        if parsed.host_str().is_none() {
            anyhow::bail!("ldap_auth: url has no host");
        }
        if scheme == "ldaps" && raw.use_tls {
            anyhow::bail!(
                "ldap_auth: use_tls (StartTLS) cannot be combined with an ldaps:// url; \
                 pick one TLS mode"
            );
        }
        if scheme == "ldap" && !raw.use_tls && !raw.allow_insecure {
            anyhow::bail!(
                "ldap_auth: refusing plaintext ldap:// without StartTLS; a simple bind \
                 sends the password in the clear. Set `use_tls: true` (StartTLS), use an \
                 ldaps:// url, or set `allow_insecure: true` to accept the exposure \
                 explicitly"
            );
        }

        if raw.base_dn.trim().is_empty() {
            anyhow::bail!("ldap_auth: base_dn must be non-empty");
        }

        let uid_attribute = raw
            .uid_attribute
            .unwrap_or_else(|| DEFAULT_UID_ATTRIBUTE.to_string());
        if !is_valid_attribute_descriptor(&uid_attribute) {
            anyhow::bail!(
                "ldap_auth: uid_attribute {uid_attribute:?} is not a valid LDAP attribute \
                 descriptor (RFC 4512 section 2.5: leading letter, then letters, digits, \
                 or hyphens)"
            );
        }

        Ok(Self {
            url: raw.url,
            base_dn: raw.base_dn,
            uid_attribute,
            use_tls: raw.use_tls,
            tls_verify: raw.tls_verify,
            allow_insecure: raw.allow_insecure,
            timeout_secs: raw.timeout_secs.unwrap_or(DEFAULT_LDAP_TIMEOUT_SECS),
        })
    }

    /// Compose the bind DN for `username`, escaping the attribute
    /// value per RFC 4514 so a crafted username cannot splice extra
    /// RDNs into the DN.
    pub fn bind_dn(&self, username: &str) -> String {
        format!(
            "{}={},{}",
            self.uid_attribute,
            ldap3::dn_escape(username),
            self.base_dn
        )
    }

    /// Authenticate one request by binding its HTTP Basic credentials
    /// against the directory.
    ///
    /// This is the one built-in auth check besides `forward_auth` that
    /// dials out on the request hot path. Like `forward_auth`'s
    /// subrequest (and unlike egress-authorized purposes such as token
    /// exchange), the dial goes straight to the operator-configured
    /// endpoint under a config-scoped deadline; the URL is validated
    /// at config load, not per request.
    ///
    /// Never logs the password. The bind DN (which contains only the
    /// username and operator config) is logged at debug on refusals.
    pub async fn authenticate(&self, headers: &http::HeaderMap) -> LdapBindOutcome {
        let Some((username, password)) = basic_credentials(headers) else {
            return LdapBindOutcome::NoCredentials;
        };
        if username.is_empty() {
            return LdapBindOutcome::InvalidCredentials;
        }
        if password.is_empty() {
            // RFC 4513 section 5.1.2: a simple bind with a name and an
            // empty password is an *unauthenticated* bind, and
            // directories commonly answer it with success. Refuse
            // locally so that success can never be mistaken for a
            // verified credential.
            debug!(
                username = %username,
                "ldap_auth: refusing empty password (would be an unauthenticated bind)"
            );
            return LdapBindOutcome::InvalidCredentials;
        }

        let bind_dn = self.bind_dn(&username);
        let deadline = Duration::from_secs(self.timeout_secs.max(1));
        match tokio::time::timeout(deadline, self.simple_bind(&bind_dn, &password)).await {
            Err(_elapsed) => {
                warn!(url = %self.url, "ldap_auth: directory bind timed out; refusing");
                LdapBindOutcome::DirectoryUnavailable
            }
            Ok(Err(err)) => {
                // Transport-level failure (dial refused, TLS failure,
                // stream error). The error text never contains the
                // password: it is not interpolated anywhere on this
                // path and the ldap3 error types carry protocol state
                // only.
                warn!(url = %self.url, error = %err, "ldap_auth: directory unreachable; refusing");
                LdapBindOutcome::DirectoryUnavailable
            }
            Ok(Ok(rc)) => match rc {
                0 => LdapBindOutcome::Allowed { username },
                // RFC 4511 appendix A result codes attributable to the
                // presented credential: invalidCredentials(49),
                // noSuchObject(32) for an unknown user's DN, and
                // invalidDNSyntax(34) for a username the DN cannot be
                // composed from.
                49 | 32 | 34 => {
                    debug!(bind_dn = %bind_dn, result_code = rc, "ldap_auth: bind refused");
                    LdapBindOutcome::InvalidCredentials
                }
                // Anything else (unwillingToPerform, busy, unavailable,
                // strongerAuthRequired, ...) is a directory-side
                // condition, not a verdict on the credential. Fail
                // closed without blaming the caller.
                other => {
                    warn!(
                        url = %self.url,
                        result_code = other,
                        "ldap_auth: directory returned a non-auth result code; refusing"
                    );
                    LdapBindOutcome::DirectoryUnavailable
                }
            },
        }
    }

    /// Dial the directory and perform one simple bind, returning the
    /// LDAP result code. TLS (ldaps or StartTLS) rides the workspace
    /// rustls stack via the `ldap3` crate's `tls-rustls-ring` feature.
    async fn simple_bind(&self, bind_dn: &str, password: &str) -> Result<u32, ldap3::LdapError> {
        let mut settings = ldap3::LdapConnSettings::new()
            .set_conn_timeout(Duration::from_secs(self.timeout_secs.max(1)));
        if self.use_tls {
            settings = settings.set_starttls(true);
        }
        if !self.tls_verify {
            settings = settings.set_no_tls_verify(true);
        }
        let (conn, mut ldap) = ldap3::LdapConnAsync::with_settings(settings, &self.url).await?;
        ldap3::drive!(conn);
        let result = ldap.simple_bind(bind_dn, password).await?;
        // Result observed; the unbind is a courtesy notice and its
        // failure carries no signal.
        let _ = ldap.unbind().await;
        Ok(result.rc)
    }
}

/// RFC 4512 section 2.5 attribute descriptor: a leading ALPHA followed
/// by ALPHA / DIGIT / HYPHEN. Enforced on `uid_attribute` so operator
/// config cannot produce a malformed DN.
fn is_valid_attribute_descriptor(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// Decode `Authorization: Basic <base64>` into `(username, password)`.
/// Mirrors the `basic_auth` provider's parsing: standard base64, split
/// on the first `:`.
fn basic_credentials(headers: &http::HeaderMap) -> Option<(String, String)> {
    let auth_value = headers
        .get(http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())?;
    let encoded = auth_value.strip_prefix("Basic ")?;
    let decoded_bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    let decoded = std::str::from_utf8(&decoded_bytes).ok()?;
    let (username, password) = decoded.split_once(':')?;
    Some((username.to_string(), password.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Config-load validation ---

    fn base_config() -> serde_json::Value {
        serde_json::json!({
            "type": "ldap_auth",
            "url": "ldaps://directory.example.org:636",
            "base_dn": "ou=users,dc=example,dc=org",
        })
    }

    #[test]
    fn secure_ldaps_config_loads_with_defaults() {
        let p = LdapAuthProvider::from_config(base_config()).unwrap();
        assert_eq!(p.uid_attribute, "cn");
        assert!(p.tls_verify);
        assert!(!p.allow_insecure);
        assert_eq!(p.timeout_secs, DEFAULT_LDAP_TIMEOUT_SECS);
    }

    /// WOR-2519 acceptance: a plaintext ldap:// URL is refused at
    /// config load unless the operator opts in explicitly.
    #[test]
    fn insecure_ldap_url_refused_at_config_load() {
        let mut cfg = base_config();
        cfg["url"] = "ldap://directory.example.org:389".into();
        let err = LdapAuthProvider::from_config(cfg).unwrap_err();
        assert!(
            err.to_string().contains("allow_insecure"),
            "refusal must name the opt-out flag: {err}"
        );
    }

    #[test]
    fn insecure_ldap_url_accepted_with_explicit_flag() {
        let mut cfg = base_config();
        cfg["url"] = "ldap://directory.example.org:389".into();
        cfg["allow_insecure"] = true.into();
        let p = LdapAuthProvider::from_config(cfg).unwrap();
        assert!(p.allow_insecure);
    }

    #[test]
    fn starttls_ldap_url_accepted_without_flag() {
        let mut cfg = base_config();
        cfg["url"] = "ldap://directory.example.org:389".into();
        cfg["use_tls"] = true.into();
        let p = LdapAuthProvider::from_config(cfg).unwrap();
        assert!(p.use_tls);
        assert!(!p.allow_insecure);
    }

    #[test]
    fn ldaps_with_starttls_refused_as_contradictory() {
        let mut cfg = base_config();
        cfg["use_tls"] = true.into();
        let err = LdapAuthProvider::from_config(cfg).unwrap_err();
        assert!(err.to_string().contains("StartTLS"), "{err}");
    }

    #[test]
    fn non_ldap_scheme_refused() {
        let mut cfg = base_config();
        cfg["url"] = "https://directory.example.org".into();
        assert!(LdapAuthProvider::from_config(cfg).is_err());
    }

    #[test]
    fn empty_base_dn_refused() {
        let mut cfg = base_config();
        cfg["base_dn"] = "  ".into();
        assert!(LdapAuthProvider::from_config(cfg).is_err());
    }

    #[test]
    fn malformed_uid_attribute_refused() {
        let mut cfg = base_config();
        cfg["uid_attribute"] = "cn=admin,ou".into();
        assert!(LdapAuthProvider::from_config(cfg).is_err());
    }

    // --- DN composition ---

    /// A username carrying RDN separators is escaped, not spliced.
    #[test]
    fn bind_dn_escapes_rdn_splicing_username() {
        let p = LdapAuthProvider::from_config({
            let mut cfg = base_config();
            cfg["uid_attribute"] = "uid".into();
            cfg
        })
        .unwrap();
        let dn = p.bind_dn("alice,cn=admin");
        assert_eq!(dn, "uid=alice\\2ccn\\3dadmin,ou=users,dc=example,dc=org");
    }

    // --- Bind behavior against a scripted in-process directory ---

    /// Minimal in-process LDAP listener speaking just enough BER to
    /// answer one simple bind: it parses the bind request's message
    /// id, DN, and password, and answers success only for the
    /// constructor's expected pair. Everything else gets
    /// invalidCredentials(49). Runs over plaintext, so the provider
    /// under test uses `allow_insecure: true`; TLS configuration is
    /// covered by the config-load tests above.
    struct ScriptedDirectory {
        port: u16,
        handle: tokio::task::JoinHandle<()>,
    }

    impl ScriptedDirectory {
        async fn start(expected_dn: &str, expected_password: &str) -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let expected_dn = expected_dn.to_string();
            let expected_password = expected_password.to_string();
            let handle = tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buf = vec![0u8; 4096];
                let n = stream.read(&mut buf).await.unwrap();
                let (msgid, dn, password) = parse_simple_bind(&buf[..n]).expect("bind request");
                let rc = if dn == expected_dn && password == expected_password {
                    0u8
                } else {
                    49u8
                };
                let response = [
                    0x30, 0x0c, // LDAPMessage SEQUENCE
                    0x02, 0x01, msgid, // messageID
                    0x61, 0x07, // [APPLICATION 1] BindResponse
                    0x0a, 0x01, rc, // resultCode
                    0x04, 0x00, // matchedDN ""
                    0x04, 0x00, // diagnosticMessage ""
                ];
                stream.write_all(&response).await.unwrap();
                // Drain the client's unbind notice until it hangs up.
                let _ = stream.read(&mut buf).await;
            });
            Self { port, handle }
        }
    }

    impl Drop for ScriptedDirectory {
        fn drop(&mut self) {
            self.handle.abort();
        }
    }

    /// Parse `(message id, bind DN, simple password)` out of an LDAP
    /// simple BindRequest. Short-form BER lengths only, which holds
    /// for the small DNs these tests send.
    fn parse_simple_bind(bytes: &[u8]) -> Option<(u8, String, String)> {
        // Outer: 0x30 <len>, then messageID: 0x02 0x01 <id>.
        if bytes.len() < 9 || bytes[0] != 0x30 || bytes[2] != 0x02 || bytes[3] != 0x01 {
            return None;
        }
        let msgid = bytes[4];
        // BindRequest: 0x60 <len>, version: 0x02 0x01 0x03.
        if bytes[5] != 0x60 || bytes[7] != 0x02 || bytes[8] != 0x01 {
            return None;
        }
        // name: 0x04 <len> <dn>.
        let mut i = 10;
        if bytes.get(i)? != &0x04 {
            return None;
        }
        let dn_len = *bytes.get(i + 1)? as usize;
        let dn = String::from_utf8(bytes.get(i + 2..i + 2 + dn_len)?.to_vec()).ok()?;
        i += 2 + dn_len;
        // authentication simple: context tag 0x80 <len> <password>.
        if bytes.get(i)? != &0x80 {
            return None;
        }
        let pw_len = *bytes.get(i + 1)? as usize;
        let password = String::from_utf8(bytes.get(i + 2..i + 2 + pw_len)?.to_vec()).ok()?;
        Some((msgid, dn, password))
    }

    fn provider_for_port(port: u16) -> LdapAuthProvider {
        LdapAuthProvider::from_config(serde_json::json!({
            "type": "ldap_auth",
            "url": format!("ldap://127.0.0.1:{port}"),
            "base_dn": "ou=users,dc=example,dc=org",
            "allow_insecure": true,
            "timeout_secs": 2,
        }))
        .unwrap()
    }

    fn basic_header(username: &str, password: &str) -> http::HeaderMap {
        let mut headers = http::HeaderMap::new();
        let encoded =
            base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"));
        headers.insert(
            http::header::AUTHORIZATION,
            format!("Basic {encoded}").parse().unwrap(),
        );
        headers
    }

    /// WOR-2519 acceptance: a good bind authenticates and surfaces the
    /// username for attribution.
    #[tokio::test]
    async fn good_bind_authenticates_with_attribution() {
        let dir = ScriptedDirectory::start("cn=alice,ou=users,dc=example,dc=org", "s3cret").await;
        let provider = provider_for_port(dir.port);
        let outcome = provider
            .authenticate(&basic_header("alice", "s3cret"))
            .await;
        assert_eq!(
            outcome,
            LdapBindOutcome::Allowed {
                username: "alice".to_string()
            }
        );
    }

    /// WOR-2519 acceptance: a bad password is refused.
    #[tokio::test]
    async fn bad_password_refused() {
        let dir = ScriptedDirectory::start("cn=alice,ou=users,dc=example,dc=org", "s3cret").await;
        let provider = provider_for_port(dir.port);
        let outcome = provider.authenticate(&basic_header("alice", "wrong")).await;
        assert_eq!(outcome, LdapBindOutcome::InvalidCredentials);
    }

    /// WOR-2519 acceptance: an unreachable directory refuses; it never
    /// allows. The port comes from a listener that is bound and then
    /// dropped, so nothing answers.
    #[tokio::test]
    async fn unreachable_directory_refuses() {
        let port = {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            listener.local_addr().unwrap().port()
        };
        let provider = provider_for_port(port);
        let outcome = provider
            .authenticate(&basic_header("alice", "s3cret"))
            .await;
        assert_eq!(outcome, LdapBindOutcome::DirectoryUnavailable);
    }

    /// RFC 4513 section 5.1.2: an empty password must be refused
    /// locally. The scripted directory here would answer *success* for
    /// the empty password, so this test is red if the guard is
    /// missing: the bypass would authenticate.
    #[tokio::test]
    async fn empty_password_refused_without_trusting_the_directory() {
        let dir = ScriptedDirectory::start("cn=alice,ou=users,dc=example,dc=org", "").await;
        let provider = provider_for_port(dir.port);
        let outcome = provider.authenticate(&basic_header("alice", "")).await;
        assert_eq!(outcome, LdapBindOutcome::InvalidCredentials);
    }

    #[tokio::test]
    async fn missing_credentials_is_no_credentials() {
        let provider = provider_for_port(1);
        let outcome = provider.authenticate(&http::HeaderMap::new()).await;
        assert_eq!(outcome, LdapBindOutcome::NoCredentials);
    }

    /// The DN the directory sees for a splicing username is the
    /// escaped one, end to end through the real client encoding.
    #[tokio::test]
    async fn spliced_username_reaches_directory_escaped() {
        let dir = ScriptedDirectory::start(
            "cn=alice\\2ccn\\3dadmin,ou=users,dc=example,dc=org",
            "s3cret",
        )
        .await;
        let provider = provider_for_port(dir.port);
        let outcome = provider
            .authenticate(&basic_header("alice,cn=admin", "s3cret"))
            .await;
        // The scripted directory only answers success when the DN it
        // parsed off the wire equals the escaped form.
        assert_eq!(
            outcome,
            LdapBindOutcome::Allowed {
                username: "alice,cn=admin".to_string()
            }
        );
    }
}
