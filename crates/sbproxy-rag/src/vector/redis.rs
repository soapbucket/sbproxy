//! Redis vector store adapter speaking `FT.SEARCH` dialect 2.
//!
//! The adapter accepts only `redis://` and `rediss://` URLs with no
//! userinfo, query, or fragment; credentials travel exclusively through
//! the separate `username` and `password` fields. DNS is never a
//! startup-only check: a `ProtectedRedisResolver` installed on the
//! connection revalidates every resolved address against the protected
//! address policy on every dial, including reconnects. For `rediss://`
//! the redis connector keeps the configured hostname for TLS server
//! name indication and certificate verification while dialing only the
//! pinned, validated addresses.
//!
//! One `redis::Client` is built at construction time and a multiplexed
//! connection is created lazily on the first search and cached. On an
//! I/O, closed-connection, or timeout error the cached connection is
//! discarded so the next search reconnects, which resolves and
//! revalidates DNS again. The cache slot carries a generation and a
//! discard only evicts the generation that actually failed, so a late
//! failure on a long-dead socket cannot throw away the replacement a
//! concurrent search already dialed. Construction never connects, which
//! keeps validation-mode builds free of network activity.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use redis::aio::MultiplexedConnection;
use redis::io::AsyncDNSResolver;
use redis::{AsyncConnectionConfig, ConnectionAddr, ConnectionInfo, RedisConnectionInfo};

use sbproxy_ai::rag_config::{
    RagDistanceMetric, RagVectorStoreConfig, MAX_PROVIDER_RESPONSE_BYTES,
};

use crate::vector::{is_safe_identifier, score_from_cosine_distance};
use crate::{
    RagBuildError, RagBuildMode, RetrievedChunk, VectorQuery, VectorStore, VectorStoreError,
};

/// Future returned by a [`HostResolver`] lookup.
///
/// The error string is internal plumbing only; it is never copied into
/// a returned [`VectorStoreError`].
pub type HostResolverFuture = Pin<Box<dyn Future<Output = Result<Vec<SocketAddr>, String>> + Send>>;

/// Injectable DNS lookup seam.
///
/// Production resolves through `sbproxy_security::ssrf::resolve_host_addrs`
/// (Tokio DNS with a bounded lookup); the reconnect contract tests
/// substitute scripted answers.
pub type HostResolver = Arc<dyn Fn(&str, u16) -> HostResolverFuture + Send + Sync>;

/// Injectable protected-address policy.
///
/// Returns `true` when the resolved address is forbidden. Production
/// wraps `sbproxy_security::is_private_ip`, the same policy
/// `validate_url_resolved` applies to the HTTP providers.
pub type AddressPolicy = Arc<dyn Fn(&SocketAddr) -> bool + Send + Sync>;

/// DNS resolver that revalidates every answer on every resolution.
///
/// Empty answer sets are rejected, and unless the store was configured
/// with `allow_private_url` a single forbidden answer rejects the whole
/// set, so a rebinding DNS record cannot steer a reconnect at a
/// protected address.
struct ProtectedRedisResolver {
    resolve_host: HostResolver,
    is_forbidden: AddressPolicy,
    allow_private: bool,
    note: Arc<parking_lot::Mutex<Option<&'static str>>>,
}

impl ProtectedRedisResolver {
    /// Records the non-secret failure class for the connect path and
    /// returns the matching redis error.
    fn fail(&self, reason: &'static str) -> redis::RedisError {
        *self.note.lock() = Some(reason);
        redis::RedisError::from((redis::ErrorKind::InvalidClientConfig, reason))
    }
}

impl AsyncDNSResolver for ProtectedRedisResolver {
    fn resolve<'a, 'b: 'a>(
        &'a self,
        host: &'b str,
        port: u16,
    ) -> redis::RedisFuture<'a, Box<dyn Iterator<Item = SocketAddr> + Send + 'a>> {
        let lookup = (self.resolve_host)(host, port);
        Box::pin(async move {
            let addrs = lookup
                .await
                .map_err(|_| self.fail("redis endpoint dns resolution failed"))?;
            if addrs.is_empty() {
                return Err(self.fail("redis endpoint resolved to no addresses"));
            }
            if !self.allow_private && addrs.iter().any(|addr| (self.is_forbidden)(addr)) {
                return Err(self.fail("redis endpoint resolved to a forbidden address"));
            }
            Ok(Box::new(addrs.into_iter()) as Box<dyn Iterator<Item = SocketAddr> + Send>)
        })
    }
}

/// Escapes a value for use inside a Redis tag filter.
///
/// Every ASCII character that is not alphanumeric or an underscore is
/// prefixed with a backslash, so query metacharacters such as `-`,
/// space, `|`, `{`, `}`, `\`, and `@` stay inside the tag value.
#[doc(hidden)]
pub fn escape_redis_tag(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_ascii() && !character.is_ascii_alphanumeric() && character != '_' {
            escaped.push('\\');
        }
        escaped.push(character);
    }
    escaped
}

/// The cached multiplexed connection and the generation naming it.
///
/// A caller carries the generation of the connection its command ran on
/// and hands it back when discarding, so a discard evicts only the
/// connection that actually failed.
///
/// Without the tag every discard cleared the slot unconditionally. Two
/// searches sharing a socket that Redis then dropped would each discard
/// on failure, and because their failures do not land together the
/// straggler evicted whatever a search in between had already dialed.
/// Under sustained traffic against a flapping Redis every late failure
/// threw away a healthy connection, so the store re-dialed (and re-ran
/// the protected DNS resolution) far more often than the outage
/// justified and could fail to settle on a connection at all.
#[derive(Default)]
struct ConnectionSlot {
    /// The live connection: absent before the first dial and after a
    /// discard.
    current: Option<MultiplexedConnection>,
    /// Names `current`. Only ever increments, so a stale tag cannot
    /// match a later connection. Reuse needs 2^64 dials on one store,
    /// which is why the counter is not recycled on discard.
    generation: u64,
}

/// Redis vector store using `FT.SEARCH` with a KNN clause, a pinned
/// resolver, and a lazily created cached multiplexed connection.
pub struct RedisVectorStore {
    client: redis::Client,
    connection_config: AsyncConnectionConfig,
    connection: tokio::sync::Mutex<ConnectionSlot>,
    resolver_note: Arc<parking_lot::Mutex<Option<&'static str>>>,
    index: String,
    vector_field: String,
    content_field: String,
    timeout: Duration,
}

impl RedisVectorStore {
    /// Builds the adapter from a `redis` vector-store configuration
    /// using Tokio DNS and the shared protected-address policy.
    pub(crate) fn from_config(
        config: &RagVectorStoreConfig,
        timeout: Duration,
        mode: RagBuildMode,
    ) -> Result<Self, RagBuildError> {
        // Neither mode connects; validation stops at client construction
        // and runtime waits for the first search.
        let _ = mode;
        let resolve_host: HostResolver = Arc::new(|host, port| {
            let host = host.to_owned();
            Box::pin(async move { sbproxy_security::ssrf::resolve_host_addrs(&host, port).await })
        });
        let is_forbidden: AddressPolicy =
            Arc::new(|addr| sbproxy_security::is_private_ip(&addr.ip()));
        Self::from_config_with_resolver(config, timeout, resolve_host, is_forbidden)
    }

    /// Builds the adapter with an injected host resolver and address
    /// policy. Test seam for the reconnect and DNS revalidation
    /// contracts; production must use the config-driven constructor.
    #[doc(hidden)]
    pub fn from_config_with_resolver(
        config: &RagVectorStoreConfig,
        timeout: Duration,
        resolve_host: HostResolver,
        is_forbidden: AddressPolicy,
    ) -> Result<Self, RagBuildError> {
        let RagVectorStoreConfig::Redis {
            url,
            username,
            password,
            index,
            vector_field,
            content_field,
            distance_metric,
            allow_private_url,
        } = config
        else {
            return Err(RagBuildError::InvalidConfig(
                "expected a redis vector store configuration".to_owned(),
            ));
        };
        // Only cosine indexes are supported; matching explicitly makes a
        // future metric variant fail here instead of miscoring silently.
        match distance_metric {
            RagDistanceMetric::Cosine => {}
        }
        let (host, port, tls) = parse_redis_url(url)?;
        // The vector field is interpolated into the KNN query text, so
        // it must satisfy the strict identifier charset even though
        // configuration validation accepts a slightly wider one.
        if !is_safe_identifier(vector_field) {
            return Err(RagBuildError::InvalidConfig(
                "vector_store.vector_field must contain only ASCII letters, digits, and underscores"
                    .to_owned(),
            ));
        }
        let addr = if tls {
            // rustls 0.23 requires a process-global CryptoProvider before
            // any TLS handshake. The sbproxy binary installs one at boot,
            // but this crate can be embedded (or tested) in a process that
            // never did, and a workspace build that unifies both the
            // `ring` and `aws-lc-rs` features leaves rustls unable to
            // pick one on its own. `install_default()` is idempotent and
            // loses harmlessly to an already-installed provider.
            let _ = rustls::crypto::ring::default_provider().install_default();
            ConnectionAddr::TcpTls {
                host,
                port,
                insecure: false,
                tls_params: None,
            }
        } else {
            ConnectionAddr::Tcp(host, port)
        };
        let info = ConnectionInfo {
            addr,
            redis: RedisConnectionInfo {
                db: 0,
                username: username.clone(),
                password: password.clone(),
                protocol: redis::ProtocolVersion::RESP2,
            },
        };
        let client = redis::Client::open(info).map_err(|_| {
            // The redis error is dropped on purpose so no endpoint
            // detail can leak into the returned error text.
            RagBuildError::Client("redis client construction failed".to_owned())
        })?;
        let note = Arc::new(parking_lot::Mutex::new(None));
        let resolver = ProtectedRedisResolver {
            resolve_host,
            is_forbidden,
            allow_private: *allow_private_url,
            note: Arc::clone(&note),
        };
        let connection_config = AsyncConnectionConfig::new().set_dns_resolver(resolver);
        Ok(Self {
            client,
            connection_config,
            connection: tokio::sync::Mutex::new(ConnectionSlot::default()),
            resolver_note: note,
            index: index.clone(),
            vector_field: vector_field.clone(),
            content_field: content_field.clone(),
            timeout,
        })
    }

    /// Hostname the TLS connector presents for server name indication
    /// and certificate verification when the store dials `rediss://`,
    /// or `None` for plaintext. Test seam for the TLS pinning contract.
    #[doc(hidden)]
    pub fn tls_host(&self) -> Option<&str> {
        match &self.client.get_connection_info().addr {
            ConnectionAddr::TcpTls { host, .. } => Some(host.as_str()),
            _ => None,
        }
    }

    /// Returns the cached connection or creates one, resolving and
    /// revalidating DNS through the protected resolver. The generation
    /// travels with the connection so the caller can name it again when
    /// discarding.
    ///
    /// The lock is deliberately held across the dial: it makes at most
    /// one dial in flight per store, so concurrent callers that arrive
    /// after a discard join one replacement rather than racing several.
    /// The cost is that they wait out that dial, bounded by
    /// `self.timeout`, which is the same bound their own search carries.
    async fn connection(&self) -> Result<(u64, MultiplexedConnection), VectorStoreError> {
        let mut slot = self.connection.lock().await;
        if let Some(connection) = slot.current.as_ref() {
            return Ok((slot.generation, connection.clone()));
        }
        *self.resolver_note.lock() = None;
        let connect = self
            .client
            .get_multiplexed_async_connection_with_config(&self.connection_config);
        match tokio::time::timeout(self.timeout, connect).await {
            Err(_) => Err(VectorStoreError::Timeout),
            Ok(Err(_)) => {
                let reason = self.resolver_note.lock().take();
                Err(VectorStoreError::MalformedResponse(
                    reason.unwrap_or("redis connection failed"),
                ))
            }
            Ok(Ok(connection)) => {
                // Bump before publishing so no two connections ever
                // share a generation, including across a failed dial.
                slot.generation = slot.generation.wrapping_add(1);
                slot.current = Some(connection.clone());
                Ok((slot.generation, connection))
            }
        }
    }

    /// Drops the cached connection so the next search reconnects
    /// through the resolver, but only if the slot still holds the
    /// generation that failed.
    ///
    /// A caller that failed on an older generation is a straggler: the
    /// connection it is complaining about is already gone and something
    /// else has since dialed a replacement, which must survive.
    ///
    /// What this cannot see: whether the connection currently in the
    /// slot is itself healthy. It only knows that this caller has no
    /// evidence against it. A replacement that is broken for its own
    /// reasons is discarded by the first caller that actually fails on
    /// it, one round later, not by this one.
    async fn discard_connection(&self, generation: u64) {
        let mut slot = self.connection.lock().await;
        if slot.generation == generation {
            slot.current = None;
        }
    }

    /// Maps a command failure to a non-secret error, discarding the
    /// generation the command ran on for transport-level failures.
    async fn classify(&self, generation: u64, error: redis::RedisError) -> VectorStoreError {
        if error.is_timeout() {
            self.discard_connection(generation).await;
            return VectorStoreError::Timeout;
        }
        if error.is_io_error() || error.is_connection_dropped() || error.is_unrecoverable_error() {
            self.discard_connection(generation).await;
            return VectorStoreError::MalformedResponse("redis connection failed");
        }
        // Server-side rejections, including a missing Search module,
        // keep the connection and surface as a fixed error class.
        VectorStoreError::MalformedResponse("redis rejected the search command")
    }

    /// Builds the `FT.SEARCH` command for one query.
    fn build_command(&self, query: &VectorQuery<'_>) -> Result<redis::Cmd, VectorStoreError> {
        let mut filters = tag_filter(query.tenant_field, query.tenant_id)?;
        for (field, value) in query.static_equals {
            filters.push(' ');
            filters.push_str(&tag_filter(field, value)?);
        }
        let knn = format!(
            "({filters})=>[KNN {} @{} $BLOB AS vector_distance]",
            query.top_k, self.vector_field
        );
        let mut blob = Vec::with_capacity(query.embedding.len() * 4);
        for value in query.embedding {
            blob.extend_from_slice(&value.to_le_bytes());
        }
        let mut command = redis::cmd("FT.SEARCH");
        command
            .arg(&self.index)
            .arg(knn)
            .arg("PARAMS")
            .arg(2)
            .arg("BLOB")
            .arg(blob)
            .arg("SORTBY")
            .arg("vector_distance")
            .arg("RETURN")
            .arg(2)
            .arg(&self.content_field)
            .arg("vector_distance")
            .arg("DIALECT")
            .arg(2);
        Ok(command)
    }
}

/// Checks the URL shape and returns `(host, port, tls)`.
fn parse_redis_url(url: &str) -> Result<(String, u16, bool), RagBuildError> {
    let invalid = |message: &str| RagBuildError::InvalidConfig(message.to_owned());
    let parsed = url::Url::parse(url).map_err(|_| invalid("redis url does not parse"))?;
    let tls = match parsed.scheme() {
        "redis" => false,
        "rediss" => true,
        _ => return Err(invalid("redis url must use the redis or rediss scheme")),
    };
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(invalid(
            "redis url must not contain userinfo; use the username and password fields",
        ));
    }
    if parsed.query().is_some() {
        return Err(invalid("redis url must not contain a query"));
    }
    if parsed.fragment().is_some() {
        return Err(invalid("redis url must not contain a fragment"));
    }
    if !matches!(parsed.path(), "" | "/") {
        return Err(invalid("redis url must not carry a path"));
    }
    let host = match parsed.host() {
        Some(url::Host::Domain(domain)) => domain.to_owned(),
        Some(url::Host::Ipv4(address)) => address.to_string(),
        Some(url::Host::Ipv6(address)) => address.to_string(),
        None => return Err(invalid("redis url has no host")),
    };
    Ok((host, parsed.port().unwrap_or(6379), tls))
}

/// Builds one `@field:{value}` tag filter with an escaped value.
fn tag_filter(field: &str, value: &str) -> Result<String, VectorStoreError> {
    // The field name is interpolated into the query text; the strict
    // identifier charset keeps it inert even under dialect 2 parsing.
    if !is_safe_identifier(field) {
        return Err(VectorStoreError::MalformedResponse(
            "filter field is not a safe identifier",
        ));
    }
    Ok(format!("@{field}:{{{}}}", escape_redis_tag(value)))
}

/// Extracts the bytes of a bulk or simple string value.
fn bulk_bytes(value: redis::Value) -> Option<Vec<u8>> {
    match value {
        redis::Value::BulkString(bytes) => Some(bytes),
        redis::Value::SimpleString(text) => Some(text.into_bytes()),
        _ => None,
    }
}

/// Extracts a UTF-8 string from a bulk or simple string value.
fn bulk_text(value: redis::Value) -> Option<String> {
    String::from_utf8(bulk_bytes(value)?).ok()
}

/// Parses one record's `[name, value, ...]` field array.
fn record_fields(value: redis::Value) -> Result<Vec<(String, Vec<u8>)>, VectorStoreError> {
    let redis::Value::Array(items) = value else {
        return Err(VectorStoreError::MalformedResponse(
            "redis record fields are not an array",
        ));
    };
    if items.len() % 2 != 0 {
        return Err(VectorStoreError::MalformedResponse(
            "redis record fields are misaligned",
        ));
    }
    let mut fields = Vec::with_capacity(items.len() / 2);
    let mut iterator = items.into_iter();
    while let (Some(name), Some(data)) = (iterator.next(), iterator.next()) {
        let name = bulk_text(name).ok_or(VectorStoreError::MalformedResponse(
            "redis field name is not a string",
        ))?;
        let data = bulk_bytes(data).ok_or(VectorStoreError::MalformedResponse(
            "redis field value is not a string",
        ))?;
        fields.push((name, data));
    }
    Ok(fields)
}

/// Parses the `FT.SEARCH` reply `[total, key, fields, key, fields, ...]`.
///
/// The document key is the source id. More than `top_k` records is a
/// contract violation, and the accumulated decoded content is capped at
/// [`MAX_PROVIDER_RESPONSE_BYTES`].
fn parse_search_reply(
    value: redis::Value,
    content_field: &str,
    top_k: usize,
) -> Result<Vec<RetrievedChunk>, VectorStoreError> {
    let redis::Value::Array(items) = value else {
        return Err(VectorStoreError::MalformedResponse(
            "redis reply is not an array",
        ));
    };
    let mut items = items.into_iter();
    let Some(redis::Value::Int(_)) = items.next() else {
        return Err(VectorStoreError::MalformedResponse(
            "redis reply is missing the result count",
        ));
    };
    let rest: Vec<redis::Value> = items.collect();
    if !rest.len().is_multiple_of(2) {
        return Err(VectorStoreError::MalformedResponse(
            "redis reply records are misaligned",
        ));
    }
    if rest.len() / 2 > top_k {
        return Err(VectorStoreError::MalformedResponse(
            "redis returned more records than requested",
        ));
    }
    let mut budget = MAX_PROVIDER_RESPONSE_BYTES;
    let mut chunks = Vec::with_capacity(rest.len() / 2);
    let mut records = rest.into_iter();
    while let (Some(key), Some(fields)) = (records.next(), records.next()) {
        let source_id = bulk_text(key).ok_or(VectorStoreError::MalformedResponse(
            "redis document key is not a string",
        ))?;
        let mut content: Option<String> = None;
        let mut distance: Option<f64> = None;
        for (name, data) in record_fields(fields)? {
            if name == content_field {
                if data.len() > budget {
                    return Err(VectorStoreError::ResponseTooLarge);
                }
                budget -= data.len();
                content = Some(String::from_utf8(data).map_err(|_| {
                    VectorStoreError::MalformedResponse("redis content is not utf8")
                })?);
            } else if name == "vector_distance" {
                let text = String::from_utf8(data).map_err(|_| {
                    VectorStoreError::MalformedResponse("redis vector distance is not numeric")
                })?;
                let parsed = text.trim().parse::<f64>().map_err(|_| {
                    VectorStoreError::MalformedResponse("redis vector distance is not numeric")
                })?;
                distance = Some(parsed);
            }
        }
        let content = content.ok_or(VectorStoreError::MalformedResponse(
            "redis record is missing content",
        ))?;
        let distance = distance.ok_or(VectorStoreError::MalformedResponse(
            "redis record is missing the vector distance",
        ))?;
        chunks.push(RetrievedChunk {
            source_id,
            content,
            score: score_from_cosine_distance(distance)?,
        });
    }
    Ok(chunks)
}

#[async_trait::async_trait]
impl VectorStore for RedisVectorStore {
    async fn search(
        &self,
        query: VectorQuery<'_>,
    ) -> Result<Vec<RetrievedChunk>, VectorStoreError> {
        let command = self.build_command(&query)?;
        let (generation, mut connection) = self.connection().await?;
        match tokio::time::timeout(
            self.timeout,
            command.query_async::<redis::Value>(&mut connection),
        )
        .await
        {
            Err(_) => {
                // A stalled multiplexed pipeline cannot be reused; the
                // late reply would misalign with the next request. Only
                // this generation goes: a search that timed out on an
                // earlier socket must not evict a later one, and two
                // searches stalled on the same socket time out at
                // different moments.
                self.discard_connection(generation).await;
                Err(VectorStoreError::Timeout)
            }
            Ok(Err(error)) => Err(self.classify(generation, error).await),
            Ok(Ok(value)) => parse_search_reply(value, &self.content_field, query.top_k),
        }
    }

    fn provider_name(&self) -> &'static str {
        "redis"
    }
}
