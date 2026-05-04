//! Storage action: serves files from object storage.
//!
//! Backends: S3, Google Cloud Storage, Azure Blob Storage, and the local
//! filesystem. Implementation routes through the [`object_store`] crate
//! so all four share one codepath: build a `Box<dyn ObjectStore>` at
//! config-load time, then on every request translate the inbound path
//! into a key, fetch (or HEAD) the object, and stream the bytes to the
//! client with `Content-Type`, `Content-Length`, `ETag`, and
//! `Last-Modified` set from the object metadata.
//!
//! Supports `GET` and `HEAD`, byte-range requests (`Range` /
//! `Content-Range` / 206 Partial Content), and an `index_file` fallback
//! for paths ending in `/`. Anything else is rejected with `405`.
//! Missing objects are surfaced as `404`; transient backend errors
//! become `502`.

use std::sync::Arc;

use bytes::Bytes;
use futures::stream::StreamExt;
use object_store::path::Path as ObjectPath;
use object_store::{ObjectMeta, ObjectStore};
use serde::Deserialize;

/// Storage action config (raw, as parsed from sb.yml).
///
/// The compiled form lives in [`CompiledStorage`]; the runtime carries
/// the compiled value and never re-parses the user config.
#[derive(Debug, Deserialize)]
pub struct StorageAction {
    /// Storage backend: `s3`, `gcs`, `azure`, or `local`.
    pub backend: String,
    /// Bucket / container name (for cloud backends).
    #[serde(default)]
    pub bucket: Option<String>,
    /// Key prefix prepended to every request path.
    #[serde(default)]
    pub prefix: Option<String>,
    /// Local filesystem root path (for the `local` backend).
    #[serde(default)]
    pub path: Option<String>,
    /// Default index file served for directory requests (e.g. `index.html`).
    #[serde(default)]
    pub index_file: Option<String>,
    /// Optional region override (S3 + S3-compatible endpoints).
    #[serde(default)]
    pub region: Option<String>,
    /// Optional endpoint override for S3-compatible backends (MinIO,
    /// Cloudflare R2, etc.).
    #[serde(default)]
    pub endpoint: Option<String>,
}

/// A storage action with its backing [`ObjectStore`] already constructed.
///
/// One instance per origin / forward-rule. The `ObjectStore` is wrapped
/// in an `Arc` so cheap clones can be handed to per-request handlers
/// without re-building the backend.
pub struct CompiledStorage {
    /// Backend identifier (`s3`/`gcs`/`azure`/`local`).
    pub backend: String,
    /// Key prefix to prepend to incoming request paths.
    pub prefix: Option<String>,
    /// Default index file for directory requests.
    pub index_file: Option<String>,
    /// The constructed object store, built once at config compile time.
    pub store: Arc<dyn ObjectStore>,
}

impl std::fmt::Debug for CompiledStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompiledStorage")
            .field("backend", &self.backend)
            .field("prefix", &self.prefix)
            .field("index_file", &self.index_file)
            .finish_non_exhaustive()
    }
}

impl StorageAction {
    /// Build a [`StorageAction`] config (raw form) from a JSON value.
    ///
    /// Performs validation only. The actual `ObjectStore` is built by
    /// [`StorageAction::build`].
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        let action: Self = serde_json::from_value(value)?;
        match action.backend.as_str() {
            "s3" | "gcs" | "azure" | "local" => {}
            other => anyhow::bail!("unsupported storage backend: {}", other),
        }
        if action.backend == "local" && action.path.is_none() {
            anyhow::bail!("local storage backend requires a 'path' field");
        }
        if action.backend != "local" && action.bucket.is_none() {
            anyhow::bail!(
                "{} storage backend requires a 'bucket' field",
                action.backend
            );
        }
        if let Some(ref p) = action.path {
            reject_traversal("path", p)?;
        }
        if let Some(ref p) = action.prefix {
            reject_traversal("prefix", p)?;
        }
        if let Some(ref f) = action.index_file {
            reject_traversal("index_file", f)?;
        }
        Ok(action)
    }

    /// Construct the backing [`ObjectStore`] and return a
    /// [`CompiledStorage`] ready to serve requests.
    ///
    /// Cloud backends pick up credentials from the environment using
    /// each provider's standard discovery (`AWS_*`, `GOOGLE_*`,
    /// `AZURE_*`). Operators who need explicit credential injection can
    /// set them via the proxy's existing variable interpolation before
    /// process start.
    pub fn build(self) -> anyhow::Result<CompiledStorage> {
        let store: Arc<dyn ObjectStore> = match self.backend.as_str() {
            "local" => {
                let path = self
                    .path
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("local backend requires 'path'"))?;
                // LocalFileSystem rejects relative paths and missing
                // dirs at construction time. We pre-create the dir so a
                // fresh deployment with `path: /var/cache/sbproxy` does
                // not fail to start before any user has uploaded.
                std::fs::create_dir_all(path).map_err(|e| {
                    anyhow::anyhow!("failed to create local storage path '{}': {}", path, e)
                })?;
                let local = object_store::local::LocalFileSystem::new_with_prefix(path)?;
                Arc::new(local)
            }
            "s3" => {
                let bucket = self
                    .bucket
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("s3 backend requires 'bucket'"))?;
                let mut builder =
                    object_store::aws::AmazonS3Builder::from_env().with_bucket_name(bucket);
                if let Some(region) = self.region.as_deref() {
                    builder = builder.with_region(region);
                }
                if let Some(endpoint) = self.endpoint.as_deref() {
                    builder = builder.with_endpoint(endpoint);
                }
                Arc::new(builder.build()?)
            }
            "gcs" => {
                let bucket = self
                    .bucket
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("gcs backend requires 'bucket'"))?;
                let builder = object_store::gcp::GoogleCloudStorageBuilder::from_env()
                    .with_bucket_name(bucket);
                Arc::new(builder.build()?)
            }
            "azure" => {
                let container = self.bucket.as_deref().ok_or_else(|| {
                    anyhow::anyhow!("azure backend requires 'bucket' (container name)")
                })?;
                let builder = object_store::azure::MicrosoftAzureBuilder::from_env()
                    .with_container_name(container);
                Arc::new(builder.build()?)
            }
            other => anyhow::bail!("unsupported storage backend: {}", other),
        };
        Ok(CompiledStorage {
            backend: self.backend,
            prefix: self.prefix,
            index_file: self.index_file,
            store,
        })
    }
}

/// Outcome of [`CompiledStorage::serve`].
///
/// Carries everything the HTTP layer needs to write a response: the
/// status code, headers, and (for non-HEAD GETs) the body bytes.
pub struct StorageResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response headers as `(name, value)` pairs. Includes
    /// `content-type`, `content-length`, `etag`, and `last-modified`
    /// when known.
    pub headers: Vec<(String, String)>,
    /// Response body. `None` for `HEAD`; empty for error statuses
    /// without a JSON body.
    pub body: Option<Bytes>,
}

impl CompiledStorage {
    /// Serve a single request against the backing object store.
    ///
    /// `method` is `"GET"` or `"HEAD"` (any other verb yields a 405).
    /// `request_path` is the inbound URL path including the leading
    /// `/`. `range` is the optional `Range` request header value.
    pub async fn serve(
        &self,
        method: &str,
        request_path: &str,
        range: Option<&str>,
    ) -> StorageResponse {
        // Method gate. The action only exposes read operations; uploads
        // would need a separate `storage_upload` action with explicit
        // credentials and access policy.
        let head_only = match method {
            "GET" => false,
            "HEAD" => true,
            _ => {
                return StorageResponse {
                    status: 405,
                    headers: vec![
                        ("content-type".into(), "application/json".into()),
                        ("allow".into(), "GET, HEAD".into()),
                    ],
                    body: Some(Bytes::from_static(b"{\"error\":\"method not allowed\"}")),
                };
            }
        };

        let key = match self.resolve_key(request_path) {
            Ok(k) => k,
            Err(_) => {
                return error_response(400, "invalid request path");
            }
        };

        // HEAD: just metadata.
        if head_only {
            return match self.store.head(&key).await {
                Ok(meta) => StorageResponse {
                    status: 200,
                    headers: build_headers(&meta, &key, None),
                    body: None,
                },
                Err(object_store::Error::NotFound { .. }) => error_response(404, "not found"),
                Err(e) => {
                    tracing::warn!(backend = %self.backend, error = %e, "storage HEAD failed");
                    error_response(502, "storage backend error")
                }
            };
        }

        // GET, optionally with a Range header. Range support is
        // best-effort: we parse a single `bytes=start-end` range and
        // hand it to `get_range`, which the backend implements
        // efficiently (HTTP Range for cloud backends, seek for local).
        if let Some(spec) = range.and_then(parse_range) {
            return match self.store.head(&key).await {
                Ok(meta) => {
                    let total = meta.size as u64;
                    let (start, end) = match spec.resolve(total) {
                        Some(v) => v,
                        None => return error_response(416, "range not satisfiable"),
                    };
                    let r = (start as usize)..(end as usize + 1);
                    match self.store.get_range(&key, r.clone()).await {
                        Ok(bytes) => {
                            let mut headers = build_headers(&meta, &key, Some(bytes.len() as u64));
                            headers.push((
                                "content-range".into(),
                                format!("bytes {}-{}/{}", start, end, total),
                            ));
                            headers.push(("accept-ranges".into(), "bytes".into()));
                            StorageResponse {
                                status: 206,
                                headers,
                                body: Some(bytes),
                            }
                        }
                        Err(object_store::Error::NotFound { .. }) => {
                            error_response(404, "not found")
                        }
                        Err(e) => {
                            tracing::warn!(
                                backend = %self.backend,
                                error = %e,
                                "storage range GET failed"
                            );
                            error_response(502, "storage backend error")
                        }
                    }
                }
                Err(object_store::Error::NotFound { .. }) => error_response(404, "not found"),
                Err(e) => {
                    tracing::warn!(backend = %self.backend, error = %e, "storage HEAD failed");
                    error_response(502, "storage backend error")
                }
            };
        }

        // Plain GET: stream into a buffer. Cloud and local backends
        // both expose chunked streams; we accumulate into one Bytes so
        // the caller can hand it to Pingora's body filter as a single
        // write. Memory cost is bounded by upstream object size; if
        // that is unbounded in your deployment, gate this with a
        // separate config knob (left for a follow-up).
        match self.store.get(&key).await {
            Ok(get_result) => {
                let meta = get_result.meta.clone();
                let mut stream = get_result.into_stream();
                let mut out = Vec::with_capacity(meta.size);
                while let Some(chunk) = stream.next().await {
                    match chunk {
                        Ok(chunk) => out.extend_from_slice(&chunk),
                        Err(e) => {
                            tracing::warn!(
                                backend = %self.backend,
                                error = %e,
                                "storage stream failed mid-body"
                            );
                            return error_response(502, "storage backend error");
                        }
                    }
                }
                let body = Bytes::from(out);
                let mut headers = build_headers(&meta, &key, Some(body.len() as u64));
                headers.push(("accept-ranges".into(), "bytes".into()));
                StorageResponse {
                    status: 200,
                    headers,
                    body: Some(body),
                }
            }
            Err(object_store::Error::NotFound { .. }) => error_response(404, "not found"),
            Err(e) => {
                tracing::warn!(backend = %self.backend, error = %e, "storage GET failed");
                error_response(502, "storage backend error")
            }
        }
    }

    /// Translate the inbound request path into the object-store key.
    ///
    /// The leading `/` is stripped, the configured `prefix` is
    /// prepended, and a trailing `/` triggers the `index_file`
    /// fallback. Returns an error if the resulting path would escape
    /// the configured prefix (defence-in-depth on top of the
    /// config-time `reject_traversal` check).
    fn resolve_key(&self, request_path: &str) -> Result<ObjectPath, object_store::path::Error> {
        let trimmed = request_path.trim_start_matches('/');
        let mut joined = match (&self.prefix, trimmed) {
            (Some(p), suffix) if !p.is_empty() => {
                let p = p.trim_end_matches('/');
                if suffix.is_empty() {
                    p.to_string()
                } else {
                    format!("{}/{}", p, suffix)
                }
            }
            _ => trimmed.to_string(),
        };
        // Directory requests: substitute the index file when the path
        // ends in `/` (or is empty).
        if joined.is_empty() || joined.ends_with('/') {
            if let Some(idx) = self.index_file.as_deref() {
                joined.push_str(idx);
            }
        }
        ObjectPath::parse(joined)
    }
}

/// Parsed `Range:` header (single byte range only).
struct RangeSpec {
    start: Option<u64>,
    end: Option<u64>,
    suffix: Option<u64>,
}

impl RangeSpec {
    /// Resolve a parsed range against the known total length.
    /// Returns `(start, end_inclusive)` or `None` if unsatisfiable.
    fn resolve(&self, total: u64) -> Option<(u64, u64)> {
        if total == 0 {
            return None;
        }
        if let Some(suffix) = self.suffix {
            if suffix == 0 {
                return None;
            }
            let start = total.saturating_sub(suffix);
            return Some((start, total - 1));
        }
        let start = self.start?;
        if start >= total {
            return None;
        }
        let end = self.end.unwrap_or(total - 1).min(total - 1);
        if end < start {
            return None;
        }
        Some((start, end))
    }
}

/// Parse a `Range: bytes=...` header value into a [`RangeSpec`].
///
/// Supports the common forms: `bytes=0-499`, `bytes=500-`, and
/// `bytes=-500` (last 500 bytes). Multi-range requests are not
/// supported and return `None`.
fn parse_range(header: &str) -> Option<RangeSpec> {
    let spec = header.strip_prefix("bytes=")?;
    if spec.contains(',') {
        return None;
    }
    let (a, b) = spec.split_once('-')?;
    if a.is_empty() {
        // suffix: bytes=-N -> last N bytes
        let n: u64 = b.parse().ok()?;
        return Some(RangeSpec {
            start: None,
            end: None,
            suffix: Some(n),
        });
    }
    let start: u64 = a.parse().ok()?;
    let end = if b.is_empty() {
        None
    } else {
        Some(b.parse::<u64>().ok()?)
    };
    Some(RangeSpec {
        start: Some(start),
        end,
        suffix: None,
    })
}

/// Build the response headers from object metadata.
///
/// `override_len` is used for range requests where the streamed body
/// length differs from the full object size.
fn build_headers(
    meta: &ObjectMeta,
    key: &ObjectPath,
    override_len: Option<u64>,
) -> Vec<(String, String)> {
    let mut out = Vec::with_capacity(4);
    let len = override_len.unwrap_or(meta.size as u64);
    out.push(("content-length".into(), len.to_string()));
    out.push((
        "content-type".into(),
        guess_content_type(key.as_ref()).to_string(),
    ));
    out.push((
        "last-modified".into(),
        meta.last_modified
            .format("%a, %d %b %Y %H:%M:%S GMT")
            .to_string(),
    ));
    if let Some(etag) = &meta.e_tag {
        out.push(("etag".into(), etag.clone()));
    }
    out
}

/// Infer a `Content-Type` from the key extension. Cheap and common, no
/// external `mime_guess` dep needed for the small set of types served
/// by typical static-site / asset use cases.
fn guess_content_type(key: &str) -> &'static str {
    let ext = key.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "application/javascript; charset=utf-8",
        "json" => "application/json",
        "xml" => "application/xml",
        "txt" => "text/plain; charset=utf-8",
        "md" => "text/markdown; charset=utf-8",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        "ico" => "image/x-icon",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "tar" => "application/x-tar",
        "gz" => "application/gzip",
        "wasm" => "application/wasm",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        _ => "application/octet-stream",
    }
}

fn error_response(status: u16, message: &str) -> StorageResponse {
    let body = format!("{{\"error\":\"{}\"}}", message);
    StorageResponse {
        status,
        headers: vec![
            ("content-type".into(), "application/json".into()),
            ("content-length".into(), body.len().to_string()),
        ],
        body: Some(Bytes::from(body)),
    }
}

/// Reject any component that contains a `..` segment or a NUL byte. We
/// deliberately check segments rather than substrings so `..foo` (a valid
/// filename) is allowed, while `foo/../../etc` is not.
fn reject_traversal(field: &str, value: &str) -> anyhow::Result<()> {
    if value.contains('\0') {
        anyhow::bail!("storage {field} must not contain NUL bytes");
    }
    for segment in value.split(['/', '\\']) {
        if segment == ".." {
            anyhow::bail!(
                "storage {field} contains '..' traversal segment: {:?}",
                value
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use object_store::PutPayload;

    // --- config validation tests ---

    #[test]
    fn storage_action_s3_from_config() {
        let json = serde_json::json!({
            "type": "storage",
            "backend": "s3",
            "bucket": "my-bucket",
            "prefix": "assets/"
        });
        let action = StorageAction::from_config(json).unwrap();
        assert_eq!(action.backend, "s3");
        assert_eq!(action.bucket.as_deref(), Some("my-bucket"));
        assert_eq!(action.prefix.as_deref(), Some("assets/"));
        assert!(action.path.is_none());
        assert!(action.index_file.is_none());
    }

    #[test]
    fn storage_action_local_from_config() {
        let json = serde_json::json!({
            "type": "storage",
            "backend": "local",
            "path": "/var/www/static",
            "index_file": "index.html"
        });
        let action = StorageAction::from_config(json).unwrap();
        assert_eq!(action.backend, "local");
        assert_eq!(action.path.as_deref(), Some("/var/www/static"));
    }

    #[test]
    fn storage_action_unsupported_backend() {
        let json = serde_json::json!({
            "type": "storage",
            "backend": "dropbox",
            "bucket": "test"
        });
        assert!(StorageAction::from_config(json).is_err());
    }

    #[test]
    fn storage_action_local_without_path() {
        let json = serde_json::json!({
            "type": "storage",
            "backend": "local"
        });
        assert!(StorageAction::from_config(json).is_err());
    }

    #[test]
    fn storage_action_s3_without_bucket() {
        let json = serde_json::json!({
            "type": "storage",
            "backend": "s3"
        });
        assert!(StorageAction::from_config(json).is_err());
    }

    #[test]
    fn storage_action_rejects_dotdot_in_prefix() {
        let json = serde_json::json!({
            "type": "storage",
            "backend": "s3",
            "bucket": "b",
            "prefix": "foo/../bar"
        });
        assert!(StorageAction::from_config(json).is_err());
    }

    #[test]
    fn storage_action_rejects_nul_byte() {
        let json = serde_json::json!({
            "type": "storage",
            "backend": "local",
            "path": "/var/www/static\0evil"
        });
        assert!(StorageAction::from_config(json).is_err());
    }

    // --- range parser tests ---

    #[test]
    fn parse_range_full_form() {
        let r = parse_range("bytes=0-499").unwrap();
        assert_eq!(r.start, Some(0));
        assert_eq!(r.end, Some(499));
        assert_eq!(r.resolve(1000), Some((0, 499)));
    }

    #[test]
    fn parse_range_open_end() {
        let r = parse_range("bytes=500-").unwrap();
        assert_eq!(r.start, Some(500));
        assert_eq!(r.end, None);
        assert_eq!(r.resolve(1000), Some((500, 999)));
    }

    #[test]
    fn parse_range_suffix() {
        let r = parse_range("bytes=-100").unwrap();
        assert_eq!(r.suffix, Some(100));
        assert_eq!(r.resolve(1000), Some((900, 999)));
    }

    #[test]
    fn parse_range_multi_unsupported() {
        assert!(parse_range("bytes=0-99,200-299").is_none());
    }

    #[test]
    fn parse_range_unsatisfiable() {
        let r = parse_range("bytes=2000-").unwrap();
        assert!(r.resolve(1000).is_none());
    }

    // --- end-to-end against local backend ---

    async fn make_local_storage(
        prefix: Option<&str>,
        index: Option<&str>,
    ) -> (CompiledStorage, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let action = StorageAction {
            backend: "local".to_string(),
            bucket: None,
            prefix: prefix.map(String::from),
            path: Some(dir.path().to_string_lossy().into_owned()),
            index_file: index.map(String::from),
            region: None,
            endpoint: None,
        };
        let compiled = action.build().unwrap();
        (compiled, dir)
    }

    #[tokio::test]
    async fn local_backend_serves_get() {
        let (storage, _dir) = make_local_storage(None, None).await;
        storage
            .store
            .put(
                &ObjectPath::from("hello.txt"),
                PutPayload::from_static(b"hello world"),
            )
            .await
            .unwrap();

        let resp = storage.serve("GET", "/hello.txt", None).await;
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body.as_deref(), Some(&b"hello world"[..]));
        let ct = resp
            .headers
            .iter()
            .find(|(k, _)| k == "content-type")
            .map(|(_, v)| v.as_str());
        assert_eq!(ct, Some("text/plain; charset=utf-8"));
    }

    #[tokio::test]
    async fn local_backend_serves_head() {
        let (storage, _dir) = make_local_storage(None, None).await;
        storage
            .store
            .put(
                &ObjectPath::from("data.json"),
                PutPayload::from_static(b"{\"a\":1}"),
            )
            .await
            .unwrap();
        let resp = storage.serve("HEAD", "/data.json", None).await;
        assert_eq!(resp.status, 200);
        assert!(resp.body.is_none());
        let ct = resp
            .headers
            .iter()
            .find(|(k, _)| k == "content-type")
            .map(|(_, v)| v.as_str());
        assert_eq!(ct, Some("application/json"));
    }

    #[tokio::test]
    async fn local_backend_404_for_missing() {
        let (storage, _dir) = make_local_storage(None, None).await;
        let resp = storage.serve("GET", "/nope", None).await;
        assert_eq!(resp.status, 404);
    }

    #[tokio::test]
    async fn local_backend_405_for_unsupported_method() {
        let (storage, _dir) = make_local_storage(None, None).await;
        let resp = storage.serve("POST", "/x", None).await;
        assert_eq!(resp.status, 405);
        let allow = resp
            .headers
            .iter()
            .find(|(k, _)| k == "allow")
            .map(|(_, v)| v.as_str());
        assert_eq!(allow, Some("GET, HEAD"));
    }

    #[tokio::test]
    async fn local_backend_index_fallback() {
        let (storage, _dir) = make_local_storage(None, Some("index.html")).await;
        storage
            .store
            .put(
                &ObjectPath::from("index.html"),
                PutPayload::from_static(b"<h1>root</h1>"),
            )
            .await
            .unwrap();
        let resp = storage.serve("GET", "/", None).await;
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body.as_deref(), Some(&b"<h1>root</h1>"[..]));
    }

    #[tokio::test]
    async fn local_backend_prefix_applied() {
        let (storage, _dir) = make_local_storage(Some("assets"), None).await;
        storage
            .store
            .put(
                &ObjectPath::from("assets/site.css"),
                PutPayload::from_static(b"body{}"),
            )
            .await
            .unwrap();
        let resp = storage.serve("GET", "/site.css", None).await;
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body.as_deref(), Some(&b"body{}"[..]));
    }

    #[tokio::test]
    async fn local_backend_range_request() {
        let (storage, _dir) = make_local_storage(None, None).await;
        storage
            .store
            .put(
                &ObjectPath::from("blob.bin"),
                PutPayload::from_static(b"0123456789abcdef"),
            )
            .await
            .unwrap();
        let resp = storage.serve("GET", "/blob.bin", Some("bytes=4-7")).await;
        assert_eq!(resp.status, 206);
        assert_eq!(resp.body.as_deref(), Some(&b"4567"[..]));
        let cr = resp
            .headers
            .iter()
            .find(|(k, _)| k == "content-range")
            .map(|(_, v)| v.as_str());
        assert_eq!(cr, Some("bytes 4-7/16"));
    }

    #[tokio::test]
    async fn local_backend_range_unsatisfiable() {
        let (storage, _dir) = make_local_storage(None, None).await;
        storage
            .store
            .put(
                &ObjectPath::from("blob.bin"),
                PutPayload::from_static(b"hello"),
            )
            .await
            .unwrap();
        let resp = storage.serve("GET", "/blob.bin", Some("bytes=999-")).await;
        assert_eq!(resp.status, 416);
    }
}
