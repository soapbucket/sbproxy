//! Wire-contract tests for the embedding provider adapters.
//!
//! Every provider is exercised against a loopback fixture that records
//! the exact request it received (method, path, headers, body) and
//! replays a canned response. This pins each adapter's request shape,
//! authentication form, response parsing, and failure taxonomy without
//! any network egress. Each provider module compiles only behind its
//! cargo feature, mirroring the adapters themselves.

#[cfg(any(
    feature = "embedding-openai",
    feature = "embedding-compatible",
    feature = "embedding-cohere",
    feature = "embedding-bedrock",
    feature = "embedding-vertex"
))]
mod fixture {
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use sbproxy_ai::rag_config::RagEmbeddingConfig;
    use sbproxy_rag::{Embedder, RagBuildMode};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    /// Query text embedded by every single-input contract test.
    pub const FIXTURE_TEXT: &str = "refund policy";
    /// Generous deadline for tests that expect a completed exchange.
    pub const FIXTURE_TIMEOUT: Duration = Duration::from_secs(5);
    /// Short deadline for tests that expect a timeout.
    pub const SHORT_TIMEOUT: Duration = Duration::from_millis(200);

    /// One HTTP request exactly as the fixture server saw it.
    pub struct RecordedRequest {
        pub method: String,
        pub path: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }

    impl RecordedRequest {
        /// Returns the header value for `name`, compared case-insensitively.
        pub fn header(&self, name: &str) -> Option<&str> {
            let wanted = name.to_ascii_lowercase();
            self.headers
                .iter()
                .find(|(header, _)| *header == wanted)
                .map(|(_, value)| value.as_str())
        }

        /// Parses the recorded request body as JSON.
        pub fn body_json(&self) -> serde_json::Value {
            serde_json::from_slice(&self.body).expect("recorded request body is not valid json")
        }
    }

    /// Reads one complete HTTP/1.1 request (head plus body) from `stream`.
    async fn read_request(stream: &mut TcpStream) -> RecordedRequest {
        let mut raw = Vec::new();
        let header_end = loop {
            let mut chunk = [0u8; 1024];
            let count = stream.read(&mut chunk).await.unwrap();
            assert!(count > 0, "client closed before sending complete headers");
            raw.extend_from_slice(&chunk[..count]);
            assert!(raw.len() <= 512 * 1024, "fixture request is too large");
            if let Some(position) = raw.windows(4).position(|window| window == b"\r\n\r\n") {
                break position + 4;
            }
        };
        let head = String::from_utf8(raw[..header_end].to_vec()).unwrap();
        let mut lines = head.split("\r\n");
        let request_line = lines.next().unwrap();
        let mut parts = request_line.split(' ');
        let method = parts.next().unwrap().to_owned();
        let path = parts.next().unwrap().to_owned();
        let headers: Vec<(String, String)> = lines
            .filter_map(|line| line.split_once(':'))
            .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
            .collect();
        let content_length: usize = headers
            .iter()
            .find(|(name, _)| name == "content-length")
            .map_or(0, |(_, value)| value.parse().unwrap());
        let mut body = raw[header_end..].to_vec();
        while body.len() < content_length {
            let mut chunk = [0u8; 4096];
            let count = stream.read(&mut chunk).await.unwrap();
            assert!(count > 0, "client closed before sending the complete body");
            body.extend_from_slice(&chunk[..count]);
        }
        body.truncate(content_length);
        RecordedRequest {
            method,
            path,
            headers,
            body,
        }
    }

    /// Loopback fixture that records every request it receives and
    /// answers each one with the same canned status and body.
    pub async fn contract_server(
        status: &'static str,
        response_body: Vec<u8>,
    ) -> (SocketAddr, Arc<Mutex<Vec<RecordedRequest>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let recorded = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&recorded);
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let request = read_request(&mut stream).await;
                sink.lock().unwrap().push(request);
                let head = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    response_body.len()
                );
                // The client may hang up early (for example once the byte
                // cap fires), so write errors are expected and ignored.
                let _ = stream.write_all(head.as_bytes()).await;
                let _ = stream.write_all(&response_body).await;
            }
        });
        (address, recorded)
    }

    /// Loopback fixture that reads one request and never answers it.
    pub async fn stalling_server() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let _request = read_request(&mut stream).await;
            // Hold the connection open until the client gives up.
            tokio::time::sleep(Duration::from_secs(60)).await;
            drop(stream);
        });
        address
    }

    /// Serializes a JSON value into response body bytes.
    pub fn json_bytes(value: serde_json::Value) -> Vec<u8> {
        value.to_string().into_bytes()
    }

    /// A body one byte over the shared 2 MiB provider response cap.
    pub fn oversized_body() -> Vec<u8> {
        vec![b'a'; 2 * 1024 * 1024 + 1]
    }

    /// Builds the configured adapter in runtime mode.
    pub fn embedder(config: &RagEmbeddingConfig, timeout: Duration) -> Arc<dyn Embedder> {
        sbproxy_rag::embedding::build(config, timeout, RagBuildMode::Runtime)
            .expect("embedding adapter construction failed")
    }
}

#[cfg(feature = "embedding-openai")]
mod openai {
    use std::net::SocketAddr;

    use sbproxy_ai::rag_config::RagEmbeddingConfig;
    use sbproxy_rag::EmbeddingError;

    use super::fixture::{
        contract_server, embedder, json_bytes, oversized_body, stalling_server, FIXTURE_TEXT,
        FIXTURE_TIMEOUT, SHORT_TIMEOUT,
    };

    fn config(address: SocketAddr, dimensions: Option<usize>) -> RagEmbeddingConfig {
        RagEmbeddingConfig::Openai {
            api_key: "fixture-key".to_owned(),
            base_url: format!("http://127.0.0.1:{}/v1", address.port()),
            model: "text-embedding-3-small".to_owned(),
            dimensions,
            allow_private_url: true,
        }
    }

    fn single_vector_body() -> Vec<u8> {
        json_bytes(serde_json::json!({
            "data": [{"index": 0, "embedding": [0.25, -0.5, 0.75]}]
        }))
    }

    #[tokio::test]
    async fn openai_request_matches_contract() {
        let (address, recorded) = contract_server("200 OK", single_vector_body()).await;
        let vector = embedder(&config(address, None), FIXTURE_TIMEOUT)
            .embed(FIXTURE_TEXT)
            .await
            .unwrap();
        assert_eq!(vector, vec![0.25, -0.5, 0.75]);

        let requests = recorded.lock().unwrap();
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/v1/embeddings");
        assert_eq!(request.header("authorization"), Some("Bearer fixture-key"));
        assert_eq!(request.header("content-type"), Some("application/json"));
        assert_eq!(
            request.body_json(),
            serde_json::json!({
                "model": "text-embedding-3-small",
                "input": [FIXTURE_TEXT],
                "encoding_format": "float",
            })
        );
    }

    #[tokio::test]
    async fn openai_includes_dimensions_only_when_configured() {
        let (address, recorded) = contract_server("200 OK", single_vector_body()).await;
        let vector = embedder(&config(address, Some(3)), FIXTURE_TIMEOUT)
            .embed(FIXTURE_TEXT)
            .await
            .unwrap();
        assert_eq!(vector.len(), 3);

        let requests = recorded.lock().unwrap();
        assert_eq!(
            requests[0].body_json(),
            serde_json::json!({
                "model": "text-embedding-3-small",
                "input": [FIXTURE_TEXT],
                "encoding_format": "float",
                "dimensions": 3,
            })
        );
    }

    #[tokio::test]
    async fn openai_batch_orders_embeddings_by_index() {
        let (address, recorded) = contract_server(
            "200 OK",
            json_bytes(serde_json::json!({
                "data": [
                    {"index": 1, "embedding": [2.0]},
                    {"index": 0, "embedding": [1.0]}
                ]
            })),
        )
        .await;
        let vectors = embedder(&config(address, None), FIXTURE_TIMEOUT)
            .embed_batch(&["first".to_owned(), "second".to_owned()])
            .await
            .unwrap();
        assert_eq!(vectors, vec![vec![1.0], vec![2.0]]);

        let requests = recorded.lock().unwrap();
        assert_eq!(
            requests[0].body_json()["input"],
            serde_json::json!(["first", "second"])
        );
    }

    #[tokio::test]
    async fn openai_duplicate_index_is_rejected() {
        let (address, _) = contract_server(
            "200 OK",
            json_bytes(serde_json::json!({
                "data": [
                    {"index": 0, "embedding": [1.0]},
                    {"index": 0, "embedding": [2.0]}
                ]
            })),
        )
        .await;
        let error = embedder(&config(address, None), FIXTURE_TIMEOUT)
            .embed_batch(&["first".to_owned(), "second".to_owned()])
            .await
            .unwrap_err();
        assert_eq!(
            error,
            EmbeddingError::MalformedResponse("duplicate embedding index")
        );
    }

    #[tokio::test]
    async fn openai_missing_index_is_rejected() {
        let (address, _) = contract_server(
            "200 OK",
            json_bytes(serde_json::json!({
                "data": [{"embedding": [0.25, -0.5, 0.75]}]
            })),
        )
        .await;
        let error = embedder(&config(address, None), FIXTURE_TIMEOUT)
            .embed(FIXTURE_TEXT)
            .await
            .unwrap_err();
        assert_eq!(
            error,
            EmbeddingError::MalformedResponse("embedding item has no index")
        );
    }

    #[tokio::test]
    async fn openai_empty_vector_is_rejected() {
        let (address, _) = contract_server(
            "200 OK",
            json_bytes(serde_json::json!({
                "data": [{"index": 0, "embedding": []}]
            })),
        )
        .await;
        let error = embedder(&config(address, None), FIXTURE_TIMEOUT)
            .embed(FIXTURE_TEXT)
            .await
            .unwrap_err();
        assert_eq!(
            error,
            EmbeddingError::MalformedResponse("provider returned an empty embedding vector")
        );
    }

    #[tokio::test]
    async fn openai_malformed_json_is_rejected() {
        let (address, _) = contract_server("200 OK", b"not json".to_vec()).await;
        let error = embedder(&config(address, None), FIXTURE_TIMEOUT)
            .embed(FIXTURE_TEXT)
            .await
            .unwrap_err();
        assert_eq!(
            error,
            EmbeddingError::MalformedResponse("response body is not valid json")
        );
    }

    #[tokio::test]
    async fn openai_non_2xx_status_is_rejected() {
        let (address, _) = contract_server(
            "500 Internal Server Error",
            json_bytes(serde_json::json!({"error": "boom"})),
        )
        .await;
        let error = embedder(&config(address, None), FIXTURE_TIMEOUT)
            .embed(FIXTURE_TEXT)
            .await
            .unwrap_err();
        assert_eq!(error, EmbeddingError::HttpStatus(500));
    }

    #[tokio::test]
    async fn openai_oversized_response_is_rejected() {
        let (address, _) = contract_server("200 OK", oversized_body()).await;
        let error = embedder(&config(address, None), FIXTURE_TIMEOUT)
            .embed(FIXTURE_TEXT)
            .await
            .unwrap_err();
        assert_eq!(error, EmbeddingError::ResponseTooLarge);
    }

    #[tokio::test]
    async fn openai_stalled_response_times_out() {
        let address = stalling_server().await;
        let error = embedder(&config(address, None), SHORT_TIMEOUT)
            .embed(FIXTURE_TEXT)
            .await
            .unwrap_err();
        assert_eq!(error, EmbeddingError::Timeout);
    }

    #[tokio::test]
    async fn openai_dimension_mismatch_is_rejected() {
        let (address, _) = contract_server("200 OK", single_vector_body()).await;
        let error = embedder(&config(address, Some(4)), FIXTURE_TIMEOUT)
            .embed(FIXTURE_TEXT)
            .await
            .unwrap_err();
        assert_eq!(
            error,
            EmbeddingError::DimensionMismatch {
                expected: 4,
                actual: 3,
            }
        );
    }

    #[tokio::test]
    async fn openai_non_finite_values_are_rejected() {
        // 1.0e39 is a finite f64 that overflows f32 to infinity, which is
        // how a non-finite value actually arrives over the JSON wire.
        let (address, _) = contract_server(
            "200 OK",
            json_bytes(serde_json::json!({
                "data": [{"index": 0, "embedding": [0.25, 1.0e39, 0.75]}]
            })),
        )
        .await;
        let error = embedder(&config(address, None), FIXTURE_TIMEOUT)
            .embed(FIXTURE_TEXT)
            .await
            .unwrap_err();
        assert_eq!(error, EmbeddingError::NonFinite);
    }
}

#[cfg(feature = "embedding-compatible")]
mod compatible {
    use std::net::SocketAddr;

    use sbproxy_ai::rag_config::RagEmbeddingConfig;
    use sbproxy_rag::EmbeddingError;

    use super::fixture::{
        contract_server, embedder, json_bytes, oversized_body, stalling_server, FIXTURE_TEXT,
        FIXTURE_TIMEOUT, SHORT_TIMEOUT,
    };

    fn config(
        address: SocketAddr,
        api_key: Option<&str>,
        auth_header: &str,
        auth_prefix: &str,
        dimensions: Option<usize>,
    ) -> RagEmbeddingConfig {
        RagEmbeddingConfig::Compatible {
            base_url: format!("http://127.0.0.1:{}/v1", address.port()),
            model: "fixture-embedding".to_owned(),
            api_key: api_key.map(str::to_owned),
            dimensions,
            auth_header: auth_header.to_owned(),
            auth_prefix: auth_prefix.to_owned(),
            allow_private_url: true,
        }
    }

    fn bearer_config(address: SocketAddr, dimensions: Option<usize>) -> RagEmbeddingConfig {
        config(
            address,
            Some("fixture-key"),
            "Authorization",
            "Bearer ",
            dimensions,
        )
    }

    fn single_vector_body() -> Vec<u8> {
        json_bytes(serde_json::json!({
            "data": [{"index": 0, "embedding": [0.25, -0.5, 0.75]}]
        }))
    }

    #[tokio::test]
    async fn compatible_request_without_key_sends_no_auth_header() {
        let (address, recorded) = contract_server("200 OK", single_vector_body()).await;
        let vector = embedder(
            &config(address, None, "Authorization", "Bearer ", None),
            FIXTURE_TIMEOUT,
        )
        .embed(FIXTURE_TEXT)
        .await
        .unwrap();
        assert_eq!(vector, vec![0.25, -0.5, 0.75]);

        let requests = recorded.lock().unwrap();
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/v1/embeddings");
        assert_eq!(request.header("authorization"), None);
        assert_eq!(request.header("api-key"), None);
        assert_eq!(
            request.body_json(),
            serde_json::json!({
                "model": "fixture-embedding",
                "input": [FIXTURE_TEXT],
                "encoding_format": "float",
            })
        );
    }

    #[tokio::test]
    async fn compatible_empty_prefix_sends_bare_credential() {
        let (address, recorded) = contract_server("200 OK", single_vector_body()).await;
        embedder(
            &config(address, Some("fixture-key"), "api-key", "", None),
            FIXTURE_TIMEOUT,
        )
        .embed(FIXTURE_TEXT)
        .await
        .unwrap();

        let requests = recorded.lock().unwrap();
        let request = &requests[0];
        assert_eq!(request.header("api-key"), Some("fixture-key"));
        assert_eq!(request.header("authorization"), None);
    }

    #[tokio::test]
    async fn compatible_default_auth_is_bearer() {
        let (address, recorded) = contract_server("200 OK", single_vector_body()).await;
        embedder(&bearer_config(address, None), FIXTURE_TIMEOUT)
            .embed(FIXTURE_TEXT)
            .await
            .unwrap();

        let requests = recorded.lock().unwrap();
        assert_eq!(
            requests[0].header("authorization"),
            Some("Bearer fixture-key")
        );
    }

    #[tokio::test]
    async fn compatible_malformed_json_is_rejected() {
        let (address, _) = contract_server("200 OK", b"not json".to_vec()).await;
        let error = embedder(&bearer_config(address, None), FIXTURE_TIMEOUT)
            .embed(FIXTURE_TEXT)
            .await
            .unwrap_err();
        assert_eq!(
            error,
            EmbeddingError::MalformedResponse("response body is not valid json")
        );
    }

    #[tokio::test]
    async fn compatible_non_2xx_status_is_rejected() {
        let (address, _) = contract_server(
            "503 Service Unavailable",
            json_bytes(serde_json::json!({"error": "down"})),
        )
        .await;
        let error = embedder(&bearer_config(address, None), FIXTURE_TIMEOUT)
            .embed(FIXTURE_TEXT)
            .await
            .unwrap_err();
        assert_eq!(error, EmbeddingError::HttpStatus(503));
    }

    #[tokio::test]
    async fn compatible_oversized_response_is_rejected() {
        let (address, _) = contract_server("200 OK", oversized_body()).await;
        let error = embedder(&bearer_config(address, None), FIXTURE_TIMEOUT)
            .embed(FIXTURE_TEXT)
            .await
            .unwrap_err();
        assert_eq!(error, EmbeddingError::ResponseTooLarge);
    }

    #[tokio::test]
    async fn compatible_stalled_response_times_out() {
        let address = stalling_server().await;
        let error = embedder(&bearer_config(address, None), SHORT_TIMEOUT)
            .embed(FIXTURE_TEXT)
            .await
            .unwrap_err();
        assert_eq!(error, EmbeddingError::Timeout);
    }

    #[tokio::test]
    async fn compatible_dimension_mismatch_is_rejected() {
        let (address, _) = contract_server("200 OK", single_vector_body()).await;
        let error = embedder(&bearer_config(address, Some(4)), FIXTURE_TIMEOUT)
            .embed(FIXTURE_TEXT)
            .await
            .unwrap_err();
        assert_eq!(
            error,
            EmbeddingError::DimensionMismatch {
                expected: 4,
                actual: 3,
            }
        );
    }

    #[tokio::test]
    async fn compatible_non_finite_values_are_rejected() {
        let (address, _) = contract_server(
            "200 OK",
            json_bytes(serde_json::json!({
                "data": [{"index": 0, "embedding": [0.25, 1.0e39, 0.75]}]
            })),
        )
        .await;
        let error = embedder(&bearer_config(address, None), FIXTURE_TIMEOUT)
            .embed(FIXTURE_TEXT)
            .await
            .unwrap_err();
        assert_eq!(error, EmbeddingError::NonFinite);
    }
}

#[cfg(feature = "embedding-cohere")]
mod cohere {
    use std::net::SocketAddr;

    use sbproxy_ai::rag_config::RagEmbeddingConfig;
    use sbproxy_rag::EmbeddingError;

    use super::fixture::{
        contract_server, embedder, json_bytes, oversized_body, stalling_server, FIXTURE_TEXT,
        FIXTURE_TIMEOUT, SHORT_TIMEOUT,
    };

    fn config(address: SocketAddr, output_dimension: Option<usize>) -> RagEmbeddingConfig {
        RagEmbeddingConfig::Cohere {
            api_key: "fixture-key".to_owned(),
            base_url: format!("http://127.0.0.1:{}", address.port()),
            model: "embed-v4.0".to_owned(),
            output_dimension,
            allow_private_url: true,
        }
    }

    fn single_vector_body() -> Vec<u8> {
        json_bytes(serde_json::json!({
            "embeddings": {"float": [[0.25, -0.5, 0.75]]}
        }))
    }

    #[tokio::test]
    async fn cohere_request_matches_contract() {
        let (address, recorded) = contract_server("200 OK", single_vector_body()).await;
        let vector = embedder(&config(address, None), FIXTURE_TIMEOUT)
            .embed(FIXTURE_TEXT)
            .await
            .unwrap();
        assert_eq!(vector, vec![0.25, -0.5, 0.75]);

        let requests = recorded.lock().unwrap();
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/v2/embed");
        assert_eq!(request.header("authorization"), Some("Bearer fixture-key"));
        assert_eq!(request.header("content-type"), Some("application/json"));
        assert_eq!(
            request.body_json(),
            serde_json::json!({
                "model": "embed-v4.0",
                "texts": [FIXTURE_TEXT],
                "input_type": "search_query",
                "embedding_types": ["float"],
            })
        );
    }

    #[tokio::test]
    async fn cohere_includes_output_dimension_only_when_configured() {
        let values = vec![0.5f64; 256];
        let (address, recorded) = contract_server(
            "200 OK",
            json_bytes(serde_json::json!({"embeddings": {"float": [values]}})),
        )
        .await;
        let vector = embedder(&config(address, Some(256)), FIXTURE_TIMEOUT)
            .embed(FIXTURE_TEXT)
            .await
            .unwrap();
        assert_eq!(vector, vec![0.5f32; 256]);

        let requests = recorded.lock().unwrap();
        assert_eq!(
            requests[0].body_json(),
            serde_json::json!({
                "model": "embed-v4.0",
                "texts": [FIXTURE_TEXT],
                "input_type": "search_query",
                "embedding_types": ["float"],
                "output_dimension": 256,
            })
        );
    }

    #[tokio::test]
    async fn cohere_batch_limit_is_enforced_locally() {
        let over_limit: Vec<String> = (0..97).map(|index| format!("text {index}")).collect();
        let float: Vec<serde_json::Value> = (0..96).map(|_| serde_json::json!([0.5])).collect();
        let (address, recorded) = contract_server(
            "200 OK",
            json_bytes(serde_json::json!({"embeddings": {"float": float}})),
        )
        .await;
        let adapter = embedder(&config(address, None), FIXTURE_TIMEOUT);

        let error = adapter.embed_batch(&over_limit).await.unwrap_err();
        assert_eq!(
            error,
            EmbeddingError::MalformedResponse("embedding batch exceeds the provider batch limit")
        );
        assert!(recorded.lock().unwrap().is_empty());

        // Exactly 96 texts still go out as one provider call.
        let at_limit: Vec<String> = over_limit[..96].to_vec();
        let vectors = adapter.embed_batch(&at_limit).await.unwrap();
        assert_eq!(vectors.len(), 96);
        assert_eq!(recorded.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn cohere_wrong_response_shape_is_rejected() {
        for body in [
            serde_json::json!({"embeddings": {"int8": [[1, 2, 3]]}}),
            serde_json::json!({"embeddings": [[0.25, -0.5, 0.75]]}),
        ] {
            let (address, _) = contract_server("200 OK", json_bytes(body)).await;
            let error = embedder(&config(address, None), FIXTURE_TIMEOUT)
                .embed(FIXTURE_TEXT)
                .await
                .unwrap_err();
            assert_eq!(
                error,
                EmbeddingError::MalformedResponse("response has no embeddings.float array")
            );
        }

        let (address, _) = contract_server(
            "200 OK",
            json_bytes(serde_json::json!({"embeddings": {"float": [42]}})),
        )
        .await;
        let error = embedder(&config(address, None), FIXTURE_TIMEOUT)
            .embed(FIXTURE_TEXT)
            .await
            .unwrap_err();
        assert_eq!(
            error,
            EmbeddingError::MalformedResponse("embedding vector is not an array")
        );
    }

    #[tokio::test]
    async fn cohere_count_mismatch_is_rejected() {
        let (address, _) = contract_server(
            "200 OK",
            json_bytes(serde_json::json!({
                "embeddings": {"float": [[0.25], [0.5]]}
            })),
        )
        .await;
        let error = embedder(&config(address, None), FIXTURE_TIMEOUT)
            .embed(FIXTURE_TEXT)
            .await
            .unwrap_err();
        assert_eq!(
            error,
            EmbeddingError::MalformedResponse("embedding count does not match input count")
        );
    }

    #[tokio::test]
    async fn cohere_malformed_json_is_rejected() {
        let (address, _) = contract_server("200 OK", b"not json".to_vec()).await;
        let error = embedder(&config(address, None), FIXTURE_TIMEOUT)
            .embed(FIXTURE_TEXT)
            .await
            .unwrap_err();
        assert_eq!(
            error,
            EmbeddingError::MalformedResponse("response body is not valid json")
        );
    }

    #[tokio::test]
    async fn cohere_non_2xx_status_is_rejected() {
        let (address, _) = contract_server(
            "429 Too Many Requests",
            json_bytes(serde_json::json!({"message": "slow down"})),
        )
        .await;
        let error = embedder(&config(address, None), FIXTURE_TIMEOUT)
            .embed(FIXTURE_TEXT)
            .await
            .unwrap_err();
        assert_eq!(error, EmbeddingError::HttpStatus(429));
    }

    #[tokio::test]
    async fn cohere_oversized_response_is_rejected() {
        let (address, _) = contract_server("200 OK", oversized_body()).await;
        let error = embedder(&config(address, None), FIXTURE_TIMEOUT)
            .embed(FIXTURE_TEXT)
            .await
            .unwrap_err();
        assert_eq!(error, EmbeddingError::ResponseTooLarge);
    }

    #[tokio::test]
    async fn cohere_stalled_response_times_out() {
        let address = stalling_server().await;
        let error = embedder(&config(address, None), SHORT_TIMEOUT)
            .embed(FIXTURE_TEXT)
            .await
            .unwrap_err();
        assert_eq!(error, EmbeddingError::Timeout);
    }

    #[tokio::test]
    async fn cohere_dimension_mismatch_is_rejected() {
        let (address, _) = contract_server("200 OK", single_vector_body()).await;
        let error = embedder(&config(address, Some(256)), FIXTURE_TIMEOUT)
            .embed(FIXTURE_TEXT)
            .await
            .unwrap_err();
        assert_eq!(
            error,
            EmbeddingError::DimensionMismatch {
                expected: 256,
                actual: 3,
            }
        );
    }

    #[tokio::test]
    async fn cohere_non_finite_values_are_rejected() {
        let (address, _) = contract_server(
            "200 OK",
            json_bytes(serde_json::json!({
                "embeddings": {"float": [[0.25, 1.0e39]]}
            })),
        )
        .await;
        let error = embedder(&config(address, None), FIXTURE_TIMEOUT)
            .embed(FIXTURE_TEXT)
            .await
            .unwrap_err();
        assert_eq!(error, EmbeddingError::NonFinite);
    }
}

#[cfg(feature = "embedding-bedrock")]
mod bedrock {
    use std::net::SocketAddr;

    use sbproxy_ai::rag_config::RagEmbeddingConfig;
    use sbproxy_rag::EmbeddingError;

    use super::fixture::{
        contract_server, embedder, json_bytes, oversized_body, stalling_server, FIXTURE_TEXT,
        FIXTURE_TIMEOUT, SHORT_TIMEOUT,
    };

    fn config(address: SocketAddr, dimensions: usize) -> RagEmbeddingConfig {
        RagEmbeddingConfig::Bedrock {
            api_key: "fixture-key".to_owned(),
            region: "us-east-1".to_owned(),
            model: "amazon.titan-embed-text-v2:0".to_owned(),
            dimensions,
            endpoint_override: Some(format!("http://127.0.0.1:{}", address.port())),
            allow_private_url: true,
        }
    }

    fn embedding_body(values: Vec<f64>) -> Vec<u8> {
        json_bytes(serde_json::json!({"embedding": values}))
    }

    #[tokio::test]
    async fn bedrock_embedding_request_matches_contract() {
        let (address, recorded) =
            contract_server("200 OK", embedding_body(vec![0.5f64; 1024])).await;
        let vector = embedder(&config(address, 1024), FIXTURE_TIMEOUT)
            .embed(FIXTURE_TEXT)
            .await
            .unwrap();
        assert_eq!(vector, vec![0.5f32; 1024]);

        let requests = recorded.lock().unwrap();
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/model/amazon.titan-embed-text-v2%3A0/invoke");
        assert_eq!(request.header("authorization"), Some("Bearer fixture-key"));
        assert_eq!(request.header("content-type"), Some("application/json"));
        assert_eq!(
            request.body_json(),
            serde_json::json!({
                "inputText": FIXTURE_TEXT,
                "dimensions": 1024,
                "normalize": true,
                "embeddingTypes": ["float"],
            })
        );
    }

    #[tokio::test]
    async fn bedrock_embedding_missing_or_binary_only_vector_is_rejected() {
        for body in [
            serde_json::json!({"embeddingsByType": {"binary": [1, 0, 1]}}),
            serde_json::json!({}),
        ] {
            let (address, _) = contract_server("200 OK", json_bytes(body)).await;
            let error = embedder(&config(address, 256), FIXTURE_TIMEOUT)
                .embed(FIXTURE_TEXT)
                .await
                .unwrap_err();
            assert_eq!(
                error,
                EmbeddingError::MalformedResponse("response has no float embedding vector")
            );
        }
    }

    #[tokio::test]
    async fn bedrock_embedding_batch_sends_one_request_per_input() {
        let (address, recorded) =
            contract_server("200 OK", embedding_body(vec![0.5f64; 256])).await;
        let vectors = embedder(&config(address, 256), FIXTURE_TIMEOUT)
            .embed_batch(&["first".to_owned(), "second".to_owned()])
            .await
            .unwrap();
        assert_eq!(vectors, vec![vec![0.5f32; 256], vec![0.5f32; 256]]);

        let requests = recorded.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(
            requests[0].body_json()["inputText"],
            serde_json::json!("first")
        );
        assert_eq!(
            requests[1].body_json()["inputText"],
            serde_json::json!("second")
        );
    }

    #[tokio::test]
    async fn bedrock_embedding_malformed_json_is_rejected() {
        let (address, _) = contract_server("200 OK", b"not json".to_vec()).await;
        let error = embedder(&config(address, 256), FIXTURE_TIMEOUT)
            .embed(FIXTURE_TEXT)
            .await
            .unwrap_err();
        assert_eq!(
            error,
            EmbeddingError::MalformedResponse("response body is not valid json")
        );
    }

    #[tokio::test]
    async fn bedrock_embedding_non_2xx_status_is_rejected() {
        let (address, _) = contract_server(
            "403 Forbidden",
            json_bytes(serde_json::json!({"message": "denied"})),
        )
        .await;
        let error = embedder(&config(address, 256), FIXTURE_TIMEOUT)
            .embed(FIXTURE_TEXT)
            .await
            .unwrap_err();
        assert_eq!(error, EmbeddingError::HttpStatus(403));
    }

    #[tokio::test]
    async fn bedrock_embedding_oversized_response_is_rejected() {
        let (address, _) = contract_server("200 OK", oversized_body()).await;
        let error = embedder(&config(address, 256), FIXTURE_TIMEOUT)
            .embed(FIXTURE_TEXT)
            .await
            .unwrap_err();
        assert_eq!(error, EmbeddingError::ResponseTooLarge);
    }

    #[tokio::test]
    async fn bedrock_embedding_stalled_response_times_out() {
        let address = stalling_server().await;
        let error = embedder(&config(address, 256), SHORT_TIMEOUT)
            .embed(FIXTURE_TEXT)
            .await
            .unwrap_err();
        assert_eq!(error, EmbeddingError::Timeout);
    }

    #[tokio::test]
    async fn bedrock_embedding_dimension_mismatch_is_rejected() {
        let (address, _) = contract_server("200 OK", embedding_body(vec![0.25, -0.5, 0.75])).await;
        let error = embedder(&config(address, 256), FIXTURE_TIMEOUT)
            .embed(FIXTURE_TEXT)
            .await
            .unwrap_err();
        assert_eq!(
            error,
            EmbeddingError::DimensionMismatch {
                expected: 256,
                actual: 3,
            }
        );
    }

    #[tokio::test]
    async fn bedrock_embedding_non_finite_values_are_rejected() {
        let mut values = vec![0.5f64; 256];
        values[7] = 1.0e39;
        let (address, _) = contract_server("200 OK", embedding_body(values)).await;
        let error = embedder(&config(address, 256), FIXTURE_TIMEOUT)
            .embed(FIXTURE_TEXT)
            .await
            .unwrap_err();
        assert_eq!(error, EmbeddingError::NonFinite);
    }
}

#[cfg(feature = "embedding-vertex")]
mod vertex {
    use std::net::SocketAddr;

    use sbproxy_ai::rag_config::RagEmbeddingConfig;
    use sbproxy_rag::EmbeddingError;

    use super::fixture::{
        contract_server, embedder, json_bytes, oversized_body, stalling_server, FIXTURE_TEXT,
        FIXTURE_TIMEOUT, SHORT_TIMEOUT,
    };

    fn config(address: SocketAddr, output_dimensionality: Option<usize>) -> RagEmbeddingConfig {
        RagEmbeddingConfig::Vertex {
            access_token: "fixture-token".to_owned(),
            project_id: "fixture-project".to_owned(),
            location: "us-central1".to_owned(),
            model: "gemini-embedding-001".to_owned(),
            output_dimensionality,
            endpoint_override: Some(format!("http://127.0.0.1:{}", address.port())),
            allow_private_url: true,
        }
    }

    fn prediction_body(values: serde_json::Value) -> Vec<u8> {
        json_bytes(serde_json::json!({
            "predictions": [{
                "embeddings": {
                    "statistics": {"truncated": false, "token_count": 4},
                    "values": values,
                }
            }]
        }))
    }

    #[tokio::test]
    async fn vertex_embedding_request_matches_contract() {
        let (address, recorded) = contract_server(
            "200 OK",
            prediction_body(serde_json::json!(vec![0.5f64; 768])),
        )
        .await;
        let vector = embedder(&config(address, Some(768)), FIXTURE_TIMEOUT)
            .embed(FIXTURE_TEXT)
            .await
            .unwrap();
        assert_eq!(vector, vec![0.5f32; 768]);

        let requests = recorded.lock().unwrap();
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        assert_eq!(request.method, "POST");
        assert_eq!(
            request.path,
            "/v1/projects/fixture-project/locations/us-central1/publishers/google/models/gemini-embedding-001:predict"
        );
        assert_eq!(
            request.header("authorization"),
            Some("Bearer fixture-token")
        );
        assert_eq!(request.header("content-type"), Some("application/json"));
        assert_eq!(
            request.body_json(),
            serde_json::json!({
                "instances": [{"content": FIXTURE_TEXT}],
                "parameters": {"autoTruncate": false, "outputDimensionality": 768},
            })
        );
    }

    #[tokio::test]
    async fn vertex_embedding_omits_output_dimensionality_when_not_configured() {
        let (address, recorded) = contract_server(
            "200 OK",
            prediction_body(serde_json::json!([0.25, -0.5, 0.75])),
        )
        .await;
        let vector = embedder(&config(address, None), FIXTURE_TIMEOUT)
            .embed(FIXTURE_TEXT)
            .await
            .unwrap();
        assert_eq!(vector, vec![0.25, -0.5, 0.75]);

        let requests = recorded.lock().unwrap();
        assert_eq!(
            requests[0].body_json(),
            serde_json::json!({
                "instances": [{"content": FIXTURE_TEXT}],
                "parameters": {"autoTruncate": false},
            })
        );
    }

    #[tokio::test]
    async fn vertex_embedding_truncated_response_is_rejected() {
        let (address, _) = contract_server(
            "200 OK",
            json_bytes(serde_json::json!({
                "predictions": [{
                    "embeddings": {
                        "statistics": {"truncated": true, "token_count": 4},
                        "values": [0.25, -0.5, 0.75],
                    }
                }]
            })),
        )
        .await;
        let error = embedder(&config(address, None), FIXTURE_TIMEOUT)
            .embed(FIXTURE_TEXT)
            .await
            .unwrap_err();
        assert_eq!(
            error,
            EmbeddingError::MalformedResponse("provider truncated the embedding input")
        );
    }

    #[tokio::test]
    async fn vertex_embedding_empty_or_multiple_predictions_are_rejected() {
        for body in [
            serde_json::json!({"predictions": []}),
            serde_json::json!({
                "predictions": [
                    {"embeddings": {"values": [0.25]}},
                    {"embeddings": {"values": [0.5]}}
                ]
            }),
        ] {
            let (address, _) = contract_server("200 OK", json_bytes(body)).await;
            let error = embedder(&config(address, None), FIXTURE_TIMEOUT)
                .embed(FIXTURE_TEXT)
                .await
                .unwrap_err();
            assert_eq!(
                error,
                EmbeddingError::MalformedResponse(
                    "response prediction count does not match input count"
                )
            );
        }
    }

    #[tokio::test]
    async fn vertex_embedding_batch_is_sequential_and_capped() {
        let over_limit: Vec<String> = (0..97).map(|index| format!("text {index}")).collect();
        let (address, recorded) =
            contract_server("200 OK", prediction_body(serde_json::json!([0.25]))).await;
        let adapter = embedder(&config(address, None), FIXTURE_TIMEOUT);

        let error = adapter.embed_batch(&over_limit).await.unwrap_err();
        assert_eq!(
            error,
            EmbeddingError::MalformedResponse("embedding batch exceeds the provider batch limit")
        );
        assert!(recorded.lock().unwrap().is_empty());

        // Under the cap, the adapter embeds one input per request.
        let vectors = adapter
            .embed_batch(&["first".to_owned(), "second".to_owned()])
            .await
            .unwrap();
        assert_eq!(vectors, vec![vec![0.25], vec![0.25]]);
        let requests = recorded.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(
            requests[0].body_json()["instances"][0]["content"],
            serde_json::json!("first")
        );
        assert_eq!(
            requests[1].body_json()["instances"][0]["content"],
            serde_json::json!("second")
        );
    }

    #[tokio::test]
    async fn vertex_embedding_malformed_json_is_rejected() {
        let (address, _) = contract_server("200 OK", b"not json".to_vec()).await;
        let error = embedder(&config(address, None), FIXTURE_TIMEOUT)
            .embed(FIXTURE_TEXT)
            .await
            .unwrap_err();
        assert_eq!(
            error,
            EmbeddingError::MalformedResponse("response body is not valid json")
        );
    }

    #[tokio::test]
    async fn vertex_embedding_non_2xx_status_is_rejected() {
        let (address, _) = contract_server(
            "401 Unauthorized",
            json_bytes(serde_json::json!({"error": {"status": "UNAUTHENTICATED"}})),
        )
        .await;
        let error = embedder(&config(address, None), FIXTURE_TIMEOUT)
            .embed(FIXTURE_TEXT)
            .await
            .unwrap_err();
        assert_eq!(error, EmbeddingError::HttpStatus(401));
    }

    #[tokio::test]
    async fn vertex_embedding_oversized_response_is_rejected() {
        let (address, _) = contract_server("200 OK", oversized_body()).await;
        let error = embedder(&config(address, None), FIXTURE_TIMEOUT)
            .embed(FIXTURE_TEXT)
            .await
            .unwrap_err();
        assert_eq!(error, EmbeddingError::ResponseTooLarge);
    }

    #[tokio::test]
    async fn vertex_embedding_stalled_response_times_out() {
        let address = stalling_server().await;
        let error = embedder(&config(address, None), SHORT_TIMEOUT)
            .embed(FIXTURE_TEXT)
            .await
            .unwrap_err();
        assert_eq!(error, EmbeddingError::Timeout);
    }

    #[tokio::test]
    async fn vertex_embedding_dimension_mismatch_is_rejected() {
        let (address, _) = contract_server(
            "200 OK",
            prediction_body(serde_json::json!([0.25, -0.5, 0.75])),
        )
        .await;
        let error = embedder(&config(address, Some(768)), FIXTURE_TIMEOUT)
            .embed(FIXTURE_TEXT)
            .await
            .unwrap_err();
        assert_eq!(
            error,
            EmbeddingError::DimensionMismatch {
                expected: 768,
                actual: 3,
            }
        );
    }

    #[tokio::test]
    async fn vertex_embedding_non_finite_values_are_rejected() {
        let (address, _) =
            contract_server("200 OK", prediction_body(serde_json::json!([0.25, 1.0e39]))).await;
        let error = embedder(&config(address, None), FIXTURE_TIMEOUT)
            .embed(FIXTURE_TEXT)
            .await
            .unwrap_err();
        assert_eq!(error, EmbeddingError::NonFinite);
    }
}
