//! OpenAI ⇄ Google Gemini embeddings translator (WOR-824 item 2).
//!
//! Maps the OpenAI `/v1/embeddings` shape to and from Google's
//! Generative Language `embedContent` (single input) and
//! `batchEmbedContents` (array input) APIs. The endpoint choice is
//! driven by the OpenAI request's `input` field: a single string
//! goes to `embedContent`; an array of strings or token ids goes
//! to `batchEmbedContents`.
//!
//! ## What translates
//!
//! Request:
//!
//! | OpenAI | Google embedContent / batchEmbedContents |
//! |---|---|
//! | `model: "text-embedding-3-small"` | `model: "models/<m>"` (path rewrite) |
//! | `input: "..."` | `content: { parts: [{text: "..."}] }` (single) |
//! | `input: ["a", "b"]` | `requests: [{model, content: {parts: [{text: "a"}]}}, ...]` (batch) |
//! | `dimensions: N` (optional) | `outputDimensionality: N` |
//! | `encoding_format: "float"` | (default; Gemini returns floats) |
//!
//! Response:
//!
//! | Google | OpenAI |
//! |---|---|
//! | `{embedding: {values: [...]}}` | `{object:"list", data:[{object:"embedding", embedding:[...], index:0}]}` |
//! | `{embeddings: [{values: [...]}, ...]}` | `{object:"list", data:[{object:"embedding", embedding:[...], index:i}, ...]}` |
//!
//! ## What does not translate
//!
//! * `encoding_format: "base64"` - OpenAI's compact binary form is
//!   not in Gemini's API. The translator currently emits OpenAI's
//!   default `float` representation regardless of the request's
//!   `encoding_format`; a downstream consumer that requires base64
//!   should fall back to a non-Gemini provider.
//! * `user` (the per-end-user attribution tag) - Gemini has no
//!   equivalent; dropped silently.
//! * Tokenised input (`input: [1234, 5678]`) - Gemini accepts text
//!   parts only. Token-id input is passed through to Gemini as
//!   stringified numbers; the upstream will likely reject it. Real
//!   embedding clients send text.

use serde_json::{json, Map, Value};

/// Convert an OpenAI `/v1/embeddings` request to Gemini's
/// `embedContent` (single) or `batchEmbedContents` (array) shape.
/// Returns the new body + the rewritten path including the model.
pub fn request_to_native(body: Value, _path: &str) -> (Value, String) {
    let obj: Map<String, Value> = match body {
        Value::Object(m) => m,
        // Non-object bodies cannot be translated; return the raw
        // input + the default embed endpoint so the upstream
        // surfaces its own error. The chat translator does the
        // same for non-object bodies.
        other => {
            return (
                other,
                "/v1beta/models/text-embedding-004:embedContent".to_string(),
            );
        }
    };

    let model = obj
        .get("model")
        .and_then(|v| v.as_str())
        .unwrap_or("text-embedding-004")
        .to_string();
    let model_segment = if model.starts_with("models/") {
        model.trim_start_matches("models/").to_string()
    } else {
        model
    };

    let dimensions = obj.get("dimensions").cloned();

    match obj.get("input") {
        // Single string input → embedContent.
        Some(Value::String(text)) => {
            let mut native = Map::new();
            native.insert(
                "model".to_string(),
                Value::String(format!("models/{model_segment}")),
            );
            native.insert("content".to_string(), text_to_content(text));
            if let Some(d) = dimensions {
                native.insert("outputDimensionality".to_string(), d);
            }
            (
                Value::Object(native),
                format!("/v1beta/models/{model_segment}:embedContent"),
            )
        }
        // Array input → batchEmbedContents. Each entry becomes a
        // sub-request with its own content. Per the Gemini spec
        // each sub-request carries its own `model`.
        Some(Value::Array(arr)) => {
            let requests: Vec<Value> = arr
                .iter()
                .map(|item| {
                    let text = match item {
                        Value::String(s) => s.clone(),
                        Value::Number(n) => n.to_string(),
                        _ => item.to_string(),
                    };
                    let mut sub = Map::new();
                    sub.insert(
                        "model".to_string(),
                        Value::String(format!("models/{model_segment}")),
                    );
                    sub.insert("content".to_string(), text_to_content(&text));
                    if let Some(d) = dimensions.as_ref() {
                        sub.insert("outputDimensionality".to_string(), d.clone());
                    }
                    Value::Object(sub)
                })
                .collect();
            let mut native = Map::new();
            native.insert("requests".to_string(), Value::Array(requests));
            (
                Value::Object(native),
                format!("/v1beta/models/{model_segment}:batchEmbedContents"),
            )
        }
        // Missing or unrecognised input shape: emit an
        // empty-but-well-formed request so the upstream produces a
        // clear error. Avoids panicking on malformed client input.
        _ => {
            let mut native = Map::new();
            native.insert(
                "model".to_string(),
                Value::String(format!("models/{model_segment}")),
            );
            native.insert("content".to_string(), text_to_content(""));
            (
                Value::Object(native),
                format!("/v1beta/models/{model_segment}:embedContent"),
            )
        }
    }
}

/// Wrap a string in Gemini's `{ parts: [{text: "..."}] }` shape.
fn text_to_content(text: &str) -> Value {
    json!({
        "parts": [{"text": text}],
    })
}

/// Convert a Gemini embedding response back to OpenAI shape.
/// Handles both single (`{embedding: {values: [...]}}`) and batch
/// (`{embeddings: [{values: [...]}, ...]}`) responses.
pub fn response_to_openai(body: Value) -> Value {
    let obj = match body {
        Value::Object(m) => m,
        other => return other,
    };

    // Single-embedding shape.
    if let Some(Value::Object(emb)) = obj
        .get("embedding")
        .cloned()
        .map(|_| obj.get("embedding").cloned().unwrap())
    {
        // Borrow the values from the original obj reference.
        let values = emb.get("values").cloned().unwrap_or(Value::Null);
        return json!({
            "object": "list",
            "data": [{
                "object": "embedding",
                "embedding": values,
                "index": 0,
            }],
            "model": "",
            "usage": {
                "prompt_tokens": 0,
                "total_tokens": 0,
            },
        });
    }

    // Batch shape.
    if let Some(arr) = obj.get("embeddings").and_then(|v| v.as_array()) {
        let data: Vec<Value> = arr
            .iter()
            .enumerate()
            .map(|(i, e)| {
                let values = e.get("values").cloned().unwrap_or(Value::Null);
                json!({
                    "object": "embedding",
                    "embedding": values,
                    "index": i,
                })
            })
            .collect();
        return json!({
            "object": "list",
            "data": data,
            "model": "",
            "usage": {
                "prompt_tokens": 0,
                "total_tokens": 0,
            },
        });
    }

    // Unrecognised shape (probably an error envelope): pass through
    // so the proxy's downstream error mapper handles it.
    Value::Object(obj)
}

/// Path-based predicate that the gemini translator dispatch uses
/// to decide whether to send a request to the embeddings sub-
/// translator or the chat sub-translator. Embeddings reach the
/// gateway on `/v1/embeddings` (with optional `/api/v1` prefix and
/// any trailing slash) per `classify_surface`.
pub fn is_embeddings_path(path: &str) -> bool {
    let stripped = path.strip_prefix("/api").unwrap_or(path);
    let trimmed = stripped.trim_end_matches('/');
    trimmed == "/v1/embeddings"
}

/// Shape-based predicate that the gemini translator dispatch uses
/// to decide whether a response body is an embedding response or a
/// chat response. Gemini embedding responses carry an `embedding`
/// or `embeddings` field at the top level; chat responses carry
/// `candidates`. The detect-by-shape approach avoids threading the
/// path through the existing `response_to_openai` signature.
pub fn looks_like_embeddings_response(body: &Value) -> bool {
    let Some(obj) = body.as_object() else {
        return false;
    };
    (obj.contains_key("embedding") || obj.contains_key("embeddings"))
        && !obj.contains_key("candidates")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_string_input_maps_to_embed_content() {
        let body = json!({
            "model": "text-embedding-3-small",
            "input": "Hello, world",
        });
        let (out, path) = request_to_native(body, "/v1/embeddings");
        assert_eq!(
            path, "/v1beta/models/text-embedding-3-small:embedContent",
            "single string → embedContent + model path"
        );
        assert_eq!(out["model"], "models/text-embedding-3-small");
        assert_eq!(out["content"]["parts"][0]["text"], "Hello, world");
    }

    #[test]
    fn array_input_maps_to_batch_embed_contents() {
        let body = json!({
            "model": "text-embedding-004",
            "input": ["alpha", "beta", "gamma"],
        });
        let (out, path) = request_to_native(body, "/v1/embeddings");
        assert_eq!(
            path, "/v1beta/models/text-embedding-004:batchEmbedContents",
            "array input → batchEmbedContents"
        );
        let reqs = out["requests"].as_array().expect("requests array");
        assert_eq!(reqs.len(), 3);
        assert_eq!(reqs[0]["content"]["parts"][0]["text"], "alpha");
        assert_eq!(reqs[1]["content"]["parts"][0]["text"], "beta");
        assert_eq!(reqs[2]["content"]["parts"][0]["text"], "gamma");
        for r in reqs {
            assert_eq!(r["model"], "models/text-embedding-004");
        }
    }

    #[test]
    fn dimensions_translates_to_output_dimensionality() {
        let body = json!({
            "model": "text-embedding-004",
            "input": "test",
            "dimensions": 256,
        });
        let (out, _) = request_to_native(body, "/v1/embeddings");
        assert_eq!(out["outputDimensionality"], 256);
    }

    #[test]
    fn dimensions_propagates_to_every_batch_sub_request() {
        let body = json!({
            "model": "text-embedding-004",
            "input": ["a", "b"],
            "dimensions": 128,
        });
        let (out, _) = request_to_native(body, "/v1/embeddings");
        let reqs = out["requests"].as_array().unwrap();
        for r in reqs {
            assert_eq!(r["outputDimensionality"], 128);
        }
    }

    #[test]
    fn model_with_models_prefix_does_not_duplicate() {
        let body = json!({
            "model": "models/text-embedding-004",
            "input": "test",
        });
        let (out, path) = request_to_native(body, "/v1/embeddings");
        assert_eq!(out["model"], "models/text-embedding-004");
        assert_eq!(path, "/v1beta/models/text-embedding-004:embedContent");
    }

    #[test]
    fn missing_model_falls_back_to_default() {
        let body = json!({"input": "test"});
        let (out, path) = request_to_native(body, "/v1/embeddings");
        assert_eq!(out["model"], "models/text-embedding-004");
        assert_eq!(path, "/v1beta/models/text-embedding-004:embedContent");
    }

    #[test]
    fn response_single_embedding_maps_to_openai_list() {
        let gemini = json!({
            "embedding": {
                "values": [0.1, 0.2, 0.3, 0.4],
            },
        });
        let openai = response_to_openai(gemini);
        assert_eq!(openai["object"], "list");
        let data = openai["data"].as_array().unwrap();
        assert_eq!(data.len(), 1);
        assert_eq!(data[0]["object"], "embedding");
        assert_eq!(data[0]["index"], 0);
        let emb = data[0]["embedding"].as_array().unwrap();
        assert_eq!(emb.len(), 4);
        assert_eq!(emb[0], 0.1);
    }

    #[test]
    fn response_batch_embeddings_map_to_openai_list_in_order() {
        let gemini = json!({
            "embeddings": [
                {"values": [0.1, 0.2]},
                {"values": [0.3, 0.4]},
                {"values": [0.5, 0.6]},
            ],
        });
        let openai = response_to_openai(gemini);
        let data = openai["data"].as_array().unwrap();
        assert_eq!(data.len(), 3);
        // Indices preserve the input order.
        for (i, d) in data.iter().enumerate() {
            assert_eq!(d["index"], i);
            assert_eq!(d["object"], "embedding");
        }
        assert_eq!(data[1]["embedding"][0], 0.3);
        assert_eq!(data[2]["embedding"][1], 0.6);
    }

    #[test]
    fn response_unrecognised_shape_passes_through() {
        // Gemini error envelope; not an embedding shape.
        let body = json!({
            "error": {
                "code": 400,
                "message": "Invalid request",
            },
        });
        let out = response_to_openai(body.clone());
        // Round-trip preservation.
        assert_eq!(out["error"]["code"], 400);
        assert_eq!(out["error"]["message"], "Invalid request");
    }

    #[test]
    fn is_embeddings_path_handles_canonical_and_api_prefix() {
        assert!(is_embeddings_path("/v1/embeddings"));
        assert!(is_embeddings_path("/api/v1/embeddings"));
        assert!(is_embeddings_path("/v1/embeddings/"));
        assert!(!is_embeddings_path("/v1/chat/completions"));
        assert!(!is_embeddings_path("/v1/embeddings/extra"));
    }

    #[test]
    fn looks_like_embeddings_response_detects_correctly() {
        // Single embedding.
        assert!(looks_like_embeddings_response(&json!({
            "embedding": {"values": [0.1]}
        })));
        // Batch.
        assert!(looks_like_embeddings_response(&json!({
            "embeddings": [{"values": [0.1]}]
        })));
        // Chat response has candidates - NOT an embedding shape.
        assert!(!looks_like_embeddings_response(&json!({
            "candidates": [{"content": {"parts": [{"text": "hi"}]}}]
        })));
        // Empty object.
        assert!(!looks_like_embeddings_response(&json!({})));
        // Non-object.
        assert!(!looks_like_embeddings_response(&json!(42)));
    }
}
