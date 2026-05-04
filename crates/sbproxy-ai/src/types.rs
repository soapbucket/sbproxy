//! Core AI types - OpenAI-compatible request/response structures.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A chat completion request (OpenAI-compatible format).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatRequest {
    /// Model identifier (e.g. "gpt-4", "claude-3-sonnet").
    pub model: String,
    /// Ordered list of conversation messages forming the prompt.
    pub messages: Vec<Message>,
    /// Whether to stream the response as Server-Sent Events.
    #[serde(default)]
    pub stream: bool,
    /// Sampling temperature (0.0 deterministic, higher more random).
    #[serde(default)]
    pub temperature: Option<f64>,
    /// Maximum number of tokens to generate in the completion.
    #[serde(default)]
    pub max_tokens: Option<u32>,
    /// Nucleus sampling probability cutoff.
    #[serde(default)]
    pub top_p: Option<f64>,
    /// Provider-specific extra fields preserved as-is.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// A chat message with role and content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// Message author role (e.g. "system", "user", "assistant", "tool").
    pub role: String,
    /// String or array for multimodal content.
    pub content: serde_json::Value,
}

/// A chat completion response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatResponse {
    /// Provider-assigned response identifier.
    pub id: String,
    /// Object type tag, typically "chat.completion".
    pub object: String,
    /// Unix timestamp (seconds) when the response was created.
    pub created: u64,
    /// Model identifier that produced the response.
    pub model: String,
    /// One or more candidate completions.
    pub choices: Vec<Choice>,
    /// Token usage statistics for billing and metrics.
    #[serde(default)]
    pub usage: Option<Usage>,
}

/// A single choice in a chat completion response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Choice {
    /// Zero-based index of this choice in the response.
    pub index: u32,
    /// The assistant message produced for this choice.
    pub message: Message,
    /// Reason the model stopped (e.g. "stop", "length", "tool_calls").
    pub finish_reason: Option<String>,
}

/// Token usage statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Usage {
    /// Number of tokens in the prompt sent to the model.
    pub prompt_tokens: u32,
    /// Number of tokens in the model's completion.
    pub completion_tokens: u32,
    /// Total tokens billed (prompt + completion).
    pub total_tokens: u32,
}

/// A streaming chunk in an SSE stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamChunk {
    /// Provider-assigned response identifier (matches across chunks).
    pub id: String,
    /// Object type tag, typically "chat.completion.chunk".
    pub object: String,
    /// Unix timestamp (seconds) when the chunk was created.
    pub created: u64,
    /// Model identifier producing the stream.
    pub model: String,
    /// Delta choices contained in this chunk.
    pub choices: Vec<StreamChoice>,
    /// Optional usage stats, typically only present on the final chunk.
    #[serde(default)]
    pub usage: Option<Usage>,
}

/// A single choice in a streaming chunk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamChoice {
    /// Zero-based index of this choice across the stream.
    pub index: u32,
    /// Incremental delta for this choice.
    pub delta: Delta,
    /// Reason the stream ended for this choice, if present.
    pub finish_reason: Option<String>,
}

/// Delta content in a streaming choice.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Delta {
    /// Author role on the first delta of a message.
    #[serde(default)]
    pub role: Option<String>,
    /// Incremental text content appended in this delta.
    #[serde(default)]
    pub content: Option<String>,
}

/// An embedding request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddingRequest {
    /// Embedding model identifier.
    pub model: String,
    /// String or array of strings.
    pub input: serde_json::Value,
}

/// An embedding response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddingResponse {
    /// Object type tag, typically "list".
    pub object: String,
    /// One embedding vector per input string.
    pub data: Vec<EmbeddingData>,
    /// Model identifier that produced the embeddings.
    pub model: String,
    /// Token usage for the embedding request.
    pub usage: Usage,
}

/// A single embedding vector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddingData {
    /// Object type tag, typically "embedding".
    pub object: String,
    /// Dense vector of embedding values.
    pub embedding: Vec<f64>,
    /// Zero-based index matching the position in the input array.
    pub index: u32,
}

/// Model info returned from the /models endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelInfo {
    /// Stable model identifier used in API requests.
    pub id: String,
    /// Object type tag, typically "model".
    pub object: String,
    /// Organization that owns or hosts the model.
    pub owned_by: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chat_request_roundtrip() {
        let req = ChatRequest {
            model: "gpt-4".to_string(),
            messages: vec![
                Message {
                    role: "system".to_string(),
                    content: serde_json::json!("You are helpful."),
                },
                Message {
                    role: "user".to_string(),
                    content: serde_json::json!("Hello"),
                },
            ],
            stream: false,
            temperature: Some(0.7),
            max_tokens: Some(100),
            top_p: None,
            extra: HashMap::new(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: ChatRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.model, "gpt-4");
        assert_eq!(parsed.messages.len(), 2);
        assert_eq!(parsed.messages[0].role, "system");
        assert_eq!(parsed.temperature, Some(0.7));
        assert_eq!(parsed.max_tokens, Some(100));
        assert!(!parsed.stream);
    }

    #[test]
    fn chat_request_stream_default() {
        let json = serde_json::json!({
            "model": "gpt-4",
            "messages": [{"role": "user", "content": "hi"}]
        });
        let req: ChatRequest = serde_json::from_value(json).unwrap();
        assert!(!req.stream);
    }

    #[test]
    fn chat_request_extra_fields() {
        let json = serde_json::json!({
            "model": "gpt-4",
            "messages": [{"role": "user", "content": "hi"}],
            "frequency_penalty": 0.5,
            "presence_penalty": 0.3
        });
        let req: ChatRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.extra["frequency_penalty"], 0.5);
        assert_eq!(req.extra["presence_penalty"], 0.3);
    }

    #[test]
    fn chat_response_roundtrip() {
        let resp = ChatResponse {
            id: "chatcmpl-123".to_string(),
            object: "chat.completion".to_string(),
            created: 1700000000,
            model: "gpt-4".to_string(),
            choices: vec![Choice {
                index: 0,
                message: Message {
                    role: "assistant".to_string(),
                    content: serde_json::json!("Hello!"),
                },
                finish_reason: Some("stop".to_string()),
            }],
            usage: Some(Usage {
                prompt_tokens: 10,
                completion_tokens: 5,
                total_tokens: 15,
            }),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: ChatResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, "chatcmpl-123");
        assert_eq!(parsed.choices.len(), 1);
        assert_eq!(parsed.choices[0].finish_reason.as_deref(), Some("stop"));
        let usage = parsed.usage.unwrap();
        assert_eq!(usage.total_tokens, 15);
    }

    #[test]
    fn chat_response_no_usage() {
        let json = serde_json::json!({
            "id": "chatcmpl-1",
            "object": "chat.completion",
            "created": 1700000000,
            "model": "gpt-4",
            "choices": []
        });
        let resp: ChatResponse = serde_json::from_value(json).unwrap();
        assert!(resp.usage.is_none());
    }

    #[test]
    fn message_multimodal_content() {
        let json = serde_json::json!({
            "role": "user",
            "content": [
                {"type": "text", "text": "What is in this image?"},
                {"type": "image_url", "image_url": {"url": "https://example.com/img.png"}}
            ]
        });
        let msg: Message = serde_json::from_value(json).unwrap();
        assert_eq!(msg.role, "user");
        assert!(msg.content.is_array());
        assert_eq!(msg.content.as_array().unwrap().len(), 2);
    }

    #[test]
    fn embedding_request_roundtrip() {
        let req = EmbeddingRequest {
            model: "text-embedding-3-small".to_string(),
            input: serde_json::json!("Hello world"),
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: EmbeddingRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.model, "text-embedding-3-small");
        assert_eq!(parsed.input, "Hello world");
    }

    #[test]
    fn embedding_request_array_input() {
        let json = serde_json::json!({
            "model": "text-embedding-3-small",
            "input": ["hello", "world"]
        });
        let req: EmbeddingRequest = serde_json::from_value(json).unwrap();
        assert!(req.input.is_array());
    }

    #[test]
    fn embedding_response_roundtrip() {
        let resp = EmbeddingResponse {
            object: "list".to_string(),
            data: vec![EmbeddingData {
                object: "embedding".to_string(),
                embedding: vec![0.1, 0.2, 0.3],
                index: 0,
            }],
            model: "text-embedding-3-small".to_string(),
            usage: Usage {
                prompt_tokens: 5,
                completion_tokens: 0,
                total_tokens: 5,
            },
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: EmbeddingResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.data.len(), 1);
        assert_eq!(parsed.data[0].embedding.len(), 3);
    }

    #[test]
    fn model_info_roundtrip() {
        let info = ModelInfo {
            id: "gpt-4".to_string(),
            object: "model".to_string(),
            owned_by: "openai".to_string(),
        };
        let json = serde_json::to_string(&info).unwrap();
        let parsed: ModelInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, "gpt-4");
        assert_eq!(parsed.owned_by, "openai");
    }
}
