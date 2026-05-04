//! Multi-modal request routing.
//!
//! Detects whether a request is text, image, audio, or video
//! and routes to a provider that supports that modality.

/// The detected modality of an AI request.
#[derive(Debug, Clone, PartialEq)]
pub enum Modality {
    /// Plain text chat or completion request.
    Text,
    /// Image generation or editing request.
    Image,
    /// Audio transcription or text-to-speech request.
    Audio,
    /// Video generation or editing request.
    Video,
    /// Embedding generation request.
    Embedding,
    /// Mixed content (e.g. chat with image_url in messages).
    Multimodal,
}

/// Detect the modality of an AI request from its endpoint path and optional body.
///
/// Detection rules (in priority order):
/// - `/v1/audio/*` -> Audio
/// - `/v1/images/*` or `/v1/image/*` -> Image
/// - `/v1/embeddings` -> Embedding
/// - `/v1/video/*` -> Video
/// - `/v1/chat/completions` with `image_url` content parts -> Multimodal
/// - Otherwise -> Text
pub fn detect_modality(path: &str, body: Option<&serde_json::Value>) -> Modality {
    let path_lower = path.to_lowercase();

    // Audio endpoints
    if path_lower.contains("/audio/") {
        return Modality::Audio;
    }

    // Image generation endpoints
    if path_lower.contains("/images/") || path_lower.contains("/image/") {
        return Modality::Image;
    }

    // Embedding endpoints
    if path_lower.contains("/embeddings") {
        return Modality::Embedding;
    }

    // Video endpoints
    if path_lower.contains("/video/") || path_lower.contains("/videos/") {
        return Modality::Video;
    }

    // Check message content for image_url parts (multimodal chat)
    if let Some(body) = body {
        if has_image_url_content(body) {
            return Modality::Multimodal;
        }
    }

    Modality::Text
}

/// Returns true if the request body contains image_url content parts in messages.
fn has_image_url_content(body: &serde_json::Value) -> bool {
    let Some(messages) = body.get("messages").and_then(|m| m.as_array()) else {
        return false;
    };
    for message in messages {
        let Some(content) = message.get("content") else {
            continue;
        };
        // Content can be a string (text-only) or an array of content parts
        if let Some(parts) = content.as_array() {
            for part in parts {
                if part.get("type").and_then(|t| t.as_str()) == Some("image_url") {
                    return true;
                }
                // Also check for base64 image data
                if part.get("type").and_then(|t| t.as_str()) == Some("image") {
                    return true;
                }
            }
        }
    }
    false
}

/// Check if a provider supports a given modality.
pub fn provider_supports_modality(provider: &str, modality: &Modality) -> bool {
    match (provider, modality) {
        // OpenAI supports all modalities
        ("openai", _) => true,
        // Anthropic supports text and multimodal (vision) but not audio/image-gen/video/embeddings
        ("anthropic", Modality::Text | Modality::Multimodal) => true,
        ("anthropic", _) => false,
        // Gemini supports all modalities
        ("gemini", _) => true,
        // Cohere supports text and embeddings
        ("cohere", Modality::Text | Modality::Embedding) => true,
        ("cohere", _) => false,
        // Mistral supports text and embeddings
        ("mistral", Modality::Text | Modality::Embedding) => true,
        ("mistral", _) => false,
        // Groq supports text and audio transcription
        ("groq", Modality::Text | Modality::Audio) => true,
        ("groq", _) => false,
        // Unknown providers: assume text-only
        (_, Modality::Text) => true,
        (_, _) => false,
    }
}

/// Filter providers to only those supporting the detected modality.
pub fn filter_providers_by_modality(providers: &[String], modality: &Modality) -> Vec<String> {
    providers
        .iter()
        .filter(|p| provider_supports_modality(p, modality))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // --- detect_modality tests ---

    #[test]
    fn detect_text_from_chat_completions() {
        let body = json!({
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "hello"}]
        });
        assert_eq!(
            detect_modality("/v1/chat/completions", Some(&body)),
            Modality::Text
        );
    }

    #[test]
    fn detect_text_with_no_body() {
        assert_eq!(
            detect_modality("/v1/chat/completions", None),
            Modality::Text
        );
    }

    #[test]
    fn detect_image_from_generations_path() {
        assert_eq!(
            detect_modality("/v1/images/generations", None),
            Modality::Image
        );
    }

    #[test]
    fn detect_image_from_edits_path() {
        assert_eq!(detect_modality("/v1/images/edits", None), Modality::Image);
    }

    #[test]
    fn detect_audio_from_transcriptions_path() {
        assert_eq!(
            detect_modality("/v1/audio/transcriptions", None),
            Modality::Audio
        );
    }

    #[test]
    fn detect_audio_from_speech_path() {
        assert_eq!(detect_modality("/v1/audio/speech", None), Modality::Audio);
    }

    #[test]
    fn detect_embedding_from_embeddings_path() {
        assert_eq!(detect_modality("/v1/embeddings", None), Modality::Embedding);
    }

    #[test]
    fn detect_video_from_video_path() {
        assert_eq!(detect_modality("/v1/video/generate", None), Modality::Video);
    }

    #[test]
    fn detect_multimodal_from_image_url_in_messages() {
        let body = json!({
            "model": "gpt-4o",
            "messages": [{
                "role": "user",
                "content": [
                    {"type": "text", "text": "What is in this image?"},
                    {"type": "image_url", "image_url": {"url": "https://example.com/img.png"}}
                ]
            }]
        });
        assert_eq!(
            detect_modality("/v1/chat/completions", Some(&body)),
            Modality::Multimodal
        );
    }

    #[test]
    fn detect_text_when_content_is_string_not_array() {
        let body = json!({
            "messages": [{"role": "user", "content": "just text"}]
        });
        assert_eq!(
            detect_modality("/v1/chat/completions", Some(&body)),
            Modality::Text
        );
    }

    #[test]
    fn detect_multimodal_from_image_content_part() {
        let body = json!({
            "model": "claude-sonnet-4-5",
            "messages": [{
                "role": "user",
                "content": [
                    {"type": "text", "text": "Describe this"},
                    {"type": "image", "source": {"type": "base64", "media_type": "image/jpeg", "data": "..."}}
                ]
            }]
        });
        assert_eq!(
            detect_modality("/v1/chat/completions", Some(&body)),
            Modality::Multimodal
        );
    }

    // --- provider_supports_modality tests ---

    #[test]
    fn openai_supports_all_modalities() {
        for modality in &[
            Modality::Text,
            Modality::Image,
            Modality::Audio,
            Modality::Video,
            Modality::Embedding,
            Modality::Multimodal,
        ] {
            assert!(
                provider_supports_modality("openai", modality),
                "OpenAI should support {:?}",
                modality
            );
        }
    }

    #[test]
    fn anthropic_supports_text_and_multimodal_only() {
        assert!(provider_supports_modality("anthropic", &Modality::Text));
        assert!(provider_supports_modality(
            "anthropic",
            &Modality::Multimodal
        ));
        assert!(!provider_supports_modality("anthropic", &Modality::Image));
        assert!(!provider_supports_modality("anthropic", &Modality::Audio));
        assert!(!provider_supports_modality("anthropic", &Modality::Video));
        assert!(!provider_supports_modality(
            "anthropic",
            &Modality::Embedding
        ));
    }

    #[test]
    fn gemini_supports_all_modalities() {
        assert!(provider_supports_modality("gemini", &Modality::Text));
        assert!(provider_supports_modality("gemini", &Modality::Image));
        assert!(provider_supports_modality("gemini", &Modality::Audio));
        assert!(provider_supports_modality("gemini", &Modality::Video));
    }

    #[test]
    fn unknown_provider_supports_text_only() {
        assert!(provider_supports_modality(
            "unknown-provider",
            &Modality::Text
        ));
        assert!(!provider_supports_modality(
            "unknown-provider",
            &Modality::Image
        ));
        assert!(!provider_supports_modality(
            "unknown-provider",
            &Modality::Audio
        ));
    }

    // --- filter_providers_by_modality tests ---

    #[test]
    fn filter_keeps_supporting_providers() {
        let providers = vec![
            "openai".to_string(),
            "anthropic".to_string(),
            "cohere".to_string(),
        ];
        let filtered = filter_providers_by_modality(&providers, &Modality::Audio);
        assert_eq!(filtered, vec!["openai"]);
    }

    #[test]
    fn filter_text_keeps_all_known_providers() {
        let providers = vec![
            "openai".to_string(),
            "anthropic".to_string(),
            "gemini".to_string(),
            "cohere".to_string(),
        ];
        let filtered = filter_providers_by_modality(&providers, &Modality::Text);
        assert_eq!(filtered.len(), 4);
    }

    #[test]
    fn filter_embedding_excludes_non_embedding_providers() {
        let providers = vec![
            "openai".to_string(),
            "anthropic".to_string(),
            "cohere".to_string(),
            "gemini".to_string(),
        ];
        let filtered = filter_providers_by_modality(&providers, &Modality::Embedding);
        // openai, cohere, and gemini support embeddings; anthropic does not
        assert!(filtered.contains(&"openai".to_string()));
        assert!(filtered.contains(&"cohere".to_string()));
        assert!(!filtered.contains(&"anthropic".to_string()));
    }

    #[test]
    fn filter_returns_empty_when_no_provider_supports_modality() {
        let providers = vec!["anthropic".to_string(), "cohere".to_string()];
        let filtered = filter_providers_by_modality(&providers, &Modality::Video);
        assert!(filtered.is_empty());
    }

    #[test]
    fn filter_empty_provider_list() {
        let providers: Vec<String> = vec![];
        let filtered = filter_providers_by_modality(&providers, &Modality::Text);
        assert!(filtered.is_empty());
    }
}
