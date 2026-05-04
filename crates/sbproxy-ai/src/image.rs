//! Image generation API types.
//!
//! Serialisable request/response shapes for the OpenAI Images API.
//! Actual HTTP calls are performed by the provider layer.

use serde::{Deserialize, Serialize};

/// A request to generate one or more images from a text prompt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageGenerationRequest {
    /// The text prompt describing the desired image.
    pub prompt: String,
    /// Model identifier (e.g. `dall-e-3`, `dall-e-2`).
    pub model: String,
    /// Image dimensions string (e.g. `"1024x1024"`, `"512x512"`).
    pub size: Option<String>,
    /// Number of images to generate.  Defaults to 1 when omitted.
    pub n: Option<u32>,
}

/// The response containing one or more generated images.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageGenerationResponse {
    /// List of generated images (URL or base-64 encoded).
    pub images: Vec<ImageData>,
}

/// A single generated image, returned as either a URL or a base-64 JSON blob.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageData {
    /// Public URL to the generated image (when `response_format = "url"`).
    pub url: Option<String>,
    /// Base-64 encoded PNG data (when `response_format = "b64_json"`).
    pub b64_json: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_generation_request_roundtrip() {
        let req = ImageGenerationRequest {
            prompt: "A sunset over the ocean".to_string(),
            model: "dall-e-3".to_string(),
            size: Some("1024x1024".to_string()),
            n: Some(1),
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: ImageGenerationRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.prompt, "A sunset over the ocean");
        assert_eq!(parsed.model, "dall-e-3");
        assert_eq!(parsed.size, Some("1024x1024".to_string()));
        assert_eq!(parsed.n, Some(1));
    }

    #[test]
    fn image_generation_request_minimal() {
        let req = ImageGenerationRequest {
            prompt: "A cat".to_string(),
            model: "dall-e-2".to_string(),
            size: None,
            n: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: ImageGenerationRequest = serde_json::from_str(&json).unwrap();
        assert!(parsed.size.is_none());
        assert!(parsed.n.is_none());
    }

    #[test]
    fn image_data_url_variant() {
        let data = ImageData {
            url: Some("https://example.com/img.png".to_string()),
            b64_json: None,
        };
        let json = serde_json::to_string(&data).unwrap();
        let parsed: ImageData = serde_json::from_str(&json).unwrap();
        assert!(parsed.url.is_some());
        assert!(parsed.b64_json.is_none());
    }

    #[test]
    fn image_data_b64_variant() {
        let data = ImageData {
            url: None,
            b64_json: Some("aGVsbG8=".to_string()),
        };
        let json = serde_json::to_string(&data).unwrap();
        let parsed: ImageData = serde_json::from_str(&json).unwrap();
        assert!(parsed.url.is_none());
        assert_eq!(parsed.b64_json.as_deref(), Some("aGVsbG8="));
    }

    #[test]
    fn image_generation_response_roundtrip() {
        let resp = ImageGenerationResponse {
            images: vec![
                ImageData {
                    url: Some("https://example.com/a.png".to_string()),
                    b64_json: None,
                },
                ImageData {
                    url: None,
                    b64_json: Some("abc123".to_string()),
                },
            ],
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: ImageGenerationResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.images.len(), 2);
    }
}
