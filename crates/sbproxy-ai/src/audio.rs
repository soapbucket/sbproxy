//! Audio API types - transcription and speech synthesis.
//!
//! These types describe the request/response shapes for the OpenAI Audio API.
//! Actual HTTP calls are performed by the provider layer; this module provides
//! only the serialisable data structures.

use serde::{Deserialize, Serialize};

/// A request to transcribe audio into text.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranscriptionRequest {
    /// URL of the audio file to transcribe.
    pub file_url: String,
    /// Model identifier (e.g. `whisper-1`).
    pub model: String,
    /// Optional BCP-47 language tag (e.g. `"en"`, `"fr"`).  When absent the
    /// model auto-detects the language.
    pub language: Option<String>,
}

/// The transcribed text returned by the provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranscriptionResponse {
    /// The recognised transcript.
    pub text: String,
    /// Duration of the source audio in seconds, if the provider returns it.
    pub duration: Option<f64>,
}

/// A text-to-speech synthesis request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpeechRequest {
    /// The text to synthesise.
    pub input: String,
    /// Model identifier (e.g. `tts-1`, `tts-1-hd`).
    pub model: String,
    /// Voice identifier (e.g. `alloy`, `echo`, `fable`, `onyx`, `nova`, `shimmer`).
    pub voice: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transcription_request_roundtrip() {
        let req = TranscriptionRequest {
            file_url: "https://example.com/audio.mp3".to_string(),
            model: "whisper-1".to_string(),
            language: Some("en".to_string()),
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: TranscriptionRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.file_url, req.file_url);
        assert_eq!(parsed.model, "whisper-1");
        assert_eq!(parsed.language, Some("en".to_string()));
    }

    #[test]
    fn transcription_request_no_language() {
        let req = TranscriptionRequest {
            file_url: "https://example.com/audio.wav".to_string(),
            model: "whisper-1".to_string(),
            language: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: TranscriptionRequest = serde_json::from_str(&json).unwrap();
        assert!(parsed.language.is_none());
    }

    #[test]
    fn speech_request_roundtrip() {
        let req = SpeechRequest {
            input: "Hello, world!".to_string(),
            model: "tts-1".to_string(),
            voice: "alloy".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: SpeechRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.input, "Hello, world!");
        assert_eq!(parsed.voice, "alloy");
    }

    #[test]
    fn transcription_response_roundtrip() {
        let resp = TranscriptionResponse {
            text: "The quick brown fox.".to_string(),
            duration: Some(3.5),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: TranscriptionResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.text, "The quick brown fox.");
        assert_eq!(parsed.duration, Some(3.5));
    }
}
