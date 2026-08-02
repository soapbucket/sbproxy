use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use sbproxy_ai::guardrails::{
    register_classifier_factory, ClassifierBackendConfig, ClassifierConfig, ClassifierVerdict,
    TextClassifier,
};
use sbproxy_ai::handler::AiHandlerConfig;
use sbproxy_ai::types::Message;

static SAFETY_LOADS: AtomicUsize = AtomicUsize::new(0);
static ROUTING_LOADS: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug)]
struct SafeClassifier;

impl TextClassifier for SafeClassifier {
    fn classify(&self, _text: &str) -> anyhow::Result<Option<ClassifierVerdict>> {
        Ok(Some(ClassifierVerdict {
            label: "safe".to_string(),
            score: 0.99,
        }))
    }
}

fn install_test_factory() {
    register_classifier_factory(Box::new(|config: &ClassifierConfig| {
        let ClassifierBackendConfig::Embedding(backend) = &config.backend;
        if config.default_centroids.is_some() {
            SAFETY_LOADS.fetch_add(1, Ordering::SeqCst);
            if backend.model_path.contains("/missing/") {
                anyhow::bail!("fixture classifier artifact is unavailable");
            }
            return Ok(Arc::new(SafeClassifier));
        }

        ROUTING_LOADS.fetch_add(1, Ordering::SeqCst);
        anyhow::bail!("fixture routing artifact is unavailable")
    }));
}

#[test]
fn safety_preflight_is_retained_while_routing_artifacts_stay_lazy() {
    SAFETY_LOADS.store(0, Ordering::SeqCst);
    ROUTING_LOADS.store(0, Ordering::SeqCst);
    install_test_factory();

    let failing = AiHandlerConfig::from_config(serde_json::json!({
        "providers": [{"name": "openai", "api_key": "sk-test"}],
        "guardrails": {
            "input": [{
                "type": "jailbreak",
                "mode": "classifier",
                "classifier": {
                    "backend": {
                        "kind": "embedding",
                        "model_path": "/missing/model.onnx",
                        "tokenizer_path": "/missing/tokenizer.json"
                    },
                    "scope": "full_text"
                }
            }]
        }
    }))
    .expect("publication validates structure without loading classifier artifacts");

    let first = failing
        .preflight_default_safety_centroids()
        .expect_err("startup preflight must reject unavailable default centroid artifacts")
        .to_string();
    let second = failing
        .preflight_default_safety_centroids()
        .expect_err("the cached preflight failure must remain fail closed")
        .to_string();

    assert!(first.contains("jailbreak classifier backend is unavailable"));
    assert!(first.contains("fixture classifier artifact is unavailable"));
    assert_eq!(first, second);
    assert_eq!(SAFETY_LOADS.load(Ordering::SeqCst), 1);

    let mixed = AiHandlerConfig::from_config(serde_json::json!({
        "providers": [{"name": "openai", "api_key": "sk-test"}],
        "guardrails": {
            "input": [
                {
                    "type": "jailbreak",
                    "mode": "classifier",
                    "classifier": {
                        "backend": {
                            "kind": "embedding",
                            "model_path": "/verified/safety.onnx",
                            "tokenizer_path": "/verified/tokenizer.json"
                        },
                        "scope": "full_text"
                    }
                },
                {
                    "type": "classifier",
                    "backend": {
                        "kind": "embedding",
                        "model_path": "/late/routing.onnx",
                        "tokenizer_path": "/late/tokenizer.json"
                    },
                    "classes": {
                        "documentation": ["write the readme"]
                    }
                }
            ]
        }
    }))
    .expect("mixed safety and routing classifiers are structurally valid");

    mixed
        .preflight_default_safety_centroids()
        .expect("verified safety classifier preflight");
    assert_eq!(SAFETY_LOADS.load(Ordering::SeqCst), 2);
    assert_eq!(
        ROUTING_LOADS.load(Ordering::SeqCst),
        0,
        "safety preflight must not open an unrelated routing artifact"
    );

    mixed
        .preflight_default_safety_centroids()
        .expect("preflight reuses the retained verified pipeline");
    assert_eq!(SAFETY_LOADS.load(Ordering::SeqCst), 2);

    let pipeline = mixed
        .guardrail_pipeline()
        .expect("cached pipeline")
        .expect("guardrails configured");
    let blank_messages = [Message {
        role: "user".to_string(),
        content: serde_json::Value::String("   ".to_string()),
    }];
    assert!(pipeline.classify_input(&blank_messages).is_empty());
    assert_eq!(
        ROUTING_LOADS.load(Ordering::SeqCst),
        0,
        "an empty request must not initialize the routing artifact"
    );

    let messages = [Message {
        role: "user".to_string(),
        content: serde_json::Value::String("write the readme".to_string()),
    }];
    assert!(pipeline.classify_input(&messages).is_empty());
    assert_eq!(ROUTING_LOADS.load(Ordering::SeqCst), 1);

    assert!(pipeline.classify_input(&messages).is_empty());
    assert_eq!(
        ROUTING_LOADS.load(Ordering::SeqCst),
        1,
        "an unavailable routing artifact remains inert without repeated I/O"
    );
}
