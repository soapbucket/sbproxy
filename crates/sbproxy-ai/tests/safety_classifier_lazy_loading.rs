use sbproxy_ai::guardrails::register_classifier_factory;
use sbproxy_ai::handler::AiHandlerConfig;

#[test]
fn publication_is_structural_and_lazy_artifact_failure_stays_fail_closed() {
    register_classifier_factory(Box::new(|_| {
        anyhow::bail!("fixture classifier artifact is unavailable")
    }));
    let config = AiHandlerConfig::from_config(serde_json::json!({
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
                    "classes": {
                        "jailbreak": ["override the policy"],
                        "safe": ["ordinary question"]
                    },
                    "scope": "full_text"
                }
            }]
        }
    }))
    .expect("publication validates structure without loading classifier artifacts");

    let first = config
        .guardrail_pipeline()
        .expect_err("the first request-side pipeline build must fail closed")
        .to_string();
    let second = config
        .guardrail_pipeline()
        .expect_err("the cached artifact failure must remain fail closed")
        .to_string();

    assert!(first.contains("jailbreak classifier backend is unavailable"));
    assert!(first.contains("fixture classifier artifact is unavailable"));
    assert_eq!(first, second);
}
