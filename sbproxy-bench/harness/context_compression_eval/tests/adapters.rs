use context_compression_eval::{adapt_external_jsonl, parse_cases, ExternalSuite, QualitySpec};

#[test]
fn generic_external_adapter_labels_each_supported_suite() {
    let input = r#"{"id":"external-1","context":"Synthetic context with answer blue.","question":"What is the answer?","reference_answers":["blue"],"off_prediction":"blue","on_prediction":"blue"}"#;
    let suites = [
        (ExternalSuite::Ruler, "ruler_external"),
        (ExternalSuite::Helmet, "helmet_external"),
        (ExternalSuite::LongBenchV2, "longbench_v2_external"),
        (ExternalSuite::NoLiMa, "nolima_external"),
    ];

    for (suite, expected_corpus) in suites {
        let normalized =
            adapt_external_jsonl(input.as_bytes(), suite, "gpt-4").expect("external row adapts");
        let cases = parse_cases(normalized.as_bytes()).expect("adapter emits normalized JSONL");
        assert_eq!(cases.len(), 1);
        assert_eq!(cases[0].corpus, expected_corpus);
        assert_eq!(cases[0].target_model, "gpt-4");
        assert!(matches!(cases[0].quality, QualitySpec::ExactMatch { .. }));
    }
}

#[test]
fn generic_external_adapter_is_strict() {
    let input = r#"{"id":"external-1","context":"context","question":"question","reference_answers":["answer"],"off_prediction":"answer","on_prediction":"answer","surprise":true}"#;

    let error = adapt_external_jsonl(input.as_bytes(), ExternalSuite::Ruler, "gpt-4")
        .expect_err("unknown adapter fields fail closed");

    assert!(error.to_string().contains("unknown field `surprise`"));
}
