use context_compression_eval::parse_cases;

#[test]
fn normalized_jsonl_rejects_unknown_fields() {
    let input = r#"{"schema_version":1,"id":"case-1","corpus":"ruler_smoke","target_model":"gpt-4","messages":[{"role":"user","content":"needle: blue"}],"quality":{"kind":"evidence_retention","required_evidence":["needle: blue"]},"unexpected":true}"#;

    let error = parse_cases(input.as_bytes()).expect_err("unknown fields must fail closed");

    assert!(error.to_string().contains("unknown field `unexpected`"));
}

#[test]
fn normalized_jsonl_rejects_duplicate_case_ids() {
    let case = r#"{"schema_version":1,"id":"duplicate","corpus":"ruler_smoke","target_model":"gpt-4","messages":[{"role":"user","content":"needle: blue"}],"quality":{"kind":"evidence_retention","required_evidence":["needle: blue"]}}"#;
    let input = format!("{case}\n{case}\n");

    let error = parse_cases(input.as_bytes()).expect_err("duplicate IDs must fail closed");

    assert!(error.to_string().contains("duplicate case id `duplicate`"));
}

#[test]
fn normalized_jsonl_rejects_unsupported_schema_versions() {
    let input = r#"{"schema_version":2,"id":"future","corpus":"ruler_smoke","target_model":"gpt-4","messages":[{"role":"user","content":"needle: blue"}],"quality":{"kind":"evidence_retention","required_evidence":["needle: blue"]}}"#;

    let error = parse_cases(input.as_bytes()).expect_err("future schemas must fail closed");

    assert!(error
        .to_string()
        .contains("case `future` uses unsupported schema version 2"));
}
