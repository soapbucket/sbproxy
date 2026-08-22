# AI evaluation harness
*Last modified: 2026-08-22*

`sbproxy_ai::evaluation` (WOR-2672) is an offline toolkit for comparing
model versions and prompt templates against recorded datasets: an
embedder drives it from a script, a test, or a CI job. It does not touch
live traffic; nothing here runs on the request path.

## Not the same "judge" as `sbproxy_ai::judge`

`sbproxy_ai::judge` is this crate's live policy-authoring host function:
an operator's CEL or Lua policy calls `judge::semantic` mid-request to
get a cached, budget-capped LLM opinion feeding a `PolicyDecision` (see
`docs/adr-judge-trait.md`). `evaluation::judge` here is a different,
offline concern with the same name for the same reason both are called
"judge" in the literature: building a structured judge PROMPT and
parsing a judge model's scored JSON response for an *evaluation run*,
with no cache, no budget, and no policy integration. Neither depends on
the other.

## The five pieces

### Datasets

`DatasetStore` holds named, versioned collections of input/expected-output
pairs:

```rust,ignore
use sbproxy_ai::evaluation::{Dataset, DatasetEntry, DatasetStore};

let store = DatasetStore::new();
store.save(Dataset::new("support-qa", vec![
    DatasetEntry::with_expected("How do I reset my password?", "Go to Settings > Security > Reset password."),
    DatasetEntry::with_expected("What is your refund policy?", "Full refund within 30 days."),
]));
let ds = store.get("support-qa").unwrap();
```

### LLM-as-judge prompting

Build a structured scoring prompt and parse the judge model's JSON
response:

```rust,ignore
use sbproxy_ai::evaluation::{build_judge_prompt, parse_judge_response};

let criteria = vec!["helpfulness".to_string(), "accuracy".to_string()];
let prompt = build_judge_prompt(&candidate_response, &criteria);
// Submit `prompt` to your configured judge model, then:
let result = parse_judge_response(&judge_model_output).expect("judge returned valid JSON");
println!("composite score: {}", result.score); // mean of criteria_scores
```

### Experiment tracking

`ExperimentStore` records one row per run (model, prompt version,
parameters, and an optional result payload once evaluation completes),
so runs are comparable after the fact:

```rust,ignore
use sbproxy_ai::evaluation::Experiment;
use serde_json::json;

experiments.record(Experiment::new(
    "run-042", "gpt4-vs-claude3-summarization", "gpt-4o", "summarization-v2",
    json!({"temperature": 0.7}), "2026-08-22T00:00:00Z",
));
```

### Prompt scoring and ranking

`PromptScorer` accumulates per-prompt, per-model quality observations
and ranks prompts by average score, for picking the best-performing
variant out of several candidates:

```rust,ignore
use sbproxy_ai::evaluation::{PromptScore, PromptScorer};

let scorer = PromptScorer::new();
scorer.record(PromptScore::new("summarize this article", "gpt-4o", 0.82, 0.85));
scorer.record(PromptScore::new("summarize this article", "claude-3-5-sonnet", 0.91, 0.90));
let ranked = scorer.rank_prompts(); // highest average score first
```

### Custom pass/fail metrics

Composable, dependency-light checks over a response string: regex match,
structural JSON validity, length range, and required keywords.

```rust,ignore
use sbproxy_ai::evaluation::{pass_rate, MetricType};

let metrics = vec![
    MetricType::LengthRange(20, 500),
    MetricType::ContainsKeywords(vec!["refund".to_string()]),
];
let rate = pass_rate(&candidate_response, &metrics); // 0.0..=1.0
```

## Runnable example

[`crates/sbproxy-ai/examples/ai_evaluation_harness.rs`](../crates/sbproxy-ai/examples/ai_evaluation_harness.rs)
runs all five pieces together against a small dataset:

```bash
cargo run -p sbproxy-ai --example ai_evaluation_harness
```

## See also

- [ai-default-centroids-evaluation.md](ai-default-centroids-evaluation.md) -
  a different, unrelated evaluation: held-out precision/recall for the
  pinned classifier safety centroid artifact.
