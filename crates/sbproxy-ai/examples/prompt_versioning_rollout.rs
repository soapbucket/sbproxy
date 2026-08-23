//! Runnable demonstration of `sbproxy_ai::prompt_versioning` (WOR-2672):
//! a 90/10 weighted rollout between two prompt versions, sampled 1,000
//! times to show the observed split converges on the configured weights.
//!
//! Run with:
//!
//! ```bash
//! cargo run -p sbproxy-ai --example prompt_versioning_rollout
//! ```

use sbproxy_ai::prompt_versioning::{WeightedPromptStore, WeightedPromptVersion};
use std::collections::HashMap;

const PROMPT_NAME: &str = "support-system-prompt";
const DRAWS: u32 = 1_000;

fn main() {
    let store = WeightedPromptStore::new();
    store
        .add_version(
            PROMPT_NAME,
            WeightedPromptVersion::new(PROMPT_NAME, 1, "You are a helpful support agent.", 90.0)
                .expect("valid v1"),
        )
        .expect("unique v1");
    store
        .add_version(
            PROMPT_NAME,
            WeightedPromptVersion::new(
                PROMPT_NAME,
                2,
                "You are a concise, action-oriented support agent.",
                10.0,
            )
            .expect("valid v2"),
        )
        .expect("unique v2");

    let latest = store
        .get_latest(PROMPT_NAME)
        .expect("just registered two versions");
    println!(
        "Latest version (deterministic, highest version number): v{}",
        latest.version
    );
    println!("Registered prompt names: {:?}", store.list_names());

    println!("\nAll registered versions:");
    for v in store.list_versions(PROMPT_NAME) {
        println!("  v{} (weight {}): {:?}", v.version, v.weight, v.content);
    }

    println!("\nDrawing {DRAWS} times by weight (~90% v1, ~10% v2 expected):");
    let mut counts: HashMap<u32, u32> = HashMap::new();
    for cohort in 0..DRAWS {
        let picked = store
            .select_for_cohort(PROMPT_NAME, &format!("customer-{cohort}"), "rollout-1")
            .expect("at least one positive-weight version is registered");
        *counts.entry(picked.version).or_insert(0) += 1;
    }

    let mut versions: Vec<&u32> = counts.keys().collect();
    versions.sort();
    for version in versions {
        let count = counts[version];
        let pct = 100.0 * count as f64 / DRAWS as f64;
        println!("  v{version}: {count} draws ({pct:.1}%)");
    }
}
