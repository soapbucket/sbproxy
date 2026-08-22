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
    store.add_version(
        PROMPT_NAME,
        WeightedPromptVersion::new(PROMPT_NAME, 1, "You are a helpful support agent.", 90.0),
    );
    store.add_version(
        PROMPT_NAME,
        WeightedPromptVersion::new(
            PROMPT_NAME,
            2,
            "You are a concise, action-oriented support agent.",
            10.0,
        ),
    );

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
    for _ in 0..DRAWS {
        let picked = store
            .select_by_weight(PROMPT_NAME)
            .expect("at least one positive-weight version is registered");
        *counts.entry(picked.version).or_insert(0) += 1;
        // `select_by_weight` seeds its draw from the current microsecond
        // clock reading (see its doc comment). A tight loop can execute
        // several draws within the same microsecond tick and get the
        // identical pick each time, which is a real property of this
        // implementation worth surfacing honestly rather than hiding
        // behind a busy loop fast enough to trigger it: this sleep is
        // what makes 1,000 draws land on 1,000 distinct clock readings
        // instead of a handful of repeated bursts.
        std::thread::sleep(std::time::Duration::from_micros(1));
    }

    let mut versions: Vec<&u32> = counts.keys().collect();
    versions.sort();
    for version in versions {
        let count = counts[version];
        let pct = 100.0 * count as f64 / DRAWS as f64;
        println!("  v{version}: {count} draws ({pct:.1}%)");
    }
}
