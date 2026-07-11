// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Print the executable model-host capability registry as Markdown.

fn main() {
    print!(
        "{}",
        sbproxy_model_host::capability_registry().render_markdown()
    );
}
