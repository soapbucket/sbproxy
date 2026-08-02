// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Print the executable metric registry as the published stability catalogue.

fn main() {
    print!("{}", sbproxy_observe::metric_registry::render_markdown());
}
