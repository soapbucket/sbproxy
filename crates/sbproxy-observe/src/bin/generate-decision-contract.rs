// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Print the executable decision contract as the published record catalogue.

fn main() {
    print!("{}", sbproxy_observe::decision_contract::render_markdown());
}
