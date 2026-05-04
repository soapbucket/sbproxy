# W3C TDMRep fixture directory

The W3C TDMRep 1.0 JSON Schema lives at
`https://www.w3.org/2022/tdmrep/tdmrep.schema.json`. The Wave 4 G4.9
build agent owns vendoring the canonical schema into
`e2e/fixtures/tdmrep/tdmrep-1.0.schema.json` and wiring it into
`tdmrep_json_validates_against_w3c_schema` (currently `#[ignore]`'d
with a `TODO(wave4-G4.9)` marker).

The validation uses the `jsonschema` crate (already in the workspace
lock; see `e2e/Cargo.toml`).
