# RSL 1.0 fixture directory

The RSL (Really Simple Licensing) 1.0 specification was published by
the RSL Collective in December 2025; the canonical XSD lives at
`https://rsl.ai/spec/1.0/rsl.xsd` per `adr-policy-graph-projections.md`.

Vendoring is intentionally deferred to the Wave 4 G4.8 build agent.
That agent owns:

1. Downloading the official XSD into `e2e/fixtures/rsl/rsl-1.0.xsd`
   (including the upstream license header).
2. Updating the `NOTICE` file with the RSL Collective copyright if
   the XSD is licensed under Apache 2.0 (per the Wave 1 BSL-to-Apache
   convention in `CLAUDE.md`).
3. Wiring the file into `licenses_xml_validates_against_rsl_1_0_xsd`
   (currently `#[ignore]`'d).

Until the G4.8 agent lands, the validation test stays ignored with
the `TODO(wave4-G4.8)` marker.
