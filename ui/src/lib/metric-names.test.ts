/*
 * Every metric family the console names has to be a family the proxy
 * publishes.
 *
 * The console reads the scrape by exact family name. Nothing on the Rust
 * side reads these constants, so a rename there is invisible here: the
 * lookup stops matching, the report comes back `undefined`, and the panel
 * renders its "not reported" empty state over a live signal. That is worse
 * than a broken panel, because the empty state is a claim, and the claim is
 * false.
 *
 * This is not hypothetical. Both storage families were renamed into the
 * sanctioned `sbproxy_` prefix in the same day's merges that these panels
 * were written against, the rename arrived in this branch through a merge
 * from main after the panels were built and reviewed, and the storage panel
 * read the old names until this test was written.
 *
 * `docs/metrics-stability.md` is generated from the metric registry and the
 * gate refuses a tree where it is out of date, so it is the one artifact in
 * the repository that is guaranteed to name what the exporter actually
 * publishes. Reading it here is the same cross-boundary trick
 * `config-schema.test.ts` uses against `schemas/sb-config.schema.json`.
 */

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import { AI_ADMISSION_FAMILY } from "./ai-admission";
import { MESH_INBOUND_REJECTED_FAMILY } from "./mesh-admission";
import {
  CERT_STORE_DEGRADED_FAMILY,
  CORS_REFUSALS_FAMILY,
  SIGNATURE_LEGACY_DERIVATION_FAMILY,
} from "./security-signals";
import {
  STORAGE_OP_DURATION_FAMILY,
  STORAGE_OP_ERRORS_FAMILY,
} from "./storage-ops";

const stability = readFileSync(
  new URL("../../../docs/metrics-stability.md", import.meta.url),
  "utf8",
);

// Name each constant by its module so a failure says which panel goes dark.
const FAMILIES: [string, string][] = [
  ["ai-admission", AI_ADMISSION_FAMILY],
  ["mesh-admission", MESH_INBOUND_REJECTED_FAMILY],
  ["security-signals cert store", CERT_STORE_DEGRADED_FAMILY],
  ["security-signals CORS", CORS_REFUSALS_FAMILY],
  ["security-signals RFC 9421", SIGNATURE_LEGACY_DERIVATION_FAMILY],
  ["storage-ops duration", STORAGE_OP_DURATION_FAMILY],
  ["storage-ops errors", STORAGE_OP_ERRORS_FAMILY],
];

describe("metric families the console names", () => {
  it.each(FAMILIES)(
    "%s reads a family docs/metrics-stability.md publishes",
    (_module, family) => {
      // Backticked and row-anchored: the table writes every family as
      // `| \`name\` | Type | ... |`, so a bare substring would also match a
      // longer family that merely starts with this one.
      expect(stability).toContain(`| \`${family}\` |`);
    },
  );

  it("reads a stability table that has rows in it", () => {
    // Without this, a truncated or moved artifact would fail every case
    // above with a message about the console rather than about the file.
    expect(stability.split("\n").filter((l) => l.startsWith("| `")).length)
      .toBeGreaterThan(100);
  });
});
