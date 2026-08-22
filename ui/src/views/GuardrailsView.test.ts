import { describe, expect, it } from "vitest";

import guardrailsView from "./GuardrailsView.vue?raw";

describe("Guardrails edge-refusal visibility", () => {
  it("loads the scrape on mount through the typed api client", () => {
    expect(guardrailsView).toContain("api.metrics()");
    expect(guardrailsView).toContain("onMounted(req.run)");
  });

  it("reads the CORS and RFC 9421 families through the named derivations", () => {
    // The console curates families by name. These two shipped with
    // writers and no reader, which is why this view names them.
    expect(guardrailsView).toContain("corsRefusals(families.value)");
    expect(guardrailsView).toContain(
      "legacySignatureDerivations(families.value)",
    );
    expect(guardrailsView).toContain("CORS_REFUSALS_FAMILY");
    expect(guardrailsView).toContain("SIGNATURE_LEGACY_DERIVATION_FAMILY");
  });

  it("renders the two panels only when the family is present", () => {
    // Both counters register on first use, so `undefined` means the
    // signal was never observed. A `v-if` on a summed total would draw a
    // zero over something nothing has ever incremented.
    expect(guardrailsView).toContain('v-if="totalWafPlane > 0 || cors"');
    expect(guardrailsView).toContain('v-if="cors"');
    expect(guardrailsView).toContain('v-if="legacySignatures"');
    expect(guardrailsView).not.toContain("cors.total > 0 ||");
  });

  it("opens the page for a node whose only signal is one of the two", () => {
    // Without this the page renders the "no guardrail activity" empty
    // card while a CORS refusal or a legacy signature is sitting in the
    // scrape unseen.
    expect(guardrailsView).toContain("cors.value !== undefined");
    expect(guardrailsView).toContain("legacySignatures.value !== undefined");
  });

  it("names the CORS refusal for what the counter actually covers", () => {
    // The counter has exactly one call site today, and it is the
    // wildcard-plus-credentials config refusal. An origin missing from
    // the allowlist is denied without being counted, so the copy must
    // not let a low number read as "every cross-origin request passed".
    expect(guardrailsView).toContain("CORS headers withheld (reason)");
    expect(guardrailsView).toContain(
      "the allowlist is denied without being counted here",
    );
  });

  it("frames the legacy derivation as a deprecation window, not a block", () => {
    expect(guardrailsView).toContain("RFC 9421 signature deprecation");
    expect(guardrailsView).toContain("Legacy base accepted");
    expect(guardrailsView).toContain(
      "pre-RFC-9421 request-target base",
    );
    // The counter cannot distinguish "no legacy signers" from "no
    // signature verification configured", so the view must never claim
    // the fallback is safe to remove.
    expect(guardrailsView).not.toContain("safe to remove");
  });

  it("keeps the empty state honest about what would make data appear", () => {
    expect(guardrailsView).toContain(
      "once the CORS middleware withholds\n      headers from a response",
    );
  });
});
