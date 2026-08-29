import { describe, expect, it } from "vitest";

import licensingView from "./LicensingView.vue?raw";

/*
 * WOR-2574. `GET /admin/licensing` shipped under WOR-2673 with a note in
 * `docs/admin-api-reference.md` saying the console page was separate
 * scope. This is that page.
 */
describe("LicensingView", () => {
  it("reads the licensing route the JSON surface already exposes", () => {
    expect(licensingView).toContain("api.licensing()");
  });

  it("triggers its own load rather than waiting for a poll tick", () => {
    expect(licensingView).toContain("onMounted");
  });

  it("renders a process with no licensing origins as a configuration state", () => {
    expect(licensingView).toContain("notConfigured");
    expect(licensingView).toMatch(/<EmptyState\s+v-if="notConfigured"/);
  });

  it("lists per origin, because licensing is configured per origin", () => {
    expect(licensingView).toContain("origins");
    expect(licensingView).toContain("origin.hostname");
  });

  it("shows both halves, the CoMP bridge and the OLP issuer", () => {
    expect(licensingView).toContain("origin.comp");
    expect(licensingView).toContain("origin.olp");
  });

  /*
   * The field the route's own comment says is worth being able to see
   * without reading a rejection rate: `active_signing_kid` is null until
   * a rotation is activated, and every quote request fails closed until
   * then.
   */
  it("surfaces an unactivated signing rotation, which fails every quote closed", () => {
    expect(licensingView).toContain("active_signing_kid");
  });

  /*
   * The two tier counts differ whenever a catalog carries `cap` or
   * `public` tiers, and only the OLP ones are redeemable. An operator
   * reading "12 tiers" and seeing one redeem a day needs to know eleven
   * of them were never redeemable.
   */
  it("shows the redeemable tier count next to the total, not the total alone", () => {
    expect(licensingView).toContain("tier_count");
    expect(licensingView).toContain("olp_tier_count");
  });

  it("shows where the OLP revocation state lives, which is the field a stale revocation needs", () => {
    expect(licensingView).toContain("revocation_store");
  });

  /*
   * The route names the signing key by `kid` and never by its material,
   * reports the content-key seed as configured or not, and keeps the
   * Redis revocation URL off the wire because such a URL routinely
   * carries a password in its userinfo. The page must not reintroduce
   * any of that by rendering the response wholesale.
   */
  it("does not dump the raw response as a blob", () => {
    expect(licensingView).not.toContain("JSON.stringify(licensing.data");
  });

  it("reports the content key as configured or not, never by value", () => {
    expect(licensingView).toContain("content_key_configured");
    expect(licensingView).not.toContain("content_key_seed");
  });
});
