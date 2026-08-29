import { describe, expect, it } from "vitest";

import federationView from "./FederationView.vue?raw";

/*
 * WOR-2574. `GET /admin/federation` shipped with a note beside it saying
 * the console page was separate scope. This is that page.
 *
 * The route answers `{"enabled": false}` on a process with no federation
 * block rather than 404ing, so the page has a real "not configured"
 * state to render and it is not an error.
 */
describe("FederationView", () => {
  it("reads the federation route the JSON surface already exposes", () => {
    expect(federationView).toContain("api.federation()");
  });

  it("triggers its own load rather than waiting for a poll tick", () => {
    expect(federationView).toContain("onMounted");
  });

  it("renders 'not configured' as a configuration state, not as an error", () => {
    // `enabled: false` is what a process without the block reports, and
    // rendering it through ErrorState sends an operator to debug a
    // working proxy.
    expect(federationView).toContain("notConfigured");
    expect(federationView).toMatch(/<EmptyState\s+v-if="notConfigured"/);
  });

  it("shows the entity identity an operator came here to check", () => {
    expect(federationView).toContain("entity_id");
    expect(federationView).toContain("signing_kid");
    expect(federationView).toContain("published_keys");
  });

  it("shows how long the published entity statement is still cacheable", () => {
    // `cache_remaining_secs` is null when the document could not be
    // built, which is the same failure the well-known route 503s on and
    // the reason an operator is on this page.
    expect(federationView).toContain("cache_remaining_secs");
  });

  it("shows what this proxy requires of a peer, not only what it publishes", () => {
    expect(federationView).toContain("peer_trust");
    expect(federationView).toContain("pinned_anchors");
  });

  /*
   * Three distinct postures, not two. "No verifier" and "a verifier that
   * is present but not required" both admit a peer presenting no
   * statement, and a page that renders them as the same absent checkmark
   * hides a control that looks configured and enforces nothing.
   */
  it("tells 'no verifier' apart from 'configured but not required'", () => {
    expect(federationView).toContain("peerTrustSummary");
    expect(federationView).toContain("trust.required");
    expect(federationView).toContain("peerTrust?.configured");
  });

  /*
   * The route is deliberately free of key material: it names the signing
   * key by `kid` and never emits the key itself. A page that rendered a
   * whole response blob would undo that the first time the route grew a
   * field, so the page reads named fields.
   */
  it("does not dump the raw response as a blob", () => {
    expect(federationView).not.toContain("JSON.stringify(federation.data");
  });
});
