import { describe, expect, it } from "vitest";

import auditView from "./AuditView.vue?raw";

// WOR-2579: the chain section of the Audit view. Source assertions, in
// the same shape the routing-decisions view uses: the load-bearing
// pieces are the typed api call, the verification surfacing, and the
// cursor paging, and each has a string here that fails if it goes.
describe("AuditView chain viewer", () => {
  it("loads the chain through the typed api client on mount", () => {
    expect(auditView).toContain("api.auditChain(chainFilters())");
    expect(auditView).toContain("chainReq.run()");
    expect(auditView).toContain("onMounted(refresh)");
  });

  it("filters server-side by channel, actor, and time range", () => {
    for (const dimension of [
      "{ channel: chainChannel.value }",
      "{ actor: chainActor.value }",
      "since: new Date(chainSince.value).toISOString()",
      "until: new Date(chainUntil.value).toISOString()",
    ]) {
      expect(auditView).toContain(dimension);
    }
  });

  it("surfaces a verification failure instead of hiding it", () => {
    // The alert renders whenever a walked channel reports a break or an
    // unreadable file, independent of whether entries also rendered.
    expect(auditView).toMatch(/<div v-if="brokenChannels\.length" class="chain-alert" role="alert">/);
    expect(auditView).toContain("Chain verification FAILED");
    expect(auditView).toContain("c.enabled && (c.ok === false || c.error)");
    // And the per-channel card names the first broken sequence.
    expect(auditView).toContain("broken at #{{ card.broken_seq }}: {{ card.reason }}");
  });

  it("shows all four channels as cards, disabled ones included", () => {
    expect(auditView).toContain(
      'const CHAIN_CHANNELS = ["security", "config", "key", "admin"] as const;',
    );
    expect(auditView).toContain(
      "chainStatuses.value[name] ?? { channel: name, enabled: false }",
    );
  });

  it("pages older history with the server cursor and can walk back", () => {
    expect(auditView).toContain("selectedStatus.value?.next_before_seq");
    expect(auditView).toContain("function olderPage()");
    expect(auditView).toContain("function newerPage()");
    // A fresh filter resets the cursor: page state never leaks across
    // filter changes.
    expect(auditView).toContain("beforeSeq.value = undefined;");
  });

  it("renders errors and the empty state through the shared components", () => {
    expect(auditView).toMatch(/<ErrorState\s+v-if="chainReq\.error\.value"/);
    expect(auditView).toMatch(/<EmptyState\s+v-else-if="!chainEntries\.length"/);
  });
});
