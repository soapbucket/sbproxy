import { describe, expect, it } from "vitest";

import configView from "./ConfigView.vue?raw";

describe("ConfigView config history panel", () => {
  it("loads the history timeline on mount, alongside the rest of the page", () => {
    expect(configView).toContain("api.configHistory");
    expect(configView).toContain("configHistory.run()");
    expect(configView).toContain("onMounted(refresh)");
  });

  it("reads the disabled-feature 404 through isConfigHistoryDisabled and renders a quiet empty state", () => {
    expect(configView).toContain("isConfigHistoryDisabled(configHistory.error.value)");
    // The quiet empty state, not an error toast: an EmptyState bound to
    // historyDisabled, naming the config key that turns the feature on.
    expect(configView).toMatch(/<EmptyState\s+v-if="historyDisabled"/);
    expect(configView).toContain("proxy.config_history.enabled");
    // A real error (anything other than the disabled-feature 404) still
    // renders through ErrorState, same as every other panel on this page.
    expect(configView).toMatch(/<ErrorState\s+v-else-if="configHistory\.error\.value"/);
  });

  it("shows a state badge, a degraded marker, and blast radius per row", () => {
    expect(configView).toContain('StatusBadge :label="entry.state" :tone="historyStateTone(entry.state)"');
    expect(configView).toContain('v-if="entry.degraded.length" label="degraded"');
    expect(configView).toContain("blastRadiusLabel(entry.blast_radius)");
    expect(configView).toContain("blastRadiusTone(entry.blast_radius)");
  });

  it("loads one entry's plan on row click and renders it with the same sb-code text block the rest of the page uses", () => {
    expect(configView).toContain("api.configHistoryEntry(entry.digest)");
    expect(configView).toContain("@click=\"selectHistoryEntry(entry)\"");
    expect(configView).toContain('<pre class="sb-code">{{ historyDetail.plan_text }}</pre>');
    // Retrying a failed detail load must re-fetch, not toggle the row
    // shut: selectHistoryEntry only toggles when the digest is already
    // selected, which is exactly the state a failed detail row is in.
    expect(configView).toContain('@retry="loadHistoryDetail(entry)"');
  });

  it("refuses to submit a buffer that still contains a redaction marker", () => {
    expect(configView).toContain('editorText.value.includes("[REDACTED]")');
    expect(configView).toContain("Replace every [REDACTED] secret before saving");
  });
});
