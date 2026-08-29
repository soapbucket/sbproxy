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
});

/*
 * WOR-2574, the config-history half of the deferred console work.
 *
 * `GET /admin/config/history` has carried a `timeline` array since
 * WOR-2462 and `POST /admin/config/rollback` has existed since WOR-2460,
 * and the notes beside both routes say the console renders neither. The
 * data was tested server-side and invisible to an operator, which is the
 * whole failure the timeline exists to prevent: "the config stopped
 * updating three hours ago" and "a candidate has been refused every poll
 * cycle for three hours" are the same incident, and the applied-only
 * table shows half of it.
 */
describe("ConfigView config timeline (WOR-2462)", () => {
  it("renders the interleaved timeline, not only the applied entries", () => {
    // The applied table reads `entries`; the timeline reads `timeline`,
    // which is the array carrying the refusals.
    expect(configView).toContain("configHistory.data.value?.timeline");
    expect(configView).toContain("timelineRows");
  });

  it("marks a refused candidate as refused rather than letting it read as applied", () => {
    expect(configView).toContain('row.kind === "rejected"');
    expect(configView).toContain("timelineKindTone");
  });

  it("shows the refusal reason and the stage it was refused at", () => {
    expect(configView).toContain("row.reason");
    expect(configView).toContain("row.stage");
  });

  it("shows how long a refusal has been repeating, which is the incident signal", () => {
    // A candidate refused once is a typo; one refused every poll cycle
    // for three hours is an outage nobody has been paged for.
    expect(configView).toContain("row.count");
  });

  it("surfaces the revision under soak, so an unmoved lkg pointer can be told apart from a stuck one", () => {
    expect(configView).toContain("soak_revision");
  });
});

describe("ConfigView rollback button (WOR-2460)", () => {
  it("calls the rollback route the CLI and the JSON API already expose", () => {
    expect(configView).toContain("api.configRollback");
  });

  it("routes the submission through the typed-confirmation gate that was written ahead of it", () => {
    // `rollbackGate` shipped with WOR-2460 and nothing called it. This
    // is the call site it was written for.
    expect(configView).toContain("rollbackGate(");
    expect(configView).toContain("from \"../lib/config-history\"");
  });

  it("sends confirm_revision so the server's enforcer sees the typed confirmation", () => {
    // The client gate is the affordance; `confirm_revision` is what the
    // route actually checks. Disabling the button without sending the
    // field would leave the server refusing a submission the console
    // believed it had confirmed.
    expect(configView).toContain("confirm_revision");
  });

  it("names the target revision explicitly rather than relying on a default", () => {
    expect(configView).toContain("revision: rollbackTarget");
  });

  it("keeps the button out of reach of a role that cannot mutate", () => {
    // The API client refuses this call for a read_only session anyway;
    // this is so the operator sees a disabled control with a reason
    // instead of a live button that answers 403.
    expect(configView).toContain("canMutate");
    expect(configView).toContain("useCapabilities");
  });

  it("tells the operator the file is unchanged, which is the half the route cannot do", () => {
    expect(configView).toContain("config_file_unchanged");
  });
});
