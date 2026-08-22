import { describe, expect, it } from "vitest";

import admissionPanel from "../components/ClusterInboundAdmission.vue?raw";
import clusterView from "./ClusterView.vue?raw";

/** Collapse runs of whitespace so a prose assertion survives a reflow. */
function collapse(source: string): string {
  return source.replace(/\s+/g, " ");
}

describe("ClusterView inbound admission", () => {
  it("loads this node's own scrape on the same cadence as the roster", () => {
    expect(clusterView).toContain("api.metrics()");
    expect(clusterView).toContain("parsePrometheus(");
    expect(clusterView).toContain("void loadScrape()");
    expect(clusterView).toContain("usePoll(refresh, 15_000)");
  });

  it("does not read admission out of the aggregated fleet-metrics route", () => {
    // api.clusterMetrics() sums the fleet. Refusals are per node, and the
    // node they land on is the only actionable part of the reading.
    expect(clusterView).toMatch(
      /scrape\.value = parsePrometheus\(await api\.metrics\(\)\)/,
    );
    expect(admissionPanel).not.toContain("clusterMetrics");
  });

  it("renders the panel next to the roster it explains", () => {
    const rosterAt = clusterView.indexOf("<ClusterNodeRoster");
    const admissionAt = clusterView.indexOf("<ClusterInboundAdmission");
    const deploymentsAt = clusterView.indexOf("<ClusterDeploymentTable");

    expect(rosterAt).toBeGreaterThan(-1);
    expect(admissionAt).toBeGreaterThan(rosterAt);
    expect(deploymentsAt).toBeGreaterThan(admissionAt);
  });

  it("names the mesh counter it curates", () => {
    // The console curates families by name; the family is invisible until
    // something names it, which is why this panel exists.
    expect(admissionPanel).toContain("inboundAdmission");
    expect(clusterView).toContain(':families="scrape"');
  });

  it("distinguishes an unreported counter from a zero one", () => {
    expect(admissionPanel).toContain('v-else-if="!report"');
    expect(collapse(admissionPanel)).toContain(
      "refused no inbound peer connection",
    );
    expect(admissionPanel).toContain("not reported");
    // A zeroed StatCard must never stand in for the absent family.
    expect(admissionPanel).not.toMatch(/report\?\.refusals \?\? 0/);
  });

  it("does not flip the empty panel back to a loading message on every poll", () => {
    // `scrapeLoading` is the in-flight guard for the 15s poll, which is a
    // different question from whether a reading has arrived. Handing it to
    // the panel raw swapped the not-reported empty state for "reading
    // admission metrics" every fifteen seconds on a node that has refused
    // nothing, because both branches key off an undefined report.
    expect(clusterView).toContain(':loading="scrapeLoading && !scrapeLoaded"');
    expect(clusterView).toContain("scrapeLoaded.value = true");
  });

  it("uses the section idiom of the roster and rollouts around it", () => {
    expect(admissionPanel).toContain('class="data-section"');
    expect(admissionPanel).toContain('class="sb-eyebrow"');
    expect(admissionPanel).toContain('class="sb-card table-shell"');
  });

  it("separates the routine idle reclaim from a peer being turned away", () => {
    expect(admissionPanel).toContain("Peers turned away");
    expect(admissionPanel).toContain("Idle connections reclaimed");
    expect(collapse(admissionPanel)).toContain(
      "routine housekeeping, not a refusal",
    );
  });

  it("renders errors and the retry through the shared components", () => {
    expect(admissionPanel).toMatch(/<ErrorState\s+v-if="error"/);
    expect(admissionPanel).toContain("@retry=\"$emit('retry')\"");
    expect(clusterView).toContain('@retry="loadScrape"');
  });

  it("keeps the attacker-chosen peer address out of the table", () => {
    // The counter deliberately carries no peer label: it would mint one
    // series per source. The copy has to say where the address is instead.
    expect(collapse(admissionPanel)).toContain(
      "peer address is in the node log",
    );
    expect(admissionPanel).not.toContain('"peer"');
  });
});
