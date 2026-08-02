import type {
  MeterCoverage,
  MeterGapRow,
  MeterNodeRow,
  MeterSummary,
  MeterUnitRow,
  MeterVerifyResult,
} from "../api";

/**
 * What the meter page shows when there is nothing to count.
 *
 * A row of zeros cannot tell three different situations apart, and they
 * have three different next steps: attestation is off, attestation is on
 * and has recorded nothing, or the chain is busy and none of it belongs
 * to the tenant being looked at. The server sends a `state` for exactly
 * this reason, and this turns it into the sentence an operator reads.
 */
export interface MeterEmptyState {
  /** Headline, short enough to read at a glance. */
  title: string;
  /** The sentence that says what to do next. */
  detail: string;
  /** Distinguishes the three cases for styling and for tests. */
  kind: "off" | "idle" | "no-tenant-units";
}

const OFF_DETAIL =
  "Nothing is being metered on this node. Set proxy.attestation to a role that writes receipts, then reload.";
const IDLE_DETAIL =
  "Attestation is configured and the chain is empty. These zeros are a reading of an empty chain, not a reading of zero traffic.";

/**
 * The empty state to render, or null when there are units to show.
 *
 * Deliberately keyed on the server's `state` rather than on the length of
 * the totals array. An empty array means "no units in this view", which is
 * true in all three cases and useful in none of them.
 */
export function meterEmptyState(summary: MeterSummary | null): MeterEmptyState | null {
  if (!summary) return null;
  if (summary.state === "off") {
    return {
      kind: "off",
      title: "Attestation is off",
      detail: summary.reason ?? OFF_DETAIL,
    };
  }
  if (summary.state === "idle") {
    return {
      kind: "idle",
      title: "No receipts recorded yet",
      detail: summary.reason ?? IDLE_DETAIL,
    };
  }
  if (summary.totals.length > 0) return null;
  const entries = summary.chain?.entries ?? 0;
  const tenant = summary.tenant;
  return {
    kind: "no-tenant-units",
    title: tenant ? `No units for ${tenant}` : "No units on this chain",
    detail: tenant
      ? `The chain holds ${entries.toLocaleString()} entries and none of them are charged to ${tenant}.`
      : `The chain holds ${entries.toLocaleString()} entries and none of them carry a billable unit.`,
  };
}

/**
 * Whether the mesh fan-out was partial.
 *
 * False when no mesh is configured, because there is then exactly one
 * chain and nothing to be partial about. A banner that appears on every
 * single-node deployment is a banner nobody reads.
 */
export function coverageIsPartial(coverage: MeterCoverage | null): boolean {
  return coverage !== null && !coverage.complete;
}

/**
 * "2 of 3 nodes answered", for the coverage banner's headline.
 *
 * Null-tolerant so a template can call it without depending on the
 * narrowing of a `v-if` that sits on a different element.
 */
export function coverageHeadline(coverage: MeterCoverage | null): string {
  if (!coverage) return "";
  const answered = coverage.answered.length;
  const expected = coverage.expected;
  return `${answered} of ${expected} ${expected === 1 ? "node" : "nodes"} answered`;
}

/**
 * The plain-English reason one node is outside the total.
 *
 * The gap vocabulary drives what an operator does next, so it is spelled
 * out rather than shown as a snake-case token nobody can act on.
 */
export function gapExplanation(gap: string | undefined): string {
  switch (gap) {
    case "never_reported":
      return "has never published a segment";
    case "stale":
      return "last published too long ago to count";
    case "not_live":
      return "is no longer a live member";
    case "unreachable":
      return "could not be reached";
    case "unreadable":
      return "published a segment this build could not use";
    default:
      return "is outside the total";
  }
}

/** One group of unit rows, kept unfolded below (tenant, unit, source). */
export interface MeterTotalsGroup {
  /** The key the rows share, per the request's `group_by`. */
  group: string;
  /** Sum of the group's counts, for the header line only. */
  count: number;
  /** The rows themselves, provenance intact. */
  rows: MeterUnitRow[];
}

/**
 * Bucket unit rows by their group key, preserving every row.
 *
 * The group total on each header is a display convenience. The rows
 * underneath it are never collapsed: two provenances under one number is
 * the fold the metering vocabulary exists to refuse, and undoing it at the
 * point an operator reads the figures would defeat the whole design.
 */
export function groupedTotals(rows: readonly MeterUnitRow[]): MeterTotalsGroup[] {
  const groups = new Map<string, MeterTotalsGroup>();
  for (const row of rows) {
    const existing = groups.get(row.group);
    if (existing) {
      existing.rows.push(row);
      existing.count += row.count;
    } else {
      groups.set(row.group, { group: row.group, count: row.count, rows: [row] });
    }
  }
  return [...groups.values()];
}

/**
 * Records the meter owed and could not write, across every posture.
 *
 * The number that means revenue went unbilled. `degraded` is the posture
 * that produces it in the default configuration: the request was served,
 * the guarantee was marked as not made, and the hole is countable.
 */
export function gapCount(gaps: readonly MeterGapRow[]): number {
  return gaps.reduce((total, row) => total + row.count, 0);
}

/** Gaps in the `degraded` posture specifically, which is the default. */
export function degradedGapCount(gaps: readonly MeterGapRow[]): number {
  return gaps
    .filter((row) => row.failure_mode === "degraded")
    .reduce((total, row) => total + row.count, 0);
}

/**
 * The tone a node row reads in.
 *
 * `err` for a node that is in the cluster and outside the total, because
 * that is unbilled traffic. `warn` for a covered node whose chain has not
 * moved off genesis, which is what a meter that never started looks like.
 */
export function nodeTone(node: MeterNodeRow): "ok" | "warn" | "err" {
  if (!node.covered) return "err";
  if ((node.head_seq ?? 0) === 0) return "warn";
  return "ok";
}

/** The head an operator should read for a node, covered or not. */
export function nodeHead(node: MeterNodeRow): number | null {
  if (node.covered) return node.head_seq ?? 0;
  return node.last_known_seq ?? null;
}

/**
 * The one line a verification run leaves on screen.
 *
 * A broken chain reports the sequence number it broke at. "Verification
 * failed" tells an operator nothing they can act on; a sequence number
 * tells them which receipt to open.
 */
export function verifyHeadline(result: MeterVerifyResult | null): string {
  if (!result) return "";
  switch (result.outcome) {
    case "ok":
      return `Chain verified: ${(result.entries ?? 0).toLocaleString()} entries, every link intact.`;
    case "broken":
      return `Chain broken at sequence ${result.broken_seq ?? "unknown"}: ${
        result.reason ?? "no reason reported"
      }`;
    case "not_started":
      return result.state === "off"
        ? "Nothing to verify: attestation is off on this node."
        : "Nothing to verify: the chain has not been created yet.";
    case "unreadable":
      return `The chain could not be read: ${result.reason ?? "no reason reported"}`;
    default:
      return `Unrecognised verification outcome: ${result.outcome}`;
  }
}

/** The tone the verification line reads in. */
export function verifyTone(
  result: MeterVerifyResult | null,
): "ok" | "warn" | "err" | "neutral" {
  if (!result) return "neutral";
  if (result.outcome === "ok") return "ok";
  if (result.outcome === "broken") return "err";
  if (result.outcome === "unreadable") return "err";
  return "warn";
}
