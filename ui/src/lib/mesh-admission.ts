/*
 * Inbound mesh admission, derived from the Prometheus scrape.
 *
 * `mesh_transport_inbound_rejected_total` counts inbound cache RPC
 * connections this node refused or tore down, by `reason`. Nothing in the
 * console named the family, so the only place a refused peer showed up was
 * the node's own log.
 *
 * Two things about the family shape drive everything below.
 *
 * First, the counter registers lazily on its first increment, so a node
 * that has never refused a connection publishes no family at all. Absent
 * and zero are the same reading here, and both are healthy, but only the
 * second one can be stated as a number. `inboundAdmission` returns
 * `undefined` for absent so the panel can say "not reported" rather than
 * draw a zero over a signal nobody has observed.
 *
 * Second, `idle_timeout` is not a refusal. The client half re-evaluates
 * its connection recycle lazily, on its next request, so a peer pair with
 * nothing to say for the whole idle window gets reclaimed here as a matter
 * of course and a quiet cluster moves that counter by itself. Summing all
 * six reasons into one "rejections" number makes an idle fleet look under
 * attack. The split below matches the alert the mesh crate documents:
 * `reason!="idle_timeout"`.
 */

import { groupByLabel, type MetricFamily } from "./metrics";

/** The counter family this module reads. Renaming it blanks the panel. */
export const MESH_INBOUND_REJECTED_FAMILY =
  "mesh_transport_inbound_rejected_total";

/** The one `reason` value that is routine housekeeping, not a refusal. */
export const IDLE_RECLAIM_REASON = "idle_timeout";

/** What each `reason` means to an operator, in the order severity reads. */
const REASON_MEANING: Record<string, string> = {
  connection_limit:
    "This node was already serving its maximum inbound connections, so the peer was closed before it got a task. A sustained rate means peers are being turned away.",
  handshake_timeout:
    "The peer was admitted but its TLS handshake, including the wait for a handshake slot, ran past the admission deadline.",
  handshake_failed:
    "The handshake finished and was rejected: no client certificate, or one the mesh CA did not sign.",
  frame_timeout:
    "A request frame announced its length and then did not deliver the body inside the frame deadline.",
  write_timeout:
    "The response did not drain into the socket inside the write deadline, which is what a peer that asks and then stops reading looks like.",
  [IDLE_RECLAIM_REASON]:
    "An admitted connection began no request inside the idle window, so its slot was reclaimed. A quiet cluster does this on its own.",
};

/** One `reason` row, with the sentence that explains it. */
export interface AdmissionReasonRow {
  reason: string;
  count: number;
  meaning: string;
  /** False for `idle_timeout`, the routine reclaim. */
  refusal: boolean;
}

/** What the panel renders when the family is present. */
export interface InboundAdmissionReport {
  /** Connections turned away or torn down, excluding the idle reclaim. */
  refusals: number;
  /** Idle connections reclaimed. Routine, and counted apart from refusals. */
  idleReclaims: number;
  /** Refusals for want of an admission slot, the capacity signal. */
  connectionLimit: number;
  /** Every reason seen, refusals first and largest first inside each half. */
  rows: AdmissionReasonRow[];
}

function meaningFor(reason: string): string {
  return (
    REASON_MEANING[reason] ??
    "This node refused the connection for a reason the console does not have copy for yet."
  );
}

/**
 * Read inbound admission out of a parsed scrape.
 *
 * Returns `undefined` when the family is absent, which means this node has
 * refused nothing since it started (or runs no mesh transport at all).
 * That is not the same statement as zero and must not be rendered as one.
 */
export function inboundAdmission(
  families: MetricFamily[],
): InboundAdmissionReport | undefined {
  const family = families.find((f) => f.name === MESH_INBOUND_REJECTED_FAMILY);
  if (!family) return undefined;

  const rows: AdmissionReasonRow[] = groupByLabel(family, "reason").map(
    (entry) => ({
      reason: entry.key,
      count: entry.value,
      meaning: meaningFor(entry.key),
      refusal: entry.key !== IDLE_RECLAIM_REASON,
    }),
  );

  rows.sort((left, right) => {
    if (left.refusal !== right.refusal) return left.refusal ? -1 : 1;
    return right.count - left.count;
  });

  const sumWhere = (keep: (row: AdmissionReasonRow) => boolean) =>
    rows.filter(keep).reduce((total, row) => total + row.count, 0);

  return {
    refusals: sumWhere((row) => row.refusal),
    idleReclaims: sumWhere((row) => !row.refusal),
    connectionLimit: sumWhere((row) => row.reason === "connection_limit"),
    rows,
  };
}
