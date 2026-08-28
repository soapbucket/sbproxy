import type { ApiError, ConfigHistoryBlastRadius, ConfigHistoryEntry } from "../api";

export type PresentationTone = "ok" | "warn" | "err" | "neutral";

const STATE_TONES: Record<ConfigHistoryEntry["state"], PresentationTone> = {
  applied: "ok",
  good: "ok",
  failed: "err",
  reverted: "warn",
};

/** Tone for the per-row state badge (applied/good/failed/reverted). */
export function historyStateTone(state: ConfigHistoryEntry["state"]): PresentationTone {
  return STATE_TONES[state] ?? "neutral";
}

const BLAST_RADIUS_TONES: Record<ConfigHistoryBlastRadius, PresentationTone> = {
  hitless: "ok",
  reload: "neutral",
  restart: "warn",
  breaking: "err",
};

/** Tone for the blast-radius badge. `null` (the lineage's first entry,
 *  with nothing to compare against) reads as neutral, same as an
 *  unrecognized value would. */
export function blastRadiusTone(
  radius: ConfigHistoryEntry["blast_radius"],
): PresentationTone {
  if (!radius) return "neutral";
  return BLAST_RADIUS_TONES[radius] ?? "neutral";
}

/** Display label for blast radius; `null` reads as "first revision"
 *  rather than a bare "n/a", since that is why it is null. */
export function blastRadiusLabel(radius: ConfigHistoryEntry["blast_radius"]): string {
  return radius ?? "first revision";
}

/** One-line summary of the subsystems that did not pick up a revision,
 *  or `null` when the revision applied everywhere (`degraded` empty). */
export function degradedSummary(degraded: readonly string[]): string | null {
  if (!degraded.length) return null;
  return `degraded: ${degraded.join(", ")}`;
}

/**
 * The history routes 404 with `{"error":"config history is not
 * enabled"}` when `proxy.config_history.enabled` is off or the store is
 * absent. That is an expected, opt-in-feature state, not a failure the
 * operator needs an error toast for. Every other status, and a 404 on
 * the detail route for an unknown digest (a different body, no "not
 * enabled" text), stays a real error and renders through ErrorState.
 */
export function isConfigHistoryDisabled(error: ApiError | null): boolean {
  if (!error || error.status !== 404) return false;
  return `${error.message} ${error.body}`.includes("not enabled");
}

/**
 * Whether a Roll back button may submit, and what it has to say first
 * (WOR-2460).
 *
 * The node computes the blast radius from the two stored documents and
 * refuses a `restart` or `breaking` rollback whose `confirm_revision`
 * does not name the target. This is the same rule on the client side, so
 * the button can be disabled and explained rather than the operator
 * finding out from a 409. The server refusal is the enforcer; this is
 * the affordance.
 *
 * **Nothing calls this yet.** The Roll back button belongs to the admin
 * console work that owns `ConfigView.vue`, and until it lands the
 * operator surface is `POST /admin/config/rollback` and
 * `sbproxy config rollback`. The rule is written and tested here ahead
 * of the button so the two cannot disagree about which radii need
 * typing, and so a reader of this file is not left guessing whether the
 * gate exists.
 *
 * `null` (the lineage's first entry, with nothing to compare against)
 * requires the typed confirmation too. An unknown radius is not a safe
 * radius, and the one action here that cannot be undone in process is
 * the wrong place to assume the best case.
 */
export interface RollbackGate {
  /** Whether the operator has to type the revision number back. */
  requiresTypedConfirmation: boolean;
  /** Whether the form may be submitted as it stands. */
  canSubmit: boolean;
  /** Why not, when `canSubmit` is false. */
  reason: string | null;
}

const TYPED_CONFIRMATION_RADII: ReadonlySet<string> = new Set([
  "restart",
  "breaking",
]);

/**
 * Gate one rollback submission.
 *
 * @param radius blast radius of rolling back to this revision, as
 *   `GET /admin/config/history` reports it.
 * @param targetRevision the revision the operator is rolling back to.
 * @param typed what they typed into the confirmation field, verbatim.
 */
export function rollbackGate(
  radius: ConfigHistoryBlastRadius | null,
  targetRevision: number,
  typed: string,
): RollbackGate {
  const requiresTypedConfirmation =
    radius === null || TYPED_CONFIRMATION_RADII.has(radius);
  if (!requiresTypedConfirmation) {
    return { requiresTypedConfirmation: false, canSubmit: true, reason: null };
  }
  const what = radius === null ? "unknown-radius" : radius;
  if (typed.trim() === String(targetRevision)) {
    return { requiresTypedConfirmation: true, canSubmit: true, reason: null };
  }
  return {
    requiresTypedConfirmation: true,
    canSubmit: false,
    reason:
      `rolling back to revision ${targetRevision} is a ${what} change, which an ` +
      `in-process swap cannot fully apply. type ${targetRevision} to confirm, and ` +
      `plan to restart this node`,
  };
}
