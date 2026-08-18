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
