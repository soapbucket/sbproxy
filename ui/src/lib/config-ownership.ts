// Reading GET /admin/config/effective into the three questions the config
// page asks: may this operator edit the file, where does the configuration
// actually come from, and which settings are set somewhere else.
//
// Pure functions, separate from the view, because the interesting cases are
// the ones that are awkward to reach through a browser: a node with an
// authority configured but never reached, a git base under an authority
// overlay, and a response that failed to load at all.
import type { ConfigProvenance, EffectiveConfigResponse } from "../api";

export interface ConfigOwnership {
  /** True only when this node's own file is the whole configuration. */
  locallyOwned: boolean;
  base?: EffectiveConfigResponse["layers"] extends infer L
    ? L extends { base?: infer B }
      ? B
      : never
    : never;
  authority: NonNullable<NonNullable<EffectiveConfigResponse["layers"]>["authority"]> | null;
  localLeaves: number;
  totalLeaves: number;
}

/**
 * Read an effective-config response into ownership state, or `null` when
 * there is no response yet.
 *
 * `null` and "not locally owned" are deliberately different. A view that
 * conflated them would lock the editor while the first request was still in
 * flight, which reads as a permanent loss of control over the node rather
 * than as a page that has not finished loading.
 */
export function readOwnership(
  data: EffectiveConfigResponse | null | undefined,
): ConfigOwnership | null {
  if (!data) return null;
  return {
    locallyOwned: data.locally_owned === true,
    base: data.layers?.base,
    authority: data.layers?.authority ?? null,
    localLeaves: data.locally_owned_leaves ?? 0,
    totalLeaves: data.total_leaves ?? 0,
  };
}

/**
 * Whether the editor should refuse to offer a write.
 *
 * Locks only on a definite `false`. An unknown answer leaves the editor
 * usable and the server as the gate, which is where enforcement lives
 * anyway: the same write from curl gets the same 409.
 */
export function isEditorLocked(ownership: ConfigOwnership | null): boolean {
  return ownership?.locallyOwned === false;
}

/** One sentence naming where the configuration comes from. */
export function ownershipSummary(ownership: ConfigOwnership | null): string {
  if (!ownership) return "";
  if (ownership.locallyOwned) return "This node owns its configuration.";
  const parts: string[] = [];
  if (ownership.base?.kind === "git") {
    parts.push(
      `${ownership.base.repo} at ${ownership.base.reference} (${ownership.base.commit.slice(0, 12)})`,
    );
  }
  if (ownership.authority) {
    parts.push(
      `authority ${ownership.authority.authority_id} revision ${ownership.authority.revision} in ${ownership.authority.mode} mode`,
    );
  }
  return parts.length ? `Configuration comes from ${parts.join(", plus ")}.` : "";
}

/** Human label for one leaf's provenance. */
export function provenanceLabel(owner: ConfigProvenance | "suppressed" | unknown): string {
  if (owner === "local") return "local";
  if (owner === "authority") return "authority";
  if (owner === "suppressed") return "discarded by the remote layer";
  if (owner && typeof owner === "object" && "git" in (owner as object)) {
    const git = (owner as { git: { commit: string } }).git;
    return `git ${git.commit.slice(0, 12)}`;
  }
  return "unknown";
}

/**
 * Cap on the not-owned-here list. A replace-mode node owns almost nothing,
 * and rendering its entire configuration as a table helps no one.
 */
export const OWNED_ELSEWHERE_LIMIT = 200;

/**
 * The settings an operator cannot change on this node, capped.
 *
 * Only the exceptions. A few hundred rows reading "local" would bury the
 * handful that are the actual answer.
 */
export function ownedElsewhere(
  data: EffectiveConfigResponse | null | undefined,
): { path: string; owner: ConfigProvenance }[] {
  const provenance = data?.provenance;
  if (!provenance) return [];
  return Object.entries(provenance)
    .filter(([, owner]) => owner !== "local")
    .slice(0, OWNED_ELSEWHERE_LIMIT)
    .map(([path, owner]) => ({ path, owner }));
}
