// Deciding, per field, whether the operator may edit it and what to tell
// them if not.
//
// Three things can lock a field. The node is managed elsewhere entirely, so
// nothing is editable. The specific setting is owned by a remote layer, even
// though the node owns others. Or the form cannot tell, because the path is
// ambiguous.
//
// The third case is not hypothetical. The server's provenance map joins path
// segments with dots and an origin key is a hostname, so
// `origins["api.test"].action` and `origins.api.test.action` are the same
// string. A lookup cannot distinguish them, so this reports unknown rather
// than picking one. Guessing would either lock a field the operator owns or
// unlock one they do not, and the server refuses the write either way, so the
// only thing guessing buys is a worse error.

import type { ConfigProvenance } from "../api";
import { dottedPath } from "./config-patch";
import type { FormNode } from "./config-schema";

export type LockReason = "node-managed-elsewhere" | "setting-owned-elsewhere" | "ambiguous-path";

export interface FieldState {
  /** Whether the form should refuse the edit locally. */
  locked: boolean;
  reason?: LockReason;
  /** Short badge text, or undefined when the field is plainly editable. */
  badge?: string;
  /** The layer that owns this setting, when known. */
  owner?: ConfigProvenance;
}

export interface OwnershipContext {
  /** True when nothing on this node is editable, which is `mode: replace` or a git source. */
  wholeDocumentLocked: boolean;
  /** Dotted path to owning layer, straight from GET /admin/config/effective. */
  provenance: Record<string, ConfigProvenance>;
  /** Label for the authority, for the badge. */
  authorityLabel?: string;
}

const EDITABLE: FieldState = { locked: false };

/**
 * Decide whether `node` is editable in `context`.
 *
 * A field with no provenance entry is treated as editable. That is the
 * newly-added-key case: a setting that does not exist in the running document
 * yet has nothing that could own it, and refusing it would make the form
 * unable to add anything. The server still has the last word, and its guard
 * decides the same question by re-running the merge rather than by looking
 * anything up, so a genuinely unownable addition is caught there.
 */
export function fieldState(node: FormNode, context: OwnershipContext): FieldState {
  if (context.wholeDocumentLocked) {
    return {
      locked: true,
      reason: "node-managed-elsewhere",
      badge: context.authorityLabel ?? "managed elsewhere",
    };
  }

  const { dotted, ambiguous } = dottedPath(node.path);
  const owner = context.provenance[dotted];

  if (ambiguous) {
    // Lock rather than allow. Unlike the unknown-ownership case at the node
    // level, here the operator is looking at one specific field and the
    // honest answer is that this form cannot tell who owns it. Offering an
    // edit that may be silently discarded is worse than sending them to the
    // raw editor, which the server will judge properly.
    return {
      locked: true,
      reason: "ambiguous-path",
      badge: "ownership unclear",
      owner,
    };
  }

  if (owner === undefined || owner === "local") return EDITABLE;

  return {
    locked: true,
    reason: "setting-owned-elsewhere",
    badge: ownerBadge(owner, context.authorityLabel),
    owner,
  };
}

function ownerBadge(owner: ConfigProvenance, authorityLabel?: string): string {
  if (owner === "authority") return authorityLabel ?? "authority";
  if (typeof owner === "object" && "git" in owner) {
    return `git ${owner.git.commit.slice(0, 12)}`;
  }
  return "managed elsewhere";
}

/** `authority <id> rev <n>`, the badge text for an authority-owned field. */
export function authorityLabel(
  authority: { authority_id: string; revision: number } | null | undefined,
): string | undefined {
  if (!authority) return undefined;
  return `authority ${authority.authority_id} rev ${authority.revision}`;
}

/**
 * Index a write guard's conflict list by dotted path so a field can render
 * its own error.
 *
 * A `409` naming six paths as one toast is a puzzle. The same information
 * attached to the six fields is a to-do list.
 */
export function conflictsByPath(
  conflicts: { path: string; owner?: unknown }[] | undefined,
): Record<string, true> {
  const out: Record<string, true> = {};
  for (const conflict of conflicts ?? []) out[conflict.path] = true;
  return out;
}

/**
 * Whether a form edit set is worth sending.
 *
 * An empty patch would still round-trip the document through the server's
 * validate-persist-reload path and bump nothing, so it is refused locally.
 */
export function hasChanges(edits: unknown[]): boolean {
  return edits.length > 0;
}
