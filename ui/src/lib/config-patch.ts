// Applying form edits to a config document without destroying it.
//
// The obvious implementation reads the YAML into an object, mutates it, and
// serializes it back. That drops every comment and rewrites key order, and
// operators are right to call that data loss: the comments in a config file
// are often the only record of why a setting is what it is.
//
// So the form never re-serializes the document. It collects edits as
// path-and-value pairs and applies them to the parsed document tree, which
// the `yaml` package keeps comment-annotated and order-preserving. A field
// the form does not render is a field it cannot touch, by construction
// rather than by care.

import { parseDocument, type Document } from "yaml";

export interface SetEdit {
  path: string[];
  value: unknown;
}

export interface RemoveEdit {
  path: string[];
  remove: true;
}

export type Edit = SetEdit | RemoveEdit;

function isRemove(edit: Edit): edit is RemoveEdit {
  return (edit as RemoveEdit).remove === true;
}

export class PatchError extends Error {}

/**
 * Apply `edits` to `yamlText` and return the new text.
 *
 * Comments, key order, quoting style, and indentation of everything not
 * edited are preserved. Edits are applied in order, so two edits to the
 * same path resolve to the last one.
 *
 * @throws PatchError when the document does not parse, or when an edit
 * targets a path under a scalar (setting `a.b` where `a` is a string is a
 * bug in the caller, not something to silently repair by replacing `a`).
 */
export function applyEdits(yamlText: string, edits: Edit[]): string {
  const doc = parseDocument(yamlText);
  if (doc.errors.length) {
    throw new PatchError(doc.errors[0].message);
  }
  for (const edit of edits) {
    if (!edit.path.length) {
      throw new PatchError("an edit needs a path");
    }
    assertPathIsAddressable(doc, edit.path);
    if (isRemove(edit)) {
      doc.deleteIn(edit.path);
    } else {
      doc.setIn(edit.path, edit.value);
    }
  }
  return doc.toString();
}

/**
 * Refuse an edit whose parent path runs through a scalar.
 *
 * `setIn` would happily replace the scalar with a map, discarding whatever
 * was there. That is exactly the silent destruction this module exists to
 * avoid, so it is an error instead.
 */
function assertPathIsAddressable(doc: Document, path: string[]): void {
  for (let i = 1; i < path.length; i += 1) {
    const parent = path.slice(0, i);
    const existing = doc.getIn(parent);
    if (existing === undefined || existing === null) continue; // will be created
    const isContainer =
      typeof existing === "object" && existing !== null && ("items" in existing || "get" in existing);
    if (!isContainer) {
      throw new PatchError(
        `cannot set ${path.join(".")}: ${parent.join(".")} holds a single value, not a section`,
      );
    }
  }
}

/**
 * Coerce a form input's string into the type the schema declares.
 *
 * Returns `undefined` when the text cannot be that type, which the caller
 * shows as a field error rather than sending to the server. Catching it here
 * means a mistyped port is a red field rather than a round trip and a 400.
 */
export function coerceScalar(
  text: string,
  type: "string" | "number" | "integer" | "boolean",
): { value: unknown } | { error: string } {
  if (type === "string") return { value: text };
  const trimmed = text.trim();
  if (type === "boolean") {
    if (trimmed === "true") return { value: true };
    if (trimmed === "false") return { value: false };
    return { error: "must be true or false" };
  }
  if (trimmed === "") return { error: "must be a number" };
  const parsed = Number(trimmed);
  if (!Number.isFinite(parsed)) return { error: "must be a number" };
  if (type === "integer" && !Number.isInteger(parsed)) {
    return { error: "must be a whole number" };
  }
  return { value: parsed };
}

/**
 * The dotted path the server's provenance map and conflict list use.
 *
 * Reported with `ambiguous` when a segment contains a dot, because the
 * server joins path segments with dots too and an origin key is a hostname.
 * `origins["api.test"].action` and a hypothetical `origins.api.test.action`
 * render identically, so a lookup cannot distinguish them.
 *
 * Callers treat an ambiguous match as unknown rather than as an answer. That
 * follows the same rule as the rest of this feature: lock on a definite
 * answer, and otherwise let the server be the gate. Guessing here would
 * either lock a field an operator owns or unlock one they do not.
 */
export function dottedPath(path: string[]): { dotted: string; ambiguous: boolean } {
  return {
    dotted: path.join("."),
    ambiguous: path.some((segment) => segment.includes(".")),
  };
}
