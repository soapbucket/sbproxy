// Turning the config JSON Schema into a form descriptor.
//
// The schema is around 300KB and genuinely polymorphic in places, so this
// does not pretend to render all of it. It renders the tractable subset,
// scalars, enums, arrays of scalars, and objects with declared properties,
// and marks everything else opaque so the view can drop to a YAML editor
// scoped to that node alone.
//
// Opaque nodes are found by shape rather than by a list of known paths.
// A `serde_json::Value` field in the Rust types emits a schema with a
// description and nothing else, and a `Vec<Value>` emits `items: true`.
// Detecting that means the four fields that are opaque today
// (`origins[].action`, `policies`, `transforms`, `authentication`) need no
// special-casing, and a fifth added later is handled without a UI change.
// A hardcoded path list would silently render the new one as an empty
// object, which is the worst of the available failure modes: it looks like
// a field with no settings rather than a field this form cannot describe.

/** A JSON Schema node, loosely typed because the schema is data. */
export type JsonSchema = Record<string, unknown> | boolean;

export type ScalarType = "string" | "number" | "integer" | "boolean";

export interface NodeBase {
  /** Path segments from the document root. Not dot-joined: an origin key is a hostname and contains dots. */
  path: string[];
  /** The final path segment, as written in the document. */
  key: string;
  /** Human label. The schema's title when it has one, otherwise the key. */
  title: string;
  description?: string;
}

export type FormNode =
  | (NodeBase & {
      kind: "scalar";
      type: ScalarType;
      /** Allowed values, when the schema constrains them. */
      choices?: (string | number)[];
      default?: unknown;
      /** Whether the schema admits null, which is how `Option<T>` renders. */
      nullable: boolean;
    })
  | (NodeBase & { kind: "scalarList"; itemType: ScalarType })
  | (NodeBase & { kind: "object"; fields: FormNode[] })
  | (NodeBase & {
      kind: "map";
      /** Keys present in the document. The schema does not know them. */
      entries: { key: string; fields: FormNode[] }[];
    })
  | (NodeBase & { kind: "opaque"; reason: string });

/**
 * How deep the walk goes before it stops describing and starts deferring.
 *
 * Not a correctness guard (the `$ref` cycle check below is), a usability
 * one. Past this depth a generated form is worse than the YAML it replaced:
 * the labels lose their context and the nesting no longer fits on screen.
 */
export const MAX_DEPTH = 6;

const SCALAR_TYPES = new Set(["string", "number", "integer", "boolean"]);

/**
 * Whether a value is a keyed object, as opposed to a scalar, an array, or
 * absent.
 *
 * Takes `unknown` because it is used both on schema nodes and on document
 * values. Arrays are excluded deliberately: a YAML list is `typeof "object"`,
 * and treating one as a keyed object would have the walk look for properties
 * on a sequence.
 */
function isObjectSchema(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Follow `$ref` to its definition.
 *
 * Returns `null` on a reference already on the current chain, which is a
 * cycle. Config types are recursive in places (an overlay source contains
 * sources), and a walker that followed those would not return.
 */
function resolveRef(
  schema: JsonSchema,
  root: Record<string, unknown>,
  chain: string[],
): { schema: JsonSchema; chain: string[] } | null {
  if (!isObjectSchema(schema)) return { schema, chain };
  const ref = schema["$ref"];
  if (typeof ref !== "string") return { schema, chain };
  if (chain.includes(ref)) return null;
  const name = ref.replace("#/definitions/", "");
  const definitions = (root["definitions"] ?? {}) as Record<string, JsonSchema>;
  const target = definitions[name];
  if (target === undefined) return null;
  return resolveRef(target, root, [...chain, ref]);
}

/**
 * Collapse `allOf: [{$ref: ...}]` into the referenced schema.
 *
 * Draft-07 gives `$ref` no defined interaction with sibling keywords, so
 * schemars wraps the reference in a single-branch `allOf` whenever the field
 * also carries a doc comment or a default. Nearly every non-scalar field in
 * this schema is spelled that way, `proxy` included, so a walker that does
 * not unwrap it renders the entire configuration as opaque and still passes
 * every test written against a hand-made fixture.
 *
 * The outer keywords win on merge: the description on the field is the doc
 * comment for that field, and the one on the definition describes the type.
 */
function flattenAllOf(
  schema: JsonSchema,
  root: Record<string, unknown>,
  chain: string[],
): { schema: JsonSchema; chain: string[] } | null {
  let current = schema;
  let currentChain = chain;
  // Bounded rather than `while (true)`: the chain check already stops a
  // cycle, and a bound means a schema shape nobody anticipated cannot hang
  // the browser.
  for (let hop = 0; hop < MAX_DEPTH; hop += 1) {
    if (!isObjectSchema(current)) return { schema: current, chain: currentChain };
    const branches = current["allOf"];
    if (!Array.isArray(branches) || branches.length !== 1) {
      return { schema: current, chain: currentChain };
    }
    const inner = resolveRef(branches[0] as JsonSchema, root, currentChain);
    if (inner === null) return null;
    currentChain = inner.chain;
    if (!isObjectSchema(inner.schema)) return { schema: inner.schema, chain: currentChain };
    const outer = { ...current };
    delete outer["allOf"];
    current = { ...inner.schema, ...outer };
  }
  return { schema: current, chain: currentChain };
}

/**
 * Collapse the `anyOf` shapes schemars emits for `Option<T>` into the inner
 * schema plus a nullable flag. Anything else with a branch is left alone
 * for the caller to treat as opaque.
 */
function unwrapNullable(schema: Record<string, unknown>): {
  schema: Record<string, unknown>;
  nullable: boolean;
} {
  for (const keyword of ["anyOf", "oneOf"]) {
    const branches = schema[keyword];
    if (!Array.isArray(branches) || branches.length !== 2) continue;
    const nulls = branches.filter(
      (b) => isObjectSchema(b) && b["type"] === "null",
    );
    const others = branches.filter(
      (b) => isObjectSchema(b) && b["type"] !== "null",
    );
    if (nulls.length === 1 && others.length === 1 && isObjectSchema(others[0])) {
      // Keep the outer description: schemars puts the doc comment on the
      // wrapper and the shape on the branch.
      const inner = others[0] as Record<string, unknown>;
      return {
        schema: { description: schema["description"], ...inner },
        nullable: true,
      };
    }
  }
  // `type: ["string", "null"]` is the other spelling.
  const type = schema["type"];
  if (Array.isArray(type) && type.length === 2 && type.includes("null")) {
    const real = type.find((t) => t !== "null");
    return { schema: { ...schema, type: real }, nullable: true };
  }
  return { schema, nullable: false };
}

/**
 * Reduce a schema node to something with a `type` or `properties` on it, by
 * following `$ref`, unwrapping single-branch `allOf`, and peeling `Option<T>`
 * until none of the three applies.
 *
 * One loop rather than three sequential steps, because each of them can
 * expose another. The common spelling in this schema is an optional field
 * whose branch is a `$ref` whose definition wraps its own `$ref` in `allOf`:
 * `{"anyOf": [{"$ref": "#/definitions/Admin"}, {"type": "null"}]}`. Peeling
 * the nullable there yields a bare `$ref`, and stopping at that point
 * reports the field as opaque. Nearly every optional block in the config is
 * spelled that way, so the mistake costs most of the form and no test
 * written against a hand-made fixture notices.
 */
function normalize(
  rawSchema: JsonSchema,
  root: Record<string, unknown>,
  chain: string[],
): { schema: JsonSchema; chain: string[]; nullable: boolean } | null {
  let current = rawSchema;
  let currentChain = chain;
  let nullable = false;

  for (let pass = 0; pass < 2 * MAX_DEPTH; pass += 1) {
    const referenced = resolveRef(current, root, currentChain);
    if (referenced === null) return null;
    const flattened = flattenAllOf(referenced.schema, root, referenced.chain);
    if (flattened === null) return null;
    currentChain = flattened.chain;
    if (!isObjectSchema(flattened.schema)) {
      return { schema: flattened.schema, chain: currentChain, nullable };
    }
    const peeled = unwrapNullable(flattened.schema);
    nullable = nullable || peeled.nullable;
    // Settled when a pass changes nothing more to follow.
    const settled =
      peeled.schema["$ref"] === undefined &&
      peeled.schema["allOf"] === undefined &&
      !peeled.nullable;
    current = peeled.schema;
    if (settled) return { schema: current, chain: currentChain, nullable };
  }
  return { schema: current, chain: currentChain, nullable };
}

function scalarChoices(schema: Record<string, unknown>): (string | number)[] | undefined {
  const direct = schema["enum"];
  if (Array.isArray(direct)) {
    const usable = direct.filter(
      (v): v is string | number => typeof v === "string" || typeof v === "number",
    );
    return usable.length === direct.length ? usable : undefined;
  }
  // schemars renders a plain unit-variant enum as oneOf of single-value
  // enums, each carrying its own doc comment.
  const branches = schema["oneOf"];
  if (!Array.isArray(branches)) return undefined;
  const values: (string | number)[] = [];
  for (const branch of branches) {
    if (!isObjectSchema(branch)) return undefined;
    const inner = branch["enum"];
    if (!Array.isArray(inner) || inner.length !== 1) return undefined;
    const value = inner[0];
    if (typeof value !== "string" && typeof value !== "number") return undefined;
    values.push(value);
  }
  return values.length ? values : undefined;
}

function titleFor(schema: Record<string, unknown>, key: string): string {
  const title = schema["title"];
  return typeof title === "string" && title.length ? title : key;
}

function describe(schema: Record<string, unknown>): string | undefined {
  const description = schema["description"];
  return typeof description === "string" && description.length ? description : undefined;
}

function opaque(path: string[], key: string, title: string, description: string | undefined, reason: string): FormNode {
  return { kind: "opaque", path, key, title, description, reason };
}

/**
 * Describe one schema node as a form field.
 *
 * `docValue` is consulted only to enumerate the keys of a free-form map,
 * which the schema by definition does not know. Everything else comes from
 * the schema.
 */
function buildNode(
  rawSchema: JsonSchema,
  root: Record<string, unknown>,
  path: string[],
  key: string,
  docValue: unknown,
  depth: number,
  chain: string[],
): FormNode {
  const normalized = normalize(rawSchema, root, chain);
  if (normalized === null) {
    return opaque(path, key, key, undefined, "the schema for this field refers to itself");
  }
  const resolved = { schema: normalized.schema, chain: normalized.chain };
  if (!isObjectSchema(resolved.schema)) {
    // `true` accepts anything; `false` accepts nothing. Both are opaque to
    // a form, and both really do occur in this schema.
    return opaque(path, key, key, undefined, "the schema accepts any value here");
  }

  const schema = resolved.schema;
  const nullable = normalized.nullable;
  const title = titleFor(schema, key);
  const description = describe(schema);

  const choices = scalarChoices(schema);
  const type = schema["type"];

  if (choices && (typeof type !== "string" || SCALAR_TYPES.has(type))) {
    return {
      kind: "scalar",
      path,
      key,
      title,
      description,
      type: typeof type === "string" && SCALAR_TYPES.has(type) ? (type as ScalarType) : "string",
      choices,
      default: schema["default"],
      nullable,
    };
  }

  if (typeof type === "string" && SCALAR_TYPES.has(type)) {
    return {
      kind: "scalar",
      path,
      key,
      title,
      description,
      type: type as ScalarType,
      default: schema["default"],
      nullable,
    };
  }

  if (type === "array") {
    const items = schema["items"];
    const itemResolved =
      items === undefined ? null : resolveRef(items as JsonSchema, root, resolved.chain);
    const itemSchema = itemResolved?.schema;
    if (isObjectSchema(itemSchema) && typeof itemSchema["type"] === "string") {
      const itemType = itemSchema["type"] as string;
      if (SCALAR_TYPES.has(itemType)) {
        return { kind: "scalarList", path, key, title, description, itemType: itemType as ScalarType };
      }
    }
    // `items: true` is `Vec<serde_json::Value>`: a list of anything.
    return opaque(path, key, title, description, "a list whose entries the schema does not describe");
  }

  if (type === "object" || schema["properties"] !== undefined || schema["additionalProperties"] !== undefined) {
    if (depth >= MAX_DEPTH) {
      return opaque(path, key, title, description, `nested deeper than ${MAX_DEPTH} levels`);
    }
    const properties = schema["properties"];
    if (isObjectSchema(properties)) {
      const record = (docValue ?? {}) as Record<string, unknown>;
      const fields = Object.entries(properties).map(([name, child]) =>
        buildNode(
          child as JsonSchema,
          root,
          [...path, name],
          name,
          isObjectSchema(record) ? record[name] : undefined,
          depth + 1,
          resolved.chain,
        ),
      );
      return { kind: "object", path, key, title, description, fields };
    }

    const additional = schema["additionalProperties"];
    if (additional !== undefined && additional !== false) {
      // A free-form map: `origins`, keyed by hostname. The schema knows the
      // value shape and nothing about the keys, so the document supplies
      // them. A map with no entries yet renders as an empty group rather
      // than as a missing section, so it is obvious where to add one.
      const record = isObjectSchema(docValue) ? (docValue as Record<string, unknown>) : {};
      const entries = Object.keys(record).map((entryKey) => {
        const child = buildNode(
          additional as JsonSchema,
          root,
          [...path, entryKey],
          entryKey,
          record[entryKey],
          depth + 1,
          resolved.chain,
        );
        return {
          key: entryKey,
          fields: child.kind === "object" ? child.fields : [child],
        };
      });
      return { kind: "map", path, key, title, description, entries };
    }

    return opaque(path, key, title, description, "an object whose properties the schema does not describe");
  }

  // No type, no properties, no branch we understand: `serde_json::Value`.
  return opaque(path, key, title, description, "the schema does not describe this field's shape");
}

/**
 * Build the top-level form descriptor from the schema and the current
 * document.
 *
 * @param root the parsed `sb-config.schema.json`
 * @param doc the parsed current config, used only to enumerate map keys
 */
export function buildForm(root: JsonSchema, doc: unknown): FormNode[] {
  if (!isObjectSchema(root)) return [];
  const properties = root["properties"];
  if (!isObjectSchema(properties)) return [];
  const record = isObjectSchema(doc) ? (doc as Record<string, unknown>) : {};
  return Object.entries(properties).map(([name, child]) =>
    buildNode(child as JsonSchema, root, [name], name, record[name], 1, []),
  );
}

/** Depth-first walk over every node, parents before children. */
export function walkForm(nodes: FormNode[], visit: (node: FormNode) => void): void {
  for (const node of nodes) {
    visit(node);
    if (node.kind === "object") walkForm(node.fields, visit);
    if (node.kind === "map") for (const entry of node.entries) walkForm(entry.fields, visit);
  }
}

/** Every node the form can render as an actual input. */
export function editableNodes(nodes: FormNode[]): FormNode[] {
  const out: FormNode[] = [];
  walkForm(nodes, (node) => {
    if (node.kind === "scalar" || node.kind === "scalarList") out.push(node);
  });
  return out;
}

/** Read the value at `path` out of a parsed document. */
export function valueAt(doc: unknown, path: string[]): unknown {
  let cursor: unknown = doc;
  for (const segment of path) {
    if (!isObjectSchema(cursor)) return undefined;
    cursor = (cursor as Record<string, unknown>)[segment];
  }
  return cursor;
}
