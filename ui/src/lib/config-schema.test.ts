import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  buildForm,
  editableNodes,
  MAX_DEPTH,
  valueAt,
  walkForm,
  type FormNode,
  type JsonSchema,
} from "./config-schema";

function schema(properties: Record<string, JsonSchema>, definitions: Record<string, JsonSchema> = {}) {
  return { type: "object", properties, definitions };
}

function find(nodes: FormNode[], path: string[]): FormNode | undefined {
  let found: FormNode | undefined;
  walkForm(nodes, (node) => {
    if (node.path.length === path.length && node.path.every((p, i) => p === path[i])) found = node;
  });
  return found;
}

describe("buildForm scalars", () => {
  it("describes each scalar type", () => {
    const nodes = buildForm(
      schema({
        port: { type: "integer", description: "Bind port." },
        ratio: { type: "number" },
        name: { type: "string", title: "Display name" },
        on: { type: "boolean", default: false },
      }),
      {},
    );
    expect(nodes.map((n) => [n.key, n.kind])).toEqual([
      ["port", "scalar"],
      ["ratio", "scalar"],
      ["name", "scalar"],
      ["on", "scalar"],
    ]);
    const port = nodes[0];
    expect(port.kind === "scalar" && port.type).toBe("integer");
    expect(port.description).toBe("Bind port.");
    expect(nodes[2].title).toBe("Display name");
    // No title in the schema falls back to the key, never to a blank label.
    expect(nodes[1].title).toBe("ratio");
  });

  it("reads a plain enum as a choice list", () => {
    const nodes = buildForm(schema({ mode: { type: "string", enum: ["overlay", "replace"] } }), {});
    expect(nodes[0].kind === "scalar" && nodes[0].choices).toEqual(["overlay", "replace"]);
  });

  /// schemars renders a unit-variant Rust enum as `oneOf` of single-value
  /// enums so each variant can carry its own doc comment. Without this the
  /// most common enum shape in the schema would render as opaque.
  it("reads the oneOf spelling schemars uses for unit enums", () => {
    const nodes = buildForm(
      schema({
        mode: {
          oneOf: [
            { enum: ["overlay"], description: "Merge on top." },
            { enum: ["replace"], description: "Take over." },
          ],
        },
      }),
      {},
    );
    expect(nodes[0].kind).toBe("scalar");
    expect(nodes[0].kind === "scalar" && nodes[0].choices).toEqual(["overlay", "replace"]);
  });

  it("treats Option<T> as a nullable scalar rather than as a branch it cannot render", () => {
    for (const spelling of [
      { anyOf: [{ type: "string" }, { type: "null" }] },
      { type: ["string", "null"] },
    ]) {
      const nodes = buildForm(schema({ label: spelling as JsonSchema }), {});
      expect(nodes[0].kind).toBe("scalar");
      expect(nodes[0].kind === "scalar" && nodes[0].nullable).toBe(true);
    }
  });

  it("keeps the wrapper's description when unwrapping a nullable", () => {
    const nodes = buildForm(
      schema({
        label: { description: "What to call it.", anyOf: [{ type: "string" }, { type: "null" }] },
      }),
      {},
    );
    expect(nodes[0].description).toBe("What to call it.");
  });
});

describe("buildForm structure", () => {
  it("descends into declared object properties", () => {
    const nodes = buildForm(
      schema({ proxy: { type: "object", properties: { workers: { type: "integer" } } } }),
      {},
    );
    expect(nodes[0].kind).toBe("object");
    const workers = find(nodes, ["proxy", "workers"]);
    expect(workers?.kind).toBe("scalar");
  });

  it("follows a $ref to its definition", () => {
    const nodes = buildForm(
      schema(
        { proxy: { $ref: "#/definitions/Proxy" } },
        { Proxy: { type: "object", properties: { workers: { type: "integer" } } } },
      ),
      {},
    );
    expect(find(nodes, ["proxy", "workers"])?.kind).toBe("scalar");
  });

  it("reads an array of scalars as a list", () => {
    const nodes = buildForm(schema({ hosts: { type: "array", items: { type: "string" } } }), {});
    expect(nodes[0].kind).toBe("scalarList");
    expect(nodes[0].kind === "scalarList" && nodes[0].itemType).toBe("string");
  });

  it("enumerates a free-form map's keys from the document, not the schema", () => {
    const nodes = buildForm(
      schema(
        { origins: { type: "object", additionalProperties: { $ref: "#/definitions/Origin" } } },
        { Origin: { type: "object", properties: { url: { type: "string" } } } },
      ),
      { origins: { "api.test": { url: "https://a" }, "web.test": { url: "https://b" } } },
    );
    const map = nodes[0];
    expect(map.kind).toBe("map");
    expect(map.kind === "map" && map.entries.map((e) => e.key)).toEqual(["api.test", "web.test"]);
    expect(find(nodes, ["origins", "api.test", "url"])?.kind).toBe("scalar");
  });

  it("renders a map with no entries as an empty group rather than omitting it", () => {
    const nodes = buildForm(
      schema({ origins: { type: "object", additionalProperties: { type: "object" } } }),
      {},
    );
    expect(nodes[0].kind).toBe("map");
    expect(nodes[0].kind === "map" && nodes[0].entries).toEqual([]);
  });
});

describe("buildForm opaque detection", () => {
  /// The four opaque fields today are `serde_json::Value` in the Rust types.
  /// Detecting the shape rather than the path means a fifth one added later
  /// falls back to the YAML editor without a UI change, instead of
  /// rendering as a section with no settings in it.
  it("marks a schema with only a description as opaque", () => {
    const nodes = buildForm(
      schema({ action: { description: "Action describing what the origin does." } }),
      {},
    );
    expect(nodes[0].kind).toBe("opaque");
    expect(nodes[0].kind === "opaque" && nodes[0].reason).toMatch(/does not describe/);
    // The description still reaches the operator; it is the only guidance
    // the schema offers for a field the form cannot render.
    expect(nodes[0].description).toBe("Action describing what the origin does.");
  });

  it("marks `items: true` arrays as opaque", () => {
    const nodes = buildForm(schema({ policies: { type: "array", items: true } }), {});
    expect(nodes[0].kind).toBe("opaque");
    expect(nodes[0].kind === "opaque" && nodes[0].reason).toMatch(/entries/);
  });

  it("marks an object with no declared properties as opaque", () => {
    const nodes = buildForm(schema({ variables: { type: "object" } }), {});
    expect(nodes[0].kind).toBe("opaque");
  });

  it("marks a polymorphic oneOf it cannot reduce to choices as opaque", () => {
    const nodes = buildForm(
      schema({
        thing: {
          oneOf: [
            { type: "object", properties: { a: { type: "string" } } },
            { type: "object", properties: { b: { type: "string" } } },
          ],
        },
      }),
      {},
    );
    expect(nodes[0].kind).toBe("opaque");
  });

  /// Config types really are recursive: an overlay source contains sources.
  /// A walker that followed those would not return.
  it("stops at a self-referential definition instead of recursing forever", () => {
    const nodes = buildForm(
      schema(
        { source: { $ref: "#/definitions/Source" } },
        {
          Source: {
            type: "object",
            properties: { overlay: { $ref: "#/definitions/Source" } },
          },
        },
      ),
      {},
    );
    const overlay = find(nodes, ["source", "overlay"]);
    expect(overlay?.kind).toBe("opaque");
    expect(overlay?.kind === "opaque" && overlay.reason).toMatch(/refers to itself/);
  });

  it("stops describing past the depth cap", () => {
    let deep: JsonSchema = { type: "string" };
    for (let i = 0; i < MAX_DEPTH + 3; i += 1) {
      deep = { type: "object", properties: { down: deep } };
    }
    const nodes = buildForm(schema({ top: deep }), {});
    const opaqueNodes: FormNode[] = [];
    walkForm(nodes, (n) => {
      if (n.kind === "opaque") opaqueNodes.push(n);
    });
    expect(opaqueNodes.length).toBeGreaterThan(0);
    expect(opaqueNodes[0].kind === "opaque" && opaqueNodes[0].reason).toMatch(/deeper than/);
  });

  it("marks a missing definition as opaque rather than throwing", () => {
    const nodes = buildForm(schema({ thing: { $ref: "#/definitions/Absent" } }), {});
    expect(nodes[0].kind).toBe("opaque");
  });

  it("marks a boolean schema as opaque", () => {
    const nodes = buildForm(schema({ anything: true }), {});
    expect(nodes[0].kind).toBe("opaque");
  });
});

describe("helpers", () => {
  it("returns nothing for a schema with no properties", () => {
    expect(buildForm({ type: "object" }, {})).toEqual([]);
    expect(buildForm(true, {})).toEqual([]);
  });

  it("collects the nodes that render as inputs", () => {
    const nodes = buildForm(
      schema({
        port: { type: "integer" },
        action: { description: "opaque" },
        proxy: { type: "object", properties: { workers: { type: "integer" } } },
      }),
      {},
    );
    expect(editableNodes(nodes).map((n) => n.path.join("."))).toEqual([
      "port",
      "proxy.workers",
    ]);
  });

  it("reads a value at a path, and undefined off the end of one", () => {
    const doc = { proxy: { workers: 4 } };
    expect(valueAt(doc, ["proxy", "workers"])).toBe(4);
    expect(valueAt(doc, ["proxy", "missing"])).toBeUndefined();
    expect(valueAt(doc, ["proxy", "workers", "deeper"])).toBeUndefined();
    expect(valueAt(undefined, ["a"])).toBeUndefined();
  });
});

describe("against the real committed schema", () => {
  // Guards the assumptions above against the actual document. A schemars
  // upgrade that changed how enums or Option<T> render would otherwise turn
  // most of the form opaque and nothing would fail.
  // Read off disk rather than imported. A plain JSON import would have
  // TypeScript infer a literal type for a 2MB document, and Vite's `?raw`
  // is denied outside the ui/ root.
  const real = JSON.parse(
    readFileSync(new URL("../../../schemas/sb-config.schema.json", import.meta.url), "utf8"),
  ) as JsonSchema;

  it("renders the top-level sections", () => {
    const nodes = buildForm(real, {});
    expect(nodes.map((n) => n.key)).toContain("proxy");
    expect(nodes.map((n) => n.key)).toContain("origins");
  });

  it("renders a useful number of real fields rather than collapsing to opaque", () => {
    const nodes = buildForm(real, {});
    // Not a precise count, which would break on every schema change. A
    // floor, which catches the failure that matters: a schemars change that
    // makes the walker give up on everything.
    expect(editableNodes(nodes).length).toBeGreaterThan(100);
  });

  it("finds the proxy bind port as an editable scalar", () => {
    const nodes = buildForm(real, {});
    const port = find(nodes, ["proxy", "http_bind_port"]);
    expect(port?.kind).toBe("scalar");
  });

  /// The spelling that cost most of the form once already. `proxy.admin` is
  /// `Option<AdminConfig>`, so its schema is an `anyOf` over a `$ref` and
  /// null, and the definition wraps its own refs in `allOf`. Peeling only
  /// the nullable leaves a bare `$ref` that reports as opaque, and the whole
  /// block disappears from the form with nothing failing.
  it("descends into an optional block whose branch is a reference", () => {
    const nodes = buildForm(real, {});
    const admin = find(nodes, ["proxy", "admin"]);
    expect(admin?.kind).toBe("object");
    const bindPort = find(nodes, ["proxy", "admin", "port"]);
    expect(bindPort?.kind).toBe("scalar");
  });

  it("treats the four documented opaque fields as opaque", () => {
    const nodes = buildForm(real, { origins: { "api.test": {} } });
    for (const path of [
      ["origins", "api.test", "action"],
      ["origins", "api.test", "policies"],
      ["origins", "api.test", "transforms"],
      ["origins", "api.test", "authentication"],
    ]) {
      const node = find(nodes, path);
      expect(node?.kind, path.join(".")).toBe("opaque");
    }
  });
});
