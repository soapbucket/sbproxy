import { describe, expect, it } from "vitest";
import { applyEdits, coerceScalar, dottedPath, PatchError } from "./config-patch";

const ANNOTATED = `# Front-line proxy for the API estate.
# Do not raise the port without talking to netops first.
proxy:
  http_bind_port: 8080 # keep in sync with the load balancer
  workers: 4

origins:
  # The public API. Owned by the platform team.
  "api.test":
    action:
      type: proxy
      url: https://upstream.test
`;

describe("applyEdits", () => {
  it("preserves every comment and the key order around an edit", () => {
    const out = applyEdits(ANNOTATED, [{ path: ["proxy", "http_bind_port"], value: 8081 }]);
    expect(out).toContain("# Front-line proxy for the API estate.");
    expect(out).toContain("# Do not raise the port without talking to netops first.");
    expect(out).toContain("# keep in sync with the load balancer");
    expect(out).toContain("# The public API. Owned by the platform team.");
    expect(out).toContain("http_bind_port: 8081");
    // Order is unchanged: port before workers, proxy before origins.
    expect(out.indexOf("http_bind_port")).toBeLessThan(out.indexOf("workers"));
    expect(out.indexOf("proxy:")).toBeLessThan(out.indexOf("origins:"));
  });

  it("leaves the rest of the document byte-identical", () => {
    const out = applyEdits(ANNOTATED, [{ path: ["proxy", "workers"], value: 8 }]);
    const before = ANNOTATED.split("\n").filter((l) => !l.includes("workers"));
    const after = out.split("\n").filter((l) => !l.includes("workers"));
    expect(after).toEqual(before);
  });

  it("edits a key that contains a dot without reinterpreting it as nesting", () => {
    const out = applyEdits(ANNOTATED, [
      { path: ["origins", "api.test", "action", "url"], value: "https://other.test" },
    ]);
    expect(out).toContain("https://other.test");
    expect(out).toContain('"api.test":');
    // No `api:` section was invented from the dotted hostname.
    expect(out).not.toMatch(/^\s+api:\s*$/m);
  });

  it("creates a section that does not exist yet", () => {
    const out = applyEdits(ANNOTATED, [{ path: ["access_log", "enabled"], value: true }]);
    expect(out).toContain("access_log:");
    expect(out).toContain("enabled: true");
    expect(out).toContain("# Front-line proxy for the API estate.");
  });

  it("removes a key rather than blanking it", () => {
    const out = applyEdits(ANNOTATED, [{ path: ["proxy", "workers"], remove: true }]);
    expect(out).not.toContain("workers");
    expect(out).toContain("http_bind_port: 8080");
  });

  it("applies several edits in order, last write winning on a repeated path", () => {
    const out = applyEdits(ANNOTATED, [
      { path: ["proxy", "workers"], value: 8 },
      { path: ["proxy", "workers"], value: 16 },
    ]);
    expect(out).toContain("workers: 16");
    expect(out).not.toContain("workers: 8");
  });

  it("is a no-op with no edits, down to the byte", () => {
    expect(applyEdits(ANNOTATED, [])).toBe(ANNOTATED);
  });

  /// The whole point of the module. A round trip through parse and
  /// serialize must not be how an operator loses their comments.
  it("does not rewrite the document when an edit sets the value already there", () => {
    const out = applyEdits(ANNOTATED, [{ path: ["proxy", "http_bind_port"], value: 8080 }]);
    expect(out).toBe(ANNOTATED);
  });

  it("refuses to replace a scalar with a section", () => {
    // proxy.http_bind_port is a number; treating it as a section would
    // silently discard the port.
    expect(() =>
      applyEdits(ANNOTATED, [{ path: ["proxy", "http_bind_port", "nested"], value: 1 }]),
    ).toThrow(PatchError);
  });

  it("reports a parse failure rather than writing a repaired document", () => {
    expect(() => applyEdits("proxy:\n  - [unclosed\n", [{ path: ["a"], value: 1 }])).toThrow(
      PatchError,
    );
  });

  it("refuses an edit with no path", () => {
    expect(() => applyEdits(ANNOTATED, [{ path: [], value: 1 }])).toThrow(PatchError);
  });
});

describe("coerceScalar", () => {
  it("passes strings through untouched, including ones that look numeric", () => {
    expect(coerceScalar("8080", "string")).toEqual({ value: "8080" });
    expect(coerceScalar("  spaced  ", "string")).toEqual({ value: "  spaced  " });
  });

  it("parses numbers and integers", () => {
    expect(coerceScalar("8080", "integer")).toEqual({ value: 8080 });
    expect(coerceScalar(" 1.5 ", "number")).toEqual({ value: 1.5 });
  });

  it("rejects a fractional value for an integer field", () => {
    expect(coerceScalar("1.5", "integer")).toEqual({ error: "must be a whole number" });
  });

  it("rejects text that is not a number", () => {
    expect(coerceScalar("eighty eighty", "integer")).toEqual({ error: "must be a number" });
    expect(coerceScalar("", "number")).toEqual({ error: "must be a number" });
    expect(coerceScalar("Infinity", "number")).toEqual({ error: "must be a number" });
  });

  it("parses booleans strictly", () => {
    expect(coerceScalar("true", "boolean")).toEqual({ value: true });
    expect(coerceScalar("false", "boolean")).toEqual({ value: false });
    expect(coerceScalar("yes", "boolean")).toEqual({ error: "must be true or false" });
  });
});

describe("dottedPath", () => {
  it("joins segments the way the server does", () => {
    expect(dottedPath(["proxy", "http_bind_port"])).toEqual({
      dotted: "proxy.http_bind_port",
      ambiguous: false,
    });
  });

  /// An origin key is a hostname, so this is the common case rather than an
  /// exotic one. The server's provenance map has the same ambiguity, which
  /// is why the answer is flagged rather than trusted.
  it("flags a path whose segment contains a dot as ambiguous", () => {
    expect(dottedPath(["origins", "api.test", "action", "url"])).toEqual({
      dotted: "origins.api.test.action.url",
      ambiguous: true,
    });
  });
});
