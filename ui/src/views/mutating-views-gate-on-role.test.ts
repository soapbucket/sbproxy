import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

/*
 * WOR-2576. A detector for the render half of the console's RBAC.
 *
 * The API client refuses a mutation from a read_only session at
 * `assertCapability`, so nothing here is a security boundary and no view
 * can leak access by failing this test. What it catches is the other
 * failure: a view that offers a live button whose only outcome is a 403,
 * which is the console lying about what this operator can do.
 *
 * The list of mutating calls is derived from `api.ts` rather than
 * written down here. A hand-maintained list would go stale the first
 * time someone added a route, and a guard narrower than its claim is
 * worse than none: it would keep passing while the thing it names went
 * uncovered. So the set is computed from which client methods reach
 * `sendJson` or `sendRaw`, which is exactly the set the server's
 * state-changing-method rule refuses for `read_only`.
 */

const viewsDir = path.dirname(fileURLToPath(import.meta.url));
const apiSource = fs.readFileSync(
  path.join(viewsDir, "..", "api.ts"),
  "utf8",
);

/**
 * Client methods that reach a state-changing HTTP method.
 *
 * Parsed off the `export const api = {` object literal by walking it
 * brace-balanced, so a method whose body spans lines is read whole
 * rather than by a line-oriented regex that would miss it.
 */
function mutatingApiMethods(): Set<string> {
  const start = apiSource.indexOf("export const api = {");
  if (start < 0) throw new Error("api object literal not found in api.ts");

  const body = apiSource.slice(start);
  const found = new Set<string>();

  // Walk each top-level `name:` entry and capture its value text up to
  // the comma that closes it at depth 1.
  const entryStart = /(?:^|\n)\s{2}(\w+):/g;
  let match: RegExpExecArray | null;
  const entries: { name: string; from: number }[] = [];
  while ((match = entryStart.exec(body)) !== null) {
    entries.push({ name: match[1], from: match.index + match[0].length });
  }

  for (let i = 0; i < entries.length; i += 1) {
    const from = entries[i].from;
    const to = i + 1 < entries.length ? entries[i + 1].from : body.length;
    const value = body.slice(from, to);
    if (/\bsendJson\s*[<(]/.test(value) || /\bsendRaw\s*\(/.test(value)) {
      found.add(entries[i].name);
    }
  }
  return found;
}

const MUTATING = mutatingApiMethods();

const views = fs
  .readdirSync(viewsDir)
  .filter((f) => f.endsWith("View.vue"))
  .map(
    (f) =>
      [f, fs.readFileSync(path.join(viewsDir, f), "utf8")] as const,
  );

/**
 * Views that call a mutating client method and are deliberately not
 * gated at render time, each with the reason.
 *
 * Keep this short and keep every entry true. An entry here is a place
 * the console still renders a control that a read_only operator will see
 * refused, which is a worse experience than a disabled button but is not
 * an access problem: the client and the server both still refuse.
 */
const UNGATED_BY_DESIGN: Record<string, string> = {
  // Signing in and out are the two calls that must work for every role,
  // including one this build does not recognize. `assertCapability`
  // exempts them for the same reason.
  "LoginView.vue": "sign-in and sign-out are exempt from the gate by design",
};

describe("views that mutate gate their controls on the session role (WOR-2576)", () => {
  it("derives a non-trivial set of mutating client methods", () => {
    // If the parse breaks, every assertion below passes vacuously. This
    // is the tripwire for that.
    expect(MUTATING.size).toBeGreaterThan(20);
    expect(MUTATING.has("putConfig")).toBe(true);
    expect(MUTATING.has("configRollback")).toBe(true);
    expect(MUTATING.has("setLogLevel")).toBe(true);
  });

  it("does not classify a plain read as a mutation", () => {
    expect(MUTATING.has("drift")).toBe(false);
    expect(MUTATING.has("federation")).toBe(false);
    expect(MUTATING.has("licensing")).toBe(false);
    expect(MUTATING.has("configHistory")).toBe(false);
  });

  it("finds views to check", () => {
    expect(views.length).toBeGreaterThan(20);
  });

  it.each(views.map(([name]) => name))("%s", (name) => {
    const source = views.find(([f]) => f === name)![1];
    const called = [...source.matchAll(/\bapi\.(\w+)\s*\(/g)].map((m) => m[1]);
    const mutations = [...new Set(called.filter((c) => MUTATING.has(c)))];

    if (!mutations.length) return;
    if (name in UNGATED_BY_DESIGN) return;

    expect(
      source.includes("useCapabilities"),
      `${name} calls mutating client methods (${mutations.join(", ")}) but does ` +
        "not read useCapabilities, so it renders live controls that a read_only " +
        "session will see refused. Gate them, or add an entry to " +
        "UNGATED_BY_DESIGN with the reason.",
    ).toBe(true);

    /*
     * An import is not a gate. Requiring the identifier to appear in the
     * template region as well is what stops this from passing on a view
     * that imported the composable and then wired nothing to it, which
     * is the shape a half-finished refactor leaves behind.
     */
    const template = source.slice(source.indexOf("<template>"));
    expect(
      template.includes("canMutate") || template.includes("ReadOnlyNotice"),
      `${name} reads useCapabilities in its script but its template never ` +
        "mentions canMutate or renders a ReadOnlyNotice, so nothing is " +
        "actually gated.",
    ).toBe(true);
  });
});
