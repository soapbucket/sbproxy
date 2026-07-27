import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const viewsDir = path.dirname(fileURLToPath(import.meta.url));

/**
 * `useAsync` does not load on its own. Passing `pollMs` starts an interval,
 * but the first tick is one whole interval away, so a view that never calls
 * `run` renders its empty state forever (or, when polling, until the first
 * tick lands). Both new views shipped with exactly that bug, and neither
 * the type checker nor a component test caught it, because an empty list is
 * a legitimate state.
 *
 * So check the source: a view that constructs a `useAsync` has to trigger it.
 */
describe("views load their data", () => {
  const files = fs
    .readdirSync(viewsDir)
    .filter((f) => f.endsWith("View.vue"))
    .map((f) => [f, fs.readFileSync(path.join(viewsDir, f), "utf8")] as const)
    // Only the script block counts. A template's `@retry="req.run"` is a
    // recovery affordance, not an initial load, and matching it would make
    // this test unable to fail.
    .map(([f, src]) => [f, /<script[^>]*>([\s\S]*?)<\/script>/.exec(src)?.[1] ?? ""] as const)
    .filter(([, src]) => src.includes("useAsync("));

  it("finds views to check", () => {
    expect(files.length).toBeGreaterThan(5);
  });

  it.each(files.map(([name]) => name))("%s triggers its loader", (name) => {
    const src = files.find(([f]) => f === name)![1];

    // Named handles: `const foo = useAsync(...)` must be run somewhere.
    const handles = [...src.matchAll(/const\s+(\w+)\s*=\s*useAsync\(/g)].map((m) => m[1]);

    for (const handle of handles) {
      // `onMounted(h.run)`, `onMounted(() => h.run())`, `h.run()`, or a
      // watcher with `immediate: true` all count as triggering the load.
      const triggered =
        new RegExp(`${handle}\\.run\\b`).test(src) ||
        new RegExp(`\\b${handle}\\b[^\\n]*immediate`).test(src);
      expect(triggered, `${name}: ${handle} is created but never run`).toBe(true);
    }
  });
});
