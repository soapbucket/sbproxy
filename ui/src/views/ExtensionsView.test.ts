import { describe, expect, it } from "vitest";

import type {
  ExtensionBundleRecord,
  ExtensionHookRecord,
  ExtensionInventorySnapshot,
} from "../api";
import {
  bundleDetailClass,
  hookDetailClass,
  hooksForBundle,
  loadLabel,
  loadTone,
  sourceLabel,
  stateTone,
} from "../lib/extensions";
import extensionsView from "./ExtensionsView.vue?raw";

const bundle: ExtensionBundleRecord = {
  id: "request-policy",
  name: "Request policy",
  version: "1.2.0",
  package: "entry.js",
  source: "git",
  runtime: "javascript",
  state: "active",
  hook_ids: ["request-policy:policy:request_policy"],
  load: { phase: "candidate_load", status: "ok", detail: null },
};

const snapshot: ExtensionInventorySnapshot = {
  schema_version: 1,
  scope: {
    mode: "running",
    proxy_version: "0.9.0",
    config_revision: "sha256:config-revision",
  },
  summary: {
    bundles: 1,
    hooks: 2,
    active: 1,
    available: 1,
    failed: 0,
    collisions: 0,
  },
  bundles: [bundle],
  hooks: [
    {
      id: "request-policy:policy:request_policy",
      bundle_id: bundle.id,
      kind: "policy",
      registration: "git",
      dispatch: "chain",
      match_key: "request_policy",
      position: 0,
      state: "active",
      detail: null,
      runtime: "javascript",
      execution: {
        phase: "request",
        body_mode: "none",
        timeout_ms: 25,
        max_buffer_bytes: null,
      },
      capabilities: ["request.headers.read"],
    },
    {
      id: "request-policy:policy:fallback_policy",
      bundle_id: bundle.id,
      kind: "policy",
      registration: "git",
      dispatch: "chain",
      match_key: "fallback_policy",
      position: null,
      state: "available",
      // A hook record carries no detail unless a collision gave it one
      // (`apply_collision_states`,
      // `crates/sbproxy-core/src/extension_inventory.rs`). Every other
      // running-mode construction site leaves it null.
      detail: null,
      runtime: "javascript",
      execution: {
        phase: "request",
        body_mode: "none",
        timeout_ms: 25,
        max_buffer_bytes: null,
      },
      capabilities: [],
    },
  ],
  collisions: [],
};

describe("extension inventory presentation", () => {
  it("keeps hook registration evidence attached to its bundle", () => {
    expect(hooksForBundle(snapshot, bundle.id).map((hook) => hook.state)).toEqual([
      "active",
      "available",
    ]);
  });

  it("describes safe provenance and load evidence without inventing a digest", () => {
    expect(sourceLabel("link_time")).toBe("linked into binary");
    expect(sourceLabel("directory")).toBe("bundle directory");
    expect(sourceLabel("git")).toBe("pinned Git");
    expect(loadLabel(bundle.load)).toBe("loaded");
    expect(
      loadLabel({
        phase: "manifest",
        status: "failed",
        detail: "hook kind is unsupported",
      }),
    ).toBe("failed");
  });

  it("maps every operator state to a visible status tone", () => {
    expect(stateTone("active")).toBe("ok");
    expect(stateTone("available")).toBe("info");
    expect(stateTone("not_evaluated")).toBe("neutral");
    expect(stateTone("failed")).toBe("err");
    expect(stateTone("shadowed")).toBe("warn");
  });

  it("loads and renders the authoritative fields instead of raw JSON", () => {
    expect(extensionsView).toContain("api.extensions");
    expect(extensionsView).toContain("onMounted(loadExtensions)");
    expect(extensionsView).toContain("snapshot.scope.config_revision");
    expect(extensionsView).toContain("bundle.load.detail");
    expect(extensionsView).toContain("hook.execution.timeout_ms");
    expect(extensionsView).toContain("hook.capabilities");
    expect(extensionsView).toContain("<dt>Load</dt>");
    expect(extensionsView).not.toContain("Verification");
    expect(extensionsView).not.toContain("JSON.stringify(snapshot");
  });

  it("leaves a healthy Git refresh message unstyled and paints a rejected candidate red", () => {
    // The bug (WOR-2684): `.bundle__detail` carried unconditional error
    // coloring, so every poll of a healthy Git bundle rendered red. Both
    // fixtures below are the record `/api/extensions` really serves: the
    // loader publishes `phase: "candidate_load", status: "ok"` with the
    // redacted `<repo> at <ref> (<commit>)` provenance as the whole detail
    // (`crates/sbproxy-extension/src/bundle/loader.rs`, `load_detail` and
    // the `ExtensionBundleRecord` push beneath it), and
    // `annotate_inventory`
    // (`crates/sbproxy-core/src/extension_refresh.rs`) then prefixes the
    // cycle's health text and, on a rejected candidate, moves the status
    // to `degraded`.
    const healthy: ExtensionBundleRecord = {
      ...bundle,
      load: {
        phase: "candidate_load",
        status: "ok",
        detail:
          "refresh source unchanged; https://example.test/extensions.git at release-v1 (commit-a)",
      },
    };
    expect(bundleDetailClass(healthy)).toBe("bundle__detail");
    expect(bundleDetailClass(healthy)).not.toContain("bundle__detail--err");

    const rejectedCandidate: ExtensionBundleRecord = {
      ...bundle,
      load: {
        phase: "candidate_load",
        status: "degraded",
        detail:
          "refresh candidate rejected; serving last verified generation (3 consecutive failure(s)); https://example.test/extensions.git at release-v1 (commit-a)",
      },
    };
    expect(bundleDetailClass(rejectedCandidate)).toContain("bundle__detail--err");
  });

  it("paints a bundle whose hooks failed red even though its load record says ok", () => {
    // An unresolved exclusive collision leaves the match key with no
    // winner, so `apply_collision_states` marks both hooks `failed` and
    // `derive_bundle_states` propagates `failed` to the bundle
    // (`crates/sbproxy-core/src/extension_inventory.rs`). Nothing rewrites
    // the loader's `status: "ok"` on the way, so a gate reading only
    // `load.status` misses the one failure the running inventory can
    // actually report.
    const collided: ExtensionBundleRecord = {
      ...bundle,
      state: "failed",
      load: {
        phase: "candidate_load",
        status: "ok",
        detail: "https://example.test/extensions.git at release-v1 (commit-a)",
      },
    };
    expect(bundleDetailClass(collided)).toContain("bundle__detail--err");

    // The same collision writes the hook half. `apply_collision_states`
    // sets `state: "failed"` and, for the unresolved case, a detail of
    // `"<resolution> on `<match_key>`"`; the winner of a resolved
    // collision leaves the loser `shadowed` with the winning
    // registration named. Both are the shapes asserted here.
    const failedHook: ExtensionHookRecord = {
      ...snapshot.hooks[1],
      state: "failed",
      detail: "rejected duplicate exclusive registrations on `fallback_policy`",
    };
    expect(hookDetailClass(failedHook)).toContain("hook__detail--err");

    const shadowedHook: ExtensionHookRecord = {
      ...snapshot.hooks[1],
      state: "shadowed",
      detail:
        "linked registration takes precedence; request-policy:policy:request_policy serves `fallback_policy`",
    };
    // Shadowed is a warning, not a failure: the winner still serves the
    // key, so the reason reads in the neutral treatment.
    expect(hookDetailClass(shadowedHook)).toBe("hook__detail");
    expect(hookDetailClass(snapshot.hooks[1])).toBe("hook__detail");
  });

  it("keeps loadTone reserved for genuine failure or degraded status", () => {
    expect(loadTone({ phase: "candidate_load", status: "ok", detail: "note" })).toBe("ok");
    expect(
      loadTone({ phase: "manifest", status: "failed", detail: "hook kind is unsupported" }),
    ).toBe("err");
    expect(loadTone({ phase: "candidate_load", status: "degraded", detail: null })).toBe("err");
    // `unattributed` is the synthesized link-time bundle's status
    // (`extension_inventory.rs`, `ensure_unattributed_failure_bundle`),
    // which is a gap in attribution rather than a load failure.
    expect(loadTone({ phase: "inventory", status: "unattributed", detail: null })).toBe(
      "neutral",
    );
  });

  it("keeps error coloring on the modifier class only", () => {
    // The regression the fix removed lived in the base rule, so the base
    // rule is what has to stay free of the error tokens. Both regexes
    // tolerate the selector list on one line or several.
    const baseRuleMatch = extensionsView.match(
      /\.bundle__detail\s*,\s*\.hook__detail\s*\{([^}]*)\}/,
    );
    expect(baseRuleMatch).not.toBeNull();
    expect(baseRuleMatch?.[1]).not.toContain("var(--sb-err)");
    expect(baseRuleMatch?.[1]).not.toContain("var(--sb-err-bg)");

    const errRuleMatch = extensionsView.match(
      /\.bundle__detail--err\s*,\s*\.hook__detail--err\s*\{([^}]*)\}/,
    );
    expect(errRuleMatch).not.toBeNull();
    expect(errRuleMatch?.[1]).toContain("var(--sb-err)");
    expect(errRuleMatch?.[1]).toContain("var(--sb-err-bg)");

    // The paragraphs take their whole class list from the helpers above,
    // so those helpers are the gate rather than a second copy of it.
    expect(extensionsView).toContain(':class="bundleDetailClass(bundle)"');
    expect(extensionsView).toContain(':class="hookDetailClass(hook)"');
  });
});
