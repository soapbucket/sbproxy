import { describe, expect, it } from "vitest";

import type {
  ExtensionBundleRecord,
  ExtensionInventorySnapshot,
} from "../api";
import {
  hooksForBundle,
  loadLabel,
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
      detail: "loaded but not attached",
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
});
