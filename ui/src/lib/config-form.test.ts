import { describe, expect, it } from "vitest";
import type { ConfigProvenance } from "../api";
import { authorityLabel, conflictsByPath, fieldState, hasChanges } from "./config-form";
import type { FormNode } from "./config-schema";

const COMMIT = "b".repeat(40);

function scalar(path: string[]): FormNode {
  return {
    kind: "scalar",
    path,
    key: path[path.length - 1],
    title: path[path.length - 1],
    type: "string",
    nullable: false,
  };
}

function context(over: Partial<Parameters<typeof fieldState>[1]> = {}) {
  return {
    wholeDocumentLocked: false,
    provenance: {} as Record<string, ConfigProvenance>,
    ...over,
  };
}

describe("fieldState", () => {
  it("leaves a locally owned field editable", () => {
    const state = fieldState(
      scalar(["proxy", "http_bind_port"]),
      context({ provenance: { "proxy.http_bind_port": "local" } }),
    );
    expect(state).toEqual({ locked: false });
  });

  /// A setting that does not exist in the running document yet has nothing
  /// that could own it. Refusing it would leave the form unable to add
  /// anything at all.
  it("leaves a field with no provenance entry editable", () => {
    expect(fieldState(scalar(["access_log", "enabled"]), context()).locked).toBe(false);
  });

  it("locks a field the authority owns and names the revision", () => {
    const state = fieldState(
      scalar(["origins", "api", "action", "url"]),
      context({
        provenance: { "origins.api.action.url": "authority" },
        authorityLabel: "authority control-plane rev 12",
      }),
    );
    expect(state.locked).toBe(true);
    expect(state.reason).toBe("setting-owned-elsewhere");
    expect(state.badge).toBe("authority control-plane rev 12");
    expect(state.owner).toBe("authority");
  });

  it("locks a git-owned field and shows the short commit", () => {
    const state = fieldState(
      scalar(["proxy", "http_bind_port"]),
      context({
        provenance: {
          "proxy.http_bind_port": { git: { repo: "https://g.test/x.git", reference: "main", commit: COMMIT } },
        },
      }),
    );
    expect(state.locked).toBe(true);
    expect(state.badge).toBe("git bbbbbbbbbbbb");
  });

  it("locks everything when the whole document is managed elsewhere", () => {
    const state = fieldState(
      scalar(["proxy", "http_bind_port"]),
      context({
        wholeDocumentLocked: true,
        provenance: { "proxy.http_bind_port": "local" },
        authorityLabel: "authority control-plane rev 12",
      }),
    );
    expect(state.locked).toBe(true);
    expect(state.reason).toBe("node-managed-elsewhere");
    // Even a locally-provenanced field is locked, because under replace mode
    // the deny-listed paths are the only editable ones and this form does not
    // try to reproduce the deny list.
    expect(state.badge).toBe("authority control-plane rev 12");
  });

  /// Origin keys are hostnames, so this is the common case rather than an
  /// exotic one.
  it("locks a field whose dotted path is ambiguous rather than guessing", () => {
    const state = fieldState(
      scalar(["origins", "api.test", "action", "url"]),
      context({ provenance: { "origins.api.test.action.url": "local" } }),
    );
    expect(state.locked).toBe(true);
    expect(state.reason).toBe("ambiguous-path");
    expect(state.badge).toBe("ownership unclear");
  });

  it("falls back to a generic badge when no authority label is available", () => {
    const state = fieldState(
      scalar(["a"]),
      context({ provenance: { a: "authority" } }),
    );
    expect(state.badge).toBe("authority");
  });
});

describe("authorityLabel", () => {
  it("reads the applied authority into badge text", () => {
    expect(authorityLabel({ authority_id: "control-plane", revision: 12 })).toBe(
      "authority control-plane rev 12",
    );
  });

  it("is undefined with no authority applied", () => {
    expect(authorityLabel(null)).toBeUndefined();
    expect(authorityLabel(undefined)).toBeUndefined();
  });
});

describe("conflictsByPath", () => {
  it("indexes a guard rejection so each field can show its own error", () => {
    expect(
      conflictsByPath([
        { path: "origins.api.action.url", owner: "authority" },
        { path: "proxy.http_bind_port" },
      ]),
    ).toEqual({ "origins.api.action.url": true, "proxy.http_bind_port": true });
  });

  it("handles a missing conflict list", () => {
    expect(conflictsByPath(undefined)).toEqual({});
  });
});

describe("hasChanges", () => {
  it("refuses to send an empty patch", () => {
    expect(hasChanges([])).toBe(false);
    expect(hasChanges([{ path: ["a"], value: 1 }])).toBe(true);
  });
});
