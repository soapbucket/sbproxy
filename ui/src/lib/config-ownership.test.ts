import { describe, expect, it } from "vitest";
import type { EffectiveConfigResponse } from "../api";
import {
  isEditorLocked,
  ownedElsewhere,
  ownershipSummary,
  OWNED_ELSEWHERE_LIMIT,
  provenanceLabel,
  readOwnership,
} from "./config-ownership";

const COMMIT = "a".repeat(40);

function response(over: Partial<EffectiveConfigResponse> = {}): EffectiveConfigResponse {
  return {
    yaml: "proxy: {}\n",
    provenance: { "proxy.http_bind_port": "local" },
    layers: { base: { kind: "local" }, authority: null },
    locally_owned: true,
    locally_owned_leaves: 1,
    total_leaves: 1,
    ...over,
  };
}

describe("readOwnership", () => {
  it("returns null before a response has arrived", () => {
    expect(readOwnership(null)).toBeNull();
    expect(readOwnership(undefined)).toBeNull();
  });

  it("reads a local node as owning its configuration", () => {
    const own = readOwnership(response());
    expect(own?.locallyOwned).toBe(true);
    expect(own?.authority).toBeNull();
  });

  it("treats a missing locally_owned field as not owned", () => {
    // An older or partial server response must not be read as permission
    // to write. The conservative reading is the safe one here: the server
    // refuses the write either way, and the page would otherwise promise an
    // edit it cannot deliver.
    const own = readOwnership(response({ locally_owned: undefined }));
    expect(own?.locallyOwned).toBe(false);
  });
});

describe("isEditorLocked", () => {
  it("does not lock while the answer is unknown", () => {
    expect(isEditorLocked(null)).toBe(false);
  });

  it("locks only on a definite negative", () => {
    expect(isEditorLocked(readOwnership(response({ locally_owned: false })))).toBe(true);
    expect(isEditorLocked(readOwnership(response()))).toBe(false);
  });
});

describe("ownershipSummary", () => {
  it("is a plain statement on a local node", () => {
    expect(ownershipSummary(readOwnership(response()))).toBe(
      "This node owns its configuration.",
    );
  });

  it("names the repository and the short commit for a git base", () => {
    const own = readOwnership(
      response({
        locally_owned: false,
        layers: {
          base: { kind: "git", repo: "https://git.test/fleet.git", reference: "main", commit: COMMIT },
          authority: null,
        },
      }),
    );
    expect(ownershipSummary(own)).toBe(
      "Configuration comes from https://git.test/fleet.git at main (aaaaaaaaaaaa).",
    );
  });

  it("names both layers when a git base sits under an authority overlay", () => {
    const own = readOwnership(
      response({
        locally_owned: false,
        layers: {
          base: { kind: "git", repo: "https://git.test/fleet.git", reference: "main", commit: COMMIT },
          authority: { authority_id: "control-plane", revision: 7, mode: "overlay" },
        },
      }),
    );
    expect(ownershipSummary(own)).toBe(
      "Configuration comes from https://git.test/fleet.git at main (aaaaaaaaaaaa), plus authority control-plane revision 7 in overlay mode.",
    );
  });

  it("names the authority alone on a local base", () => {
    const own = readOwnership(
      response({
        locally_owned: false,
        layers: {
          base: { kind: "local" },
          authority: { authority_id: "control-plane", revision: 12, mode: "replace" },
        },
      }),
    );
    expect(ownershipSummary(own)).toBe(
      "Configuration comes from authority control-plane revision 12 in replace mode.",
    );
  });

  it("is empty with no ownership loaded", () => {
    expect(ownershipSummary(null)).toBe("");
  });
});

describe("provenanceLabel", () => {
  it("labels each provenance shape", () => {
    expect(provenanceLabel("local")).toBe("local");
    expect(provenanceLabel("authority")).toBe("authority");
    expect(provenanceLabel("suppressed")).toBe("discarded by the remote layer");
    expect(
      provenanceLabel({ git: { repo: "https://git.test/x.git", reference: "main", commit: COMMIT } }),
    ).toBe("git aaaaaaaaaaaa");
  });

  it("does not invent a label for an unrecognised shape", () => {
    expect(provenanceLabel(undefined)).toBe("unknown");
    expect(provenanceLabel({ something: "else" })).toBe("unknown");
  });
});

describe("ownedElsewhere", () => {
  it("lists only the settings this node does not own", () => {
    const rows = ownedElsewhere(
      response({
        provenance: {
          "proxy.http_bind_port": "local",
          "origins.api.timeout": "authority",
          "origins.api.url": "local",
        },
      }),
    );
    expect(rows).toEqual([{ path: "origins.api.timeout", owner: "authority" }]);
  });

  it("is empty when every setting is local", () => {
    expect(ownedElsewhere(response())).toEqual([]);
  });

  it("is empty with no response", () => {
    expect(ownedElsewhere(null)).toEqual([]);
  });

  it("caps the list so a replace-mode node does not render its whole config", () => {
    const provenance: Record<string, "authority"> = {};
    for (let i = 0; i < OWNED_ELSEWHERE_LIMIT + 50; i += 1) {
      provenance[`origins.o${i}.url`] = "authority";
    }
    expect(ownedElsewhere(response({ provenance })).length).toBe(OWNED_ELSEWHERE_LIMIT);
  });
});
