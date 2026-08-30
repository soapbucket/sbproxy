import { describe, expect, it } from "vitest";
import { flattenPromptOverlay } from "../api";

/**
 * WOR-2343: the Prompts page rendered empty forever against a working
 * backend. It used the generic `asList` helper, which looks for a known
 * key (`prompts`, `overlays`, `items`, `data`) or the first array-valued
 * property; the real response nests under `hosts` and every value is an
 * object, so the helper returned `[]` with no error surfaced anywhere.
 *
 * The fixture below is the shape `handle_prompts_list` builds in
 * crates/sbproxy-core/src/admin.rs.
 */
const RESPONSE = {
  hosts: {
    "api.example.com": {
      prompts: {
        greeting: {
          default_version: "2",
          effective_version: "2",
          versions: ["1", "2"],
        },
        // No pin, so the runtime picks the highest numeric label.
        summarize: {
          default_version: null,
          effective_version: "3",
          versions: ["1", "2", "3"],
        },
      },
    },
    "alt.example.com": {
      prompts: {
        greeting: {
          default_version: null,
          effective_version: "1",
          versions: ["1"],
        },
      },
    },
  },
};

describe("flattenPromptOverlay", () => {
  it("flattens hosts into one row per host and prompt", () => {
    const rows = flattenPromptOverlay(RESPONSE);
    expect(rows).toHaveLength(3);
    expect(rows.map((r) => `${r.host}/${r.name}`)).toEqual([
      "alt.example.com/greeting",
      "api.example.com/greeting",
      "api.example.com/summarize",
    ]);
  });

  it("carries the pin and the effective version separately", () => {
    const rows = flattenPromptOverlay(RESPONSE);
    const pinned = rows.find((r) => r.host === "api.example.com" && r.name === "greeting");
    expect(pinned?.pinned).toBe("2");
    expect(pinned?.active).toBe("2");
    expect(pinned?.versions).toEqual(["1", "2"]);

    // An unpinned prompt still has an active version. Collapsing the two
    // would make it look like nothing is being served.
    const unpinned = rows.find((r) => r.name === "summarize");
    expect(unpinned?.pinned).toBeUndefined();
    expect(unpinned?.active).toBe("3");
  });

  it("sorts stably so a poll does not reshuffle the page", () => {
    const forward = flattenPromptOverlay(RESPONSE).map((r) => `${r.host}/${r.name}`);
    const reversedInput = {
      hosts: Object.fromEntries(Object.entries(RESPONSE.hosts).reverse()),
    };
    expect(flattenPromptOverlay(reversedInput).map((r) => `${r.host}/${r.name}`)).toEqual(
      forward,
    );
  });

  it("returns an empty list for shapes it cannot read, rather than throwing", () => {
    expect(flattenPromptOverlay(null)).toEqual([]);
    expect(flattenPromptOverlay(undefined)).toEqual([]);
    expect(flattenPromptOverlay({})).toEqual([]);
    expect(flattenPromptOverlay({ hosts: null })).toEqual([]);
    expect(flattenPromptOverlay({ hosts: { h: {} } })).toEqual([]);
    expect(flattenPromptOverlay({ hosts: { h: { prompts: null } } })).toEqual([]);
  });

  it("tolerates a prompt entry missing its versions array", () => {
    const rows = flattenPromptOverlay({
      hosts: { h: { prompts: { p: { effective_version: "1" } } } },
    });
    expect(rows).toEqual([
      {
        host: "h",
        name: "p",
        pinned: undefined,
        active: "1",
        versions: [],
        labels: {},
      },
    ]);
  });

  // WOR-2582. Labels are a movable pointer at a version, so the row has
  // to carry them separately from the pin: a pin is one pointer per
  // prompt and cannot express staging and production sitting on
  // different versions at once, which is the whole reason labels exist.
  it("carries labels alongside the pin rather than collapsing them", () => {
    const rows = flattenPromptOverlay({
      hosts: {
        h: {
          prompts: {
            p: {
              default_version: "1",
              effective_version: "1",
              versions: ["1", "2"],
              labels: { production: "1", staging: "2" },
            },
          },
        },
      },
    });
    expect(rows[0].labels).toEqual({ production: "1", staging: "2" });
    expect(rows[0].pinned).toBe("1");
  });

  it("reads a server that predates labels as a prompt with none", () => {
    const rows = flattenPromptOverlay({
      hosts: { h: { prompts: { p: { effective_version: "1", versions: ["1"] } } } },
    });
    expect(rows[0].labels).toEqual({});
  });

  it("ignores a labels field that is not an object rather than throwing", () => {
    const rows = flattenPromptOverlay({
      hosts: { h: { prompts: { p: { effective_version: "1", labels: "nope" } } } },
    });
    expect(rows[0].labels).toEqual({});
  });
});
