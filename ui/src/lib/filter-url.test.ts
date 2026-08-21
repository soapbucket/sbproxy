import { describe, expect, it } from "vitest";

import { filterStateFromQuery, filterStateToQuery, groupByFromQuery } from "./filter-url";

const DIMENSIONS = ["model", "api_key_id", "tenant", "user"] as const;

describe("filter-url", () => {
  it("serializes only the set dimensions, so a shared link carries no noise", () => {
    expect(
      filterStateToQuery({
        model: "claude-sonnet-4",
        api_key_id: "",
        tenant: "acme",
        user: "",
      }),
    ).toEqual({ model: "claude-sonnet-4", tenant: "acme" });
  });

  it("serializes an empty state to an empty query", () => {
    expect(filterStateToQuery({ model: "", tenant: "" })).toEqual({});
  });

  it("reads the named keys back out of a parsed route query", () => {
    expect(
      filterStateFromQuery(
        { model: "gpt-5", tenant: "acme", unrelated: "x" },
        ["model", "api_key_id", "tenant", "user"],
      ),
    ).toEqual({ model: "gpt-5", api_key_id: "", tenant: "acme", user: "" });
  });

  it("takes the first value when a key repeats in the URL", () => {
    expect(
      filterStateFromQuery({ model: ["gpt-5", "claude-sonnet-4"] }, ["model"]),
    ).toEqual({ model: "gpt-5" });
  });

  it("treats null and non-string values as unset", () => {
    expect(
      filterStateFromQuery({ model: null, tenant: 7 }, ["model", "tenant"]),
    ).toEqual({ model: "", tenant: "" });
  });

  it("round-trips: state to query to state is the identity on set keys", () => {
    const state = { model: "claude-sonnet-4", api_key_id: "sbk_1", tenant: "", user: "" };
    const query = filterStateToQuery(state);
    expect(
      filterStateFromQuery(query, ["model", "api_key_id", "tenant", "user"]),
    ).toEqual(state);
  });
});

describe("groupByFromQuery", () => {
  it("keeps the known dimensions in canonical order, whatever order the link used", () => {
    expect(groupByFromQuery("user,model", DIMENSIONS)).toEqual(["model", "user"]);
  });

  // The report API refuses an unknown dimension with a 400, so a
  // shared link that carries one has to degrade rather than error.
  it("drops an unknown dimension instead of sending it", () => {
    expect(groupByFromQuery("model,flavor", DIMENSIONS)).toEqual(["model"]);
  });

  // Same for a repeated one: `group_by=model,model` is a 400.
  it("deduplicates a repeated dimension", () => {
    expect(groupByFromQuery("model,model,tenant", DIMENSIONS)).toEqual([
      "model",
      "tenant",
    ]);
  });

  it("returns nothing when the link names no known dimension, so the caller keeps its default", () => {
    expect(groupByFromQuery("", DIMENSIONS)).toEqual([]);
    expect(groupByFromQuery("flavor,vibes", DIMENSIONS)).toEqual([]);
  });
});
