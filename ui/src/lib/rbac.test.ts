import { describe, expect, it } from "vitest";

import {
  ADMIN_ROLE,
  capabilitiesFor,
  capabilityForRequest,
  hasCapability,
  READ_ONLY_ROLE,
  refusalReason,
  type Capability,
} from "./rbac";

describe("capabilitiesFor (WOR-2576)", () => {
  it("gives the admin role both the mutation and the content-inspection capability", () => {
    const caps = capabilitiesFor(ADMIN_ROLE);

    expect(caps.has("mutate")).toBe(true);
    expect(caps.has("inspect_content")).toBe(true);
  });

  it("gives the read_only role neither", () => {
    const caps = capabilitiesFor(READ_ONLY_ROLE);

    expect(caps.has("mutate")).toBe(false);
    expect(caps.has("inspect_content")).toBe(false);
  });

  /*
   * Default deny is the whole point. A role the console has never heard
   * of is a role whose permissions the console cannot reason about, and
   * the safe reading of "I do not know what this operator may do" is
   * "nothing", not "everything". This is what keeps a server-side role
   * added after this build ships from silently rendering as full admin.
   */
  it.each([
    "key-operator",
    "config-editor",
    "viewer",
    "org_admin",
    "ADMIN",
    "Admin",
    "read only",
    "",
    "   ",
  ])("denies every capability to the unrecognized role %j", (role) => {
    expect([...capabilitiesFor(role)]).toEqual([]);
  });

  it("denies every capability when no role is present at all", () => {
    expect([...capabilitiesFor(null)]).toEqual([]);
    expect([...capabilitiesFor(undefined)]).toEqual([]);
  });

  it("hands out a fresh set, so one caller cannot widen every later reader", () => {
    // A shared instance would be mutable privilege state, and this is the
    // one module where widening it would be worth someone's while.
    const caps = capabilitiesFor(READ_ONLY_ROLE) as Set<Capability>;
    caps.add("mutate");

    expect(capabilitiesFor(READ_ONLY_ROLE).has("mutate")).toBe(false);
    expect(hasCapability(READ_ONLY_ROLE, "mutate")).toBe(false);
  });
});

describe("hasCapability (WOR-2576)", () => {
  it("is false for read_only on both capabilities and true for admin", () => {
    expect(hasCapability(READ_ONLY_ROLE, "mutate")).toBe(false);
    expect(hasCapability(READ_ONLY_ROLE, "inspect_content")).toBe(false);
    expect(hasCapability(ADMIN_ROLE, "mutate")).toBe(true);
    expect(hasCapability(ADMIN_ROLE, "inspect_content")).toBe(true);
  });
});

/*
 * `capabilityForRequest` is the half that has to be as wide as the
 * server enforcer, because a request it classifies as needing nothing is
 * a request the console will never gate.
 *
 * The enforcers it mirrors, on `origin/main` at c1b393ad2:
 *   - crates/sbproxy-core/src/admin.rs:8043   read_only + state-changing
 *                                             method -> 403, method-shaped
 *                                             and route-blind, which is why
 *                                             this is keyed off the method
 *                                             and not off a route list.
 *   - crates/sbproxy-core/src/admin.rs:6608   GET /api/requests/{id}/content
 *                                             requires the admin role.
 *   - crates/sbproxy-core/src/admin_compression.rs:489
 *                                             the compression content record
 *                                             requires the admin role.
 */
describe("capabilityForRequest mirrors the server enforcers (WOR-2576)", () => {
  it.each(["POST", "PUT", "PATCH", "DELETE", "post", "put", "patch", "delete"])(
    "classifies the state-changing method %s as needing the mutate capability, whatever the path",
    (method) => {
      expect(capabilityForRequest(method, "/api/anything/at/all")).toBe("mutate");
    },
  );

  it.each(["GET", "HEAD", "OPTIONS", "get"])(
    "classifies the safe method %s as needing nothing by default",
    (method) => {
      expect(capabilityForRequest(method, "/api/requests")).toBeNull();
    },
  );

  it("classifies the request content sample as an admin-only read", () => {
    expect(capabilityForRequest("GET", "/api/requests/abc123/content")).toBe(
      "inspect_content",
    );
  });

  it("classifies the compression content record as an admin-only read", () => {
    expect(
      capabilityForRequest("GET", "/admin/compression/sessions/rec-7/content"),
    ).toBe("inspect_content");
  });

  it("still classifies an admin-only read carrying a query string", () => {
    expect(
      capabilityForRequest("GET", "/api/requests/abc123/content?redact=1"),
    ).toBe("inspect_content");
  });

  it("does not mistake the request row itself for the content sample", () => {
    expect(capabilityForRequest("GET", "/api/requests/abc123")).toBeNull();
    expect(capabilityForRequest("GET", "/api/requests")).toBeNull();
  });

  it("does not let a content-shaped suffix elsewhere in the path claim the exemption", () => {
    // `/content` has to be the last segment of a request-scoped path, not
    // any segment anywhere, or a future route would silently inherit the
    // admin-only classification and disappear for read_only operators.
    expect(capabilityForRequest("GET", "/api/content/requests/7")).toBeNull();
  });
});

describe("refusalReason (WOR-2576)", () => {
  it("names the role it refused and the capability it wanted", () => {
    const reason = refusalReason("mutate", READ_ONLY_ROLE);

    expect(reason).toContain("read_only");
    expect(reason.toLowerCase()).toContain("read-only");
  });

  it("says the server is the authority rather than implying the console is", () => {
    expect(refusalReason("inspect_content", READ_ONLY_ROLE)).toContain(
      "admin role",
    );
  });

  it("describes an unrecognized role as unrecognized rather than naming it a permission", () => {
    const reason = refusalReason("mutate", "key-operator");

    expect(reason).toContain("key-operator");
    expect(reason).toContain("not a role this console knows");
  });

  /*
   * A refusal string lands in the console UI and in nothing else, but the
   * role comes off a session the server minted, so it is still operator
   * input reaching a rendered surface. Keep it short and bounded rather
   * than echoing an arbitrarily long claim back.
   */
  it("bounds an absurd role string instead of echoing it whole", () => {
    const reason = refusalReason("mutate", "x".repeat(500));

    expect(reason.length).toBeLessThan(300);
  });
});
