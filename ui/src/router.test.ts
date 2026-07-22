import { describe, expect, it } from "vitest";

import { router } from "./router";

describe("session routes", () => {
  it("resolves the sessions index", () => {
    const route = router.resolve("/sessions");

    expect(route.name).toBe("sessions");
    expect(route.meta.title).toBe("Sessions");
  });

  it("encodes a session id when resolving its detail route", () => {
    const route = router.resolve({
      name: "session-detail",
      params: { sessionId: "tenant/session 1" },
    });

    expect(route.path).toBe("/sessions/tenant%2Fsession%201");
    expect(route.params.sessionId).toBe("tenant/session 1");
  });
});
