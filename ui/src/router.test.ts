import { api } from "./api";
import { useAuth } from "./composables/useAuth";
import { beforeEach, describe, expect, it, vi } from "vitest";

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

describe("alert route", () => {
  it("resolves the alert operations page", () => {
    const route = router.resolve("/alerts");

    expect(route.name).toBe("alerts");
    expect(route.meta.title).toBe("Alerts");
  });
});

describe("auth guard", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("sends an unauthenticated visitor to /login carrying the destination", async () => {
    vi.spyOn(api, "session").mockResolvedValue({ authenticated: false } as never);
    await router.push("/keys");
    await router.isReady();
    expect(router.currentRoute.value.name).toBe("login");
    // The destination rides along so signing in returns them there.
    expect(router.currentRoute.value.query.next).toBe("/keys");
  });

  it("does not attach next for the root, which is the default landing", async () => {
    vi.spyOn(api, "session").mockResolvedValue({ authenticated: false } as never);
    await router.push("/");
    await router.isReady();
    expect(router.currentRoute.value.name).toBe("login");
    expect(router.currentRoute.value.query.next).toBeUndefined();
  });

  it("keeps an authenticated operator off the login route", async () => {
    vi.spyOn(api, "session").mockResolvedValue({
      authenticated: true,
      username: "admin",
      role: "admin",
    } as never);
    // `useAuth` is a module singleton and the guard only probes the session
    // when it has not settled yet, so establish the authenticated state
    // explicitly rather than relying on the guard to re-probe.
    await useAuth().refresh();
    // Move off /login first: a previous case left the router there, and
    // pushing the same route again is a duplicate navigation that vue-router
    // drops without ever consulting the guard.
    await router.push("/keys");
    expect(router.currentRoute.value.path).toBe("/keys");

    await router.push("/login");
    await router.isReady();
    expect(router.currentRoute.value.path).toBe("/");
  });

  it("signs the operator out when any request comes back 401", async () => {
    vi.spyOn(api, "session").mockResolvedValue({
      authenticated: true,
      username: "admin",
      role: "admin",
    } as never);
    const auth = useAuth();
    await auth.refresh();
    expect(auth.authenticated.value).toBe(true);

    // A lapsed session surfaces as a 401 on some unrelated panel request.
    // Without this the operator sits on a console where every panel reports
    // "Not authorized" and nothing tells them to sign in again.
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: false,
        status: 401,
        text: async () => "unauthorized",
      }),
    );
    await expect(api.keys()).rejects.toThrow();
    expect(auth.authenticated.value).toBe(false);
    vi.unstubAllGlobals();
  });
});
