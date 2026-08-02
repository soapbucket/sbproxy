import { effectScope } from "vue";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { ApiError } from "../api";
import { useAsync } from "./useAsync";
import { toast, useToasts } from "./useToasts";

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

describe("useAsync", () => {
  it("lets only the latest invocation update data and loading", async () => {
    const first = deferred<string>();
    const second = deferred<string>();
    const loads = [first.promise, second.promise];
    const state = useAsync(() => loads.shift() as Promise<string>);

    const firstRun = state.run();
    const secondRun = state.run();
    first.resolve("older");
    await firstRun;

    expect(state.loading.value).toBe(true);
    expect(state.data.value).toBeNull();

    second.resolve("newest");
    await secondRun;

    expect(state.loading.value).toBe(false);
    expect(state.data.value).toBe("newest");
    expect(state.error.value).toBeNull();
    expect(state.succeeded.value).toBe(true);
  });

  it("keeps last-known data while the latest failed invocation owns error state", async () => {
    const initial = deferred<string>();
    const older = deferred<string>();
    const latest = deferred<string>();
    const loads = [initial.promise, older.promise, latest.promise];
    const state = useAsync(() => loads.shift() as Promise<string>);

    const initialRun = state.run();
    initial.resolve("last-known");
    await initialRun;
    expect(state.succeeded.value).toBe(true);

    const olderRun = state.run();
    const latestRun = state.run();
    latest.reject(new ApiError(503, "latest unavailable", "latest body"));
    await latestRun;
    older.resolve("stale success");
    await olderRun;

    expect(state.data.value).toBe("last-known");
    expect(state.error.value?.status).toBe(503);
    expect(state.error.value?.body).toBe("latest body");
    expect(state.loading.value).toBe(false);
    expect(state.succeeded.value).toBe(false);
  });
});

describe("useAsync polling", () => {
  it("re-runs on the interval and keeps data visible between ticks", async () => {
    vi.useFakeTimers();
    let calls = 0;
    const scope = effectScope();
    let state!: ReturnType<typeof useAsync<number>>;
    scope.run(() => {
      state = useAsync(async () => ++calls, { pollMs: 1000 });
    });
    await state.run();
    expect(state.data.value).toBe(1);

    await vi.advanceTimersByTimeAsync(1000);
    expect(calls).toBeGreaterThan(1);
    // A refresh must not blank the panel the operator is reading.
    expect(state.data.value).not.toBeNull();
    scope.stop();
    vi.useRealTimers();
  });

  it("stops polling once the scope is disposed", async () => {
    vi.useFakeTimers();
    let calls = 0;
    const scope = effectScope();
    scope.run(() => {
      useAsync(async () => ++calls, { pollMs: 1000 });
    });
    await vi.advanceTimersByTimeAsync(1000);
    const afterFirst = calls;
    scope.stop();
    await vi.advanceTimersByTimeAsync(5000);
    // Leaving the view must not leave a timer hitting the admin API.
    expect(calls).toBe(afterFirst);
    vi.useRealTimers();
  });

  it("keeps the previous data when a refresh fails", async () => {
    vi.useFakeTimers();
    let calls = 0;
    const scope = effectScope();
    let state!: ReturnType<typeof useAsync<string>>;
    scope.run(() => {
      state = useAsync(async () => {
        calls += 1;
        if (calls > 1) throw new Error("upstream blip");
        return "first";
      }, { pollMs: 1000 });
    });
    await state.run();
    expect(state.data.value).toBe("first");

    await vi.advanceTimersByTimeAsync(1000);
    // A transient failure surfaces without emptying a dashboard someone
    // is actively watching.
    expect(state.data.value).toBe("first");
    expect(state.error.value).not.toBeNull();
    scope.stop();
    vi.useRealTimers();
  });

  it("does not poll at all without pollMs", async () => {
    vi.useFakeTimers();
    let calls = 0;
    const scope = effectScope();
    scope.run(() => {
      useAsync(async () => ++calls);
    });
    await vi.advanceTimersByTimeAsync(10_000);
    expect(calls).toBe(0);
    scope.stop();
    vi.useRealTimers();
  });

});

describe("useAsync refreshLabel", () => {
  // Sibling tests opt into fake timers without restoring them.
  beforeEach(() => vi.useRealTimers());

  it("toasts once per failure streak when a refresh fails over existing data", async () => {
    toast.clear();
    const { toasts } = useToasts();
    let attempt = 0;
    const loader = vi.fn(async () => {
      attempt += 1;
      if (attempt === 1) return "first-good";
      throw new ApiError(500, "upstream exploded");
    });

    const scope = effectScope();
    const state = scope.run(() => useAsync(loader, { refreshLabel: "Alerts" }))!;

    await state.run();
    expect(state.data.value).toBe("first-good");
    expect(toasts).toHaveLength(0);

    // First failing refresh: stale data stays, so say so.
    await state.run();
    expect(state.data.value).toBe("first-good");
    expect(toasts).toHaveLength(1);
    expect(toasts[0].kind).toBe("error");
    expect(toasts[0].message).toBe("Refreshing alerts failed");

    // Still failing: no second toast for the same streak.
    await state.run();
    expect(toasts).toHaveLength(1);

    scope.stop();
    toast.clear();
  });

  it("stays silent on a first-load failure and on 401", async () => {
    toast.clear();
    const { toasts } = useToasts();

    // First load has no data to go stale; the view renders an error panel.
    const failFirst = vi.fn(async () => {
      throw new ApiError(500, "nope");
    });
    const scopeA = effectScope();
    const a = scopeA.run(() => useAsync(failFirst, { refreshLabel: "Alerts" }))!;
    await a.run();
    expect(a.error.value?.status).toBe(500);
    expect(toasts).toHaveLength(0);
    scopeA.stop();

    // 401 belongs to the session handler's redirect, not to a toast.
    let n = 0;
    const expire = vi.fn(async () => {
      n += 1;
      if (n === 1) return "good";
      throw new ApiError(401, "session expired");
    });
    const scopeB = effectScope();
    const b = scopeB.run(() => useAsync(expire, { refreshLabel: "Alerts" }))!;
    await b.run();
    await b.run();
    expect(b.error.value?.status).toBe(401);
    expect(toasts).toHaveLength(0);
    scopeB.stop();
    toast.clear();
  });

  it("re-arms the toast after a recovery", async () => {
    toast.clear();
    const { toasts } = useToasts();
    const script = ["ok", "fail", "ok", "fail"];
    let i = 0;
    const loader = vi.fn(async () => {
      const step = script[i++];
      if (step === "fail") throw new ApiError(503, "flap");
      return step;
    });

    const scope = effectScope();
    const state = scope.run(() => useAsync(loader, { refreshLabel: "Stats" }))!;
    await state.run();
    await state.run();
    expect(toasts).toHaveLength(1);

    // Recovered, then failed again: that is a new streak worth reporting.
    await state.run();
    toast.clear();
    await state.run();
    expect(toasts).toHaveLength(1);

    scope.stop();
    toast.clear();
  });
});
