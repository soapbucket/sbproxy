import { effectScope } from "vue";
import { describe, expect, it, vi } from "vitest";

import { ApiError } from "../api";
import { useAsync } from "./useAsync";

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
