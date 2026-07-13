import { describe, expect, it } from "vitest";

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
