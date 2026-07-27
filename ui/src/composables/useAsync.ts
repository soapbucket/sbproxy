import { onScopeDispose, ref, shallowRef, type Ref, type ShallowRef } from "vue";
import { ApiError } from "../api";

export interface AsyncState<T> {
  data: ShallowRef<T | null>;
  error: Ref<ApiError | null>;
  loading: Ref<boolean>;
  succeeded: Ref<boolean>;
  run: () => Promise<void>;
  /** True while a background refresh is in flight, so a view can show a
   *  subtle indicator without blanking the panel it already has. */
  refreshing: Ref<boolean>;
  /** Wall-clock time of the last successful load, for a "as of" label. */
  lastLoadedAt: Ref<Date | null>;
}

export interface UseAsyncOptions {
  /**
   * Refresh every N milliseconds. Omit for a one-shot load.
   *
   * Polling pauses while the document is hidden and resumes with an
   * immediate refresh, so a console left open on another tab neither burns
   * requests nor shows a stale panel when the operator returns.
   */
  pollMs?: number;
}

/**
 * Wrap an async loader with loading and error state. `run` never
 * throws; failures land in `error` as an ApiError so views can render
 * a clear error surface instead of a blank panel.
 *
 * With `pollMs`, the loader re-runs on an interval. A refresh that fails
 * leaves the last good data in place and surfaces the error, because a
 * transient blip should not empty a dashboard the operator is watching.
 */
export function useAsync<T>(
  loader: () => Promise<T>,
  options: UseAsyncOptions = {},
): AsyncState<T> {
  const data = shallowRef<T | null>(null);
  const error = ref<ApiError | null>(null);
  const loading = ref<boolean>(false);
  const refreshing = ref<boolean>(false);
  const succeeded = ref<boolean>(false);
  const lastLoadedAt = ref<Date | null>(null);
  let latestInvocation = 0;
  let inFlight = false;

  async function run() {
    inFlight = true;
    const invocation = ++latestInvocation;
    // Only the first load blanks the panel; later refreshes keep the
    // existing data on screen so the view does not flicker every tick.
    const isFirst = data.value === null;
    if (isFirst) {
      loading.value = true;
    } else {
      refreshing.value = true;
    }
    error.value = null;
    succeeded.value = false;
    try {
      const loaded = await loader();
      if (invocation !== latestInvocation) return;
      data.value = loaded;
      succeeded.value = true;
      lastLoadedAt.value = new Date();
    } catch (e) {
      if (invocation !== latestInvocation) return;
      if (e instanceof ApiError) {
        error.value = e;
      } else {
        error.value = new ApiError(0, String(e));
      }
    } finally {
      if (invocation === latestInvocation) {
        loading.value = false;
        refreshing.value = false;
      }
      inFlight = false;
    }
  }

  const pollMs = options.pollMs;
  if (pollMs && pollMs > 0) {
    let timer: ReturnType<typeof setInterval> | null = null;

    // Skip a tick while a load is still in flight rather than guarding
    // `run` itself: callers may legitimately fire overlapping requests, and
    // `latestInvocation` already resolves those so the newest wins. The
    // guard belongs to the timer, whose only job is to not stack polls.
    const tick = () => {
      if (!inFlight) void run();
    };

    const start = () => {
      if (timer === null) timer = setInterval(tick, pollMs);
    };
    const stop = () => {
      if (timer !== null) {
        clearInterval(timer);
        timer = null;
      }
    };
    const onVisibility = () => {
      if (document.hidden) {
        stop();
      } else {
        // Catch up immediately: whatever is on screen is at least one
        // interval stale by now.
        tick();
        start();
      }
    };

    if (typeof document !== "undefined") {
      document.addEventListener("visibilitychange", onVisibility);
      if (!document.hidden) start();
    } else {
      start();
    }

    onScopeDispose(() => {
      stop();
      if (typeof document !== "undefined") {
        document.removeEventListener("visibilitychange", onVisibility);
      }
    });
  }

  return { data, error, loading, succeeded, run, refreshing, lastLoadedAt };
}
