import { onScopeDispose, ref, shallowRef, type Ref, type ShallowRef } from "vue";
import { ApiError } from "../api";
import { toast } from "./useToasts";

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
  /**
   * Human name for what is being loaded ("Compression sessions"). When set,
   * a background refresh that fails over data already on screen raises an
   * error toast, because the view keeps showing the last good data and
   * would otherwise go stale silently.
   *
   * The first load needs no label: it fails into `error`, and views render
   * that as a full error panel.
   */
  refreshLabel?: string;
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
  // True once a background refresh has failed and not yet recovered, so a
  // loop of failing polls toasts once rather than on every tick.
  let refreshFailing = false;

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
      refreshFailing = false;
      lastLoadedAt.value = new Date();
    } catch (e) {
      if (invocation !== latestInvocation) return;
      const err = e instanceof ApiError ? e : new ApiError(0, String(e));
      error.value = err;
      // A failed refresh leaves stale data on screen with no error panel,
      // so say so once per failure streak. 401 is excluded: the session
      // handler redirects to login, and a toast would race that.
      if (options.refreshLabel && !isFirst && !refreshFailing && err.status !== 401) {
        refreshFailing = true;
        toast.error(err, `Refreshing ${options.refreshLabel.toLowerCase()}`);
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
