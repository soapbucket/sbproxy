import { onScopeDispose } from "vue";

/**
 * Re-run `fn` on an interval for as long as the calling scope lives.
 *
 * Polling pauses while the document is hidden and resumes with an immediate
 * call, so a console left open on a background tab neither burns requests nor
 * shows a stale panel when the operator switches back to it.
 *
 * `useAsync` carries its own copy of this behavior for the views that load
 * through it. This exists for the views that hand-roll their loading and
 * would otherwise each reinvent the visibility handling.
 */
export function usePoll(fn: () => void, intervalMs: number): void {
  if (!(intervalMs > 0)) return;

  let timer: ReturnType<typeof setInterval> | null = null;

  const start = () => {
    if (timer === null) timer = setInterval(fn, intervalMs);
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
      // Whatever is on screen is at least one interval stale by now.
      fn();
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
