import { reactive, readonly } from "vue";
import { ApiError } from "../api";

export type ToastKind = "success" | "error" | "warn" | "info";

export interface Toast {
  id: number;
  kind: ToastKind;
  /** The one-line headline, e.g. "Key created". */
  message: string;
  /** Optional second line with the server's detail. */
  detail?: string;
  /** Milliseconds before auto-dismiss; 0 keeps it until dismissed. */
  timeout: number;
}

/**
 * Module-level toast queue shared by every view. Success and info
 * toasts dismiss themselves; error toasts stay longer so the detail
 * can be read, and every toast is click-dismissable in the host.
 */
const state = reactive<{ toasts: Toast[] }>({ toasts: [] });

let nextId = 1;
const timers = new Map<number, ReturnType<typeof setTimeout>>();

const DEFAULT_TIMEOUT: Record<ToastKind, number> = {
  success: 4000,
  info: 5000,
  warn: 7000,
  error: 9000,
};

const MAX_VISIBLE = 5;

function push(kind: ToastKind, message: string, detail?: string): number {
  // Collapse an identical, still-visible toast instead of stacking
  // duplicates (a failing poll loop would otherwise fill the screen).
  const dup = state.toasts.find(
    (t) => t.kind === kind && t.message === message && t.detail === detail,
  );
  if (dup) {
    restartTimer(dup);
    return dup.id;
  }

  const toast: Toast = {
    id: nextId++,
    kind,
    message,
    detail,
    timeout: DEFAULT_TIMEOUT[kind],
  };
  state.toasts.push(toast);
  while (state.toasts.length > MAX_VISIBLE) {
    dismiss(state.toasts[0].id);
  }
  restartTimer(toast);
  return toast.id;
}

function restartTimer(toast: Toast): void {
  const existing = timers.get(toast.id);
  if (existing) clearTimeout(existing);
  if (toast.timeout > 0) {
    timers.set(
      toast.id,
      setTimeout(() => dismiss(toast.id), toast.timeout),
    );
  }
}

function dismiss(id: number): void {
  const timer = timers.get(id);
  if (timer) {
    clearTimeout(timer);
    timers.delete(id);
  }
  const at = state.toasts.findIndex((t) => t.id === id);
  if (at !== -1) state.toasts.splice(at, 1);
}

function clear(): void {
  for (const t of [...state.toasts]) dismiss(t.id);
}

/** Reduce an unknown thrown value to a message + optional detail. */
function describeError(e: unknown): { message: string; detail?: string } {
  if (e instanceof ApiError) {
    const detail = e.body ? e.body.slice(0, 300) : undefined;
    return { message: e.hint, detail };
  }
  return { message: e instanceof Error ? e.message : String(e) };
}

export const toast = {
  success: (message: string, detail?: string) =>
    push("success", message, detail),
  info: (message: string, detail?: string) => push("info", message, detail),
  warn: (message: string, detail?: string) => push("warn", message, detail),
  /**
   * Show an error toast. Pass the action as `context` ("Create key")
   * so the toast reads "Create key failed" with the server's hint
   * underneath.
   */
  error: (e: unknown, context?: string) => {
    const { message, detail } = describeError(e);
    if (context) {
      return push("error", `${context} failed`, detail ? `${message} ${detail}` : message);
    }
    return push("error", message, detail);
  },
  dismiss,
  clear,
};

export function useToasts() {
  return { toasts: readonly(state).toasts, dismiss, clear };
}
