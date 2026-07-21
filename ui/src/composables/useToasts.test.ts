import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { toast, useToasts } from "./useToasts";
import { ApiError } from "../api";

describe("useToasts", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    toast.clear();
  });
  afterEach(() => {
    toast.clear();
    vi.useRealTimers();
  });

  it("queues and auto-dismisses a success toast", () => {
    const { toasts } = useToasts();
    toast.success("Key created");
    expect(toasts.length).toBe(1);
    expect(toasts[0].kind).toBe("success");
    vi.advanceTimersByTime(5000);
    expect(toasts.length).toBe(0);
  });

  it("renders an ApiError's hint and includes the action context", () => {
    const { toasts } = useToasts();
    toast.error(new ApiError(403, "POST /admin/keys failed (403)"), "Create key");
    expect(toasts[0].kind).toBe("error");
    expect(toasts[0].message).toBe("Create key failed");
    expect(toasts[0].detail).toContain("Forbidden");
  });

  it("collapses duplicate messages instead of stacking them", () => {
    const { toasts } = useToasts();
    toast.error(new ApiError(0, "net down"), "Metrics scrape");
    toast.error(new ApiError(0, "net down"), "Metrics scrape");
    expect(toasts.length).toBe(1);
  });

  it("caps the visible stack", () => {
    const { toasts } = useToasts();
    for (let i = 0; i < 8; i++) toast.info(`note ${i}`);
    expect(toasts.length).toBe(5);
    expect(toasts[0].message).toBe("note 3");
  });

  it("dismisses by id", () => {
    const { toasts } = useToasts();
    const id = toast.info("hello");
    expect(toasts.length).toBe(1);
    toast.dismiss(id);
    expect(toasts.length).toBe(0);
  });
});
