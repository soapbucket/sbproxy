import { describe, expect, it } from "vitest";
import { focusTargetForTab } from "./dialog-focus";

describe("dialog focus containment", () => {
  it("wraps at boundaries and recovers when active focus leaves the current focusable set", () => {
    const first = { id: "first" };
    const middle = { id: "middle" };
    const last = { id: "last" };
    const removedOrOutside = { id: "removed" };
    const focusable = [first, middle, last];

    expect(focusTargetForTab(focusable, last, false)).toBe(first);
    expect(focusTargetForTab(focusable, first, true)).toBe(last);
    expect(focusTargetForTab(focusable, removedOrOutside, false)).toBe(first);
    expect(focusTargetForTab(focusable, removedOrOutside, true)).toBe(last);
    expect(focusTargetForTab(focusable, null, false)).toBe(first);
    expect(focusTargetForTab(focusable, null, true)).toBe(last);
    expect(focusTargetForTab(focusable, middle, false)).toBeNull();
    expect(focusTargetForTab([], null, false)).toBeNull();
  });
});
