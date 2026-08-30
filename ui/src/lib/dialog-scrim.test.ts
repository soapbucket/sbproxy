import { describe, expect, it, vi } from "vitest";
import { createScrimDismiss } from "./dialog-scrim";

function event(target: object, currentTarget: object): MouseEvent {
  return { target, currentTarget } as MouseEvent;
}

describe("createScrimDismiss", () => {
  it("closes when press and release both happen on the scrim", () => {
    const onClose = vi.fn();
    const { onScrimMouseDown, onScrimClick } = createScrimDismiss(onClose);
    const scrim = {};
    onScrimMouseDown(event(scrim, scrim));
    onScrimClick(event(scrim, scrim));
    expect(onClose).toHaveBeenCalledOnce();
  });

  it("does not close when the press started inside the dialog", () => {
    const onClose = vi.fn();
    const { onScrimMouseDown, onScrimClick } = createScrimDismiss(onClose);
    const scrim = {};
    const dialog = {};
    onScrimMouseDown(event(dialog, scrim));
    onScrimClick(event(scrim, scrim));
    expect(onClose).not.toHaveBeenCalled();
  });
});
