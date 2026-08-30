import { describe, expect, it } from "vitest";
import modalDialog from "./ModalDialog.vue?raw";

describe("ModalDialog dismiss contract", () => {
  // WOR-2704: @click.self alone closes when a text-selection drag's common
  // ancestor is the scrim. Dismiss must require mousedown on the scrim too.
  it("only dismisses when both press and release happen on the scrim", () => {
    expect(modalDialog).toContain('class="scrim"');
    expect(modalDialog).toContain("onScrimMouseDown");
    expect(modalDialog).toContain("onScrimClick");
    expect(modalDialog).toMatch(/@mousedown(?:=|"|')/);
    expect(modalDialog).not.toMatch(
      /class="scrim"\s+@click\.self="\$emit\('close'\)"/,
    );
  });
});
