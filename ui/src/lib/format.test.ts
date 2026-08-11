import { describe, expect, it } from "vitest";
import { formatTime, toDate } from "./format";

describe("toDate", () => {
  it("parses the forms the admin API actually sends", () => {
    expect(toDate("2026-08-11T20:27:18Z")?.toISOString()).toBe(
      "2026-08-11T20:27:18.000Z",
    );
    // Epoch seconds, which is what the semantic-cache decisions carry.
    expect(toDate(1_754_945_238)?.toISOString()).toBe("2025-08-11T20:47:18.000Z");
    // Epoch millis.
    expect(toDate(1_754_945_238_000)?.toISOString()).toBe(
      "2025-08-11T20:47:18.000Z",
    );
  });

  it("is idempotent, so a Date round-trips instead of becoming null", () => {
    // WOR-2348. `toDate` handled number and string and fell through to
    // `return null` for everything else, and a Date's typeof is "object".
    // Any caller that wrapped defensively got null.
    const date = new Date("2026-08-11T20:27:18Z");
    expect(toDate(date)).toBe(date);
    expect(toDate(toDate(date))).toBe(date);
  });

  it("rejects an invalid Date rather than passing it through", () => {
    expect(toDate(new Date("nonsense"))).toBeNull();
  });

  it("returns null for absent values", () => {
    expect(toDate(null)).toBeNull();
    expect(toDate(undefined)).toBeNull();
  });
});

describe("formatTime", () => {
  it("survives a caller that already parsed the value", () => {
    // The exact shape the Audit page used: formatTime(toDate(x)). It
    // rendered "n/a" for every row, on both tables, because formatTime
    // calls toDate again internally.
    const raw = "2026-08-11T20:27:18Z";
    expect(formatTime(toDate(raw))).toBe(formatTime(raw));
    expect(formatTime(toDate(raw))).not.toBe("n/a");
  });
});
