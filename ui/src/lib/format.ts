/** Small formatting helpers. All tolerate undefined or malformed input. */

export function formatBytes(n: number | undefined | null): string {
  if (n === undefined || n === null || !isFinite(n)) return "n/a";
  if (n <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v.toFixed(v >= 100 || i === 0 ? 0 : 1)} ${units[i]}`;
}

export function formatDuration(seconds: number | undefined | null): string {
  if (seconds === undefined || seconds === null || !isFinite(seconds)) {
    return "n/a";
  }
  const s = Math.floor(seconds);
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  const rem = s % 60;
  const parts: string[] = [];
  if (d) parts.push(`${d}d`);
  if (h) parts.push(`${h}h`);
  if (m) parts.push(`${m}m`);
  if (!d && !h) parts.push(`${rem}s`);
  return parts.join(" ") || "0s";
}

/** Format a millisecond latency at a sensible precision (us below 1ms). */
export function formatMs(ms: number | undefined | null): string {
  if (ms === undefined || ms === null || !isFinite(ms)) return "n/a";
  if (ms < 1) return `${(ms * 1000).toFixed(0)} µs`;
  if (ms < 10) return `${ms.toFixed(2)} ms`;
  if (ms < 100) return `${ms.toFixed(1)} ms`;
  return `${ms.toFixed(0)} ms`;
}

export function formatNumber(n: number | undefined | null): string {
  if (n === undefined || n === null || !isFinite(n)) return "n/a";
  return n.toLocaleString(undefined, { maximumFractionDigits: 2 });
}

export function formatUsd(n: number | undefined | null): string {
  if (n === undefined || n === null || !isFinite(n)) return "n/a";
  return `$${n.toLocaleString(undefined, {
    minimumFractionDigits: 2,
    maximumFractionDigits: 4,
  })}`;
}

/**
 * Parse a timestamp (ISO string, epoch seconds, or epoch millis).
 *
 * Idempotent: passing an already-parsed `Date` gives it back. WOR-2348 —
 * without that branch a `Date` fell through to `return null`, because its
 * `typeof` is `"object"`. Every caller that wrapped defensively, or that
 * passed the output of one `toDate` into a helper that calls `toDate`
 * again, silently got `null` and rendered "n/a". A function named
 * `toDate` returning null for a Date is the trap; this closes it at the
 * source rather than only at the call sites that tripped over it.
 */
export function toDate(value: unknown): Date | null {
  if (value === undefined || value === null) return null;
  if (value instanceof Date) {
    return Number.isNaN(value.getTime()) ? null : value;
  }
  if (typeof value === "number") {
    // Heuristic: values below ~10^12 are seconds.
    return new Date(value < 1e12 ? value * 1000 : value);
  }
  if (typeof value === "string") {
    // Numeric-looking strings (epoch seconds or millis, as a string)
    // take this branch. An RFC 3339 string like config history's
    // `applied_at` does not: `Number("2026-08-16T10:15:32.456Z")` is
    // NaN, so it falls through to `new Date(value)` below instead,
    // which parses ISO 8601 natively. Both shapes end up correct; this
    // branch exists for callers that still hand toDate a bare epoch
    // number as a string.
    const asNum = Number(value);
    if (!Number.isNaN(asNum) && value.trim() !== "") {
      return new Date(asNum < 1e12 ? asNum * 1000 : asNum);
    }
    const d = new Date(value);
    return Number.isNaN(d.getTime()) ? null : d;
  }
  return null;
}

export function formatTime(value: unknown): string {
  const d = toDate(value);
  if (!d) return typeof value === "string" ? value : "n/a";
  return d.toLocaleString();
}

export function relativeTime(value: unknown): string {
  const d = toDate(value);
  if (!d) return "";
  const diff = Date.now() - d.getTime();
  const abs = Math.abs(diff);
  const suffix = diff >= 0 ? "ago" : "from now";
  const mins = Math.round(abs / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ${suffix}`;
  const hrs = Math.round(mins / 60);
  if (hrs < 24) return `${hrs}h ${suffix}`;
  const days = Math.round(hrs / 24);
  return `${days}d ${suffix}`;
}

/**
 * A 0..1 fraction as a percentage, never rounding a real value away.
 *
 * Rounding is the quiet failure mode of a share. A fallback price share
 * of 0.4% printed as "0%" tells the reader that no price was invented,
 * and a coverage of 99.6% printed as "100%" tells them nothing is
 * missing. Both are the opposite of what the number says, on the two
 * panels whose whole job is to say how far to trust the bill. A nonzero
 * share that rounds to zero reads "<1%", and a share below one that
 * rounds to a hundred reads ">99%".
 *
 * `digits` is the precision used in the ordinary case; the guards apply
 * at whatever precision that is.
 */
export function formatShare(
  fraction: number | undefined | null,
  digits = 0,
): string {
  if (fraction === undefined || fraction === null || !isFinite(fraction)) {
    return "n/a";
  }
  const pct = fraction * 100;
  const step = Math.pow(10, -digits);
  const floorLabel = digits > 0 ? `<${step.toFixed(digits)}%` : "<1%";
  const ceilLabel = digits > 0 ? `>${(100 - step).toFixed(digits)}%` : ">99%";
  if (pct > 0 && Number(pct.toFixed(digits)) === 0) return floorLabel;
  if (pct < 0 && Number(pct.toFixed(digits)) === 0) return `-${floorLabel}`;
  if (pct < 100 && Number(pct.toFixed(digits)) === 100) return ceilLabel;
  return `${pct.toFixed(digits)}%`;
}

/** Truncate a long identifier for display, keeping head and tail. */
export function shortId(id: string | undefined, head = 10, tail = 4): string {
  if (!id) return "";
  if (id.length <= head + tail + 1) return id;
  return `${id.slice(0, head)}…${id.slice(-tail)}`;
}
