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

/** Parse a timestamp (ISO string, epoch seconds, or epoch millis). */
export function toDate(value: unknown): Date | null {
  if (value === undefined || value === null) return null;
  if (typeof value === "number") {
    // Heuristic: values below ~10^12 are seconds.
    return new Date(value < 1e12 ? value * 1000 : value);
  }
  if (typeof value === "string") {
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

/** Truncate a long identifier for display, keeping head and tail. */
export function shortId(id: string | undefined, head = 10, tail = 4): string {
  if (!id) return "";
  if (id.length <= head + tail + 1) return id;
  return `${id.slice(0, head)}…${id.slice(-tail)}`;
}
