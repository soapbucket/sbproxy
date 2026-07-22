import type { RequestFilters, RequestLog } from "../api";

export type BadgeTone = "ok" | "warn" | "err" | "info" | "neutral";

export interface GatewayBadge {
  kind: "cache" | "retry" | "failover" | "balancer" | "guardrail" | "legacy";
  label: string;
  tone: BadgeTone;
}

export interface SessionSummary {
  sessionId: string;
  parentSessionId?: string;
  requests: RequestLog[];
  requestCount: number;
  tokensIn: number;
  tokensOut: number;
  totalTokens: number;
  costUsdMicros: number;
  wallClockMs: number;
  worstStatus?: number;
  startedAt?: string;
  endedAt?: string;
  orphaned: boolean;
  children: SessionSummary[];
}

export interface SessionForest {
  roots: SessionSummary[];
  orphans: SessionSummary[];
  ungrouped: RequestLog[];
  byId: Map<string, SessionSummary>;
}

function finiteNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

export function statusOf(request: RequestLog): number | undefined {
  const status = finiteNumber(request.status ?? request.status_code);
  return status !== undefined && Number.isInteger(status) && status >= 100 && status < 600
    ? status
    : undefined;
}

export function pathOf(request: RequestLog): string {
  return String(request.path ?? request.uri ?? "");
}

export function timestampOf(request: RequestLog): unknown {
  return request.time ?? request.timestamp ?? request.ts;
}

export function timestampMillis(request: RequestLog): number | undefined {
  const raw = timestampOf(request);
  if (typeof raw !== "string" && typeof raw !== "number" && !(raw instanceof Date)) {
    return undefined;
  }
  const parsed = new Date(raw).getTime();
  return Number.isFinite(parsed) ? parsed : undefined;
}

export function durationOf(request: RequestLog): number | undefined {
  const duration = finiteNumber(request.duration_ms ?? request.latency_ms);
  return duration !== undefined && duration >= 0 ? duration : undefined;
}

/** Pick the most operationally severe valid HTTP status. */
export function worstStatus(requests: readonly RequestLog[]): number | undefined {
  return requests.reduce<number | undefined>((worst, request) => {
    const candidate = statusOf(request);
    if (candidate === undefined) return worst;
    if (worst === undefined) return candidate;
    const candidateClass = Math.floor(candidate / 100);
    const worstClass = Math.floor(worst / 100);
    return candidateClass > worstClass ||
      (candidateClass === worstClass && candidate > worst)
      ? candidate
      : worst;
  }, undefined);
}

function safeCount(value: unknown): number {
  const number = finiteNumber(value);
  return number !== undefined && number > 0 ? number : 0;
}

function sessionSummary(sessionId: string, requests: RequestLog[]): SessionSummary {
  const timed = requests
    .map((request) => {
      const start = timestampMillis(request);
      if (start === undefined) return undefined;
      return {
        start,
        end: start + (durationOf(request) ?? 0),
        raw: String(timestampOf(request)),
      };
    })
    .filter((entry): entry is NonNullable<typeof entry> => entry !== undefined);
  const started = timed.length ? Math.min(...timed.map((entry) => entry.start)) : undefined;
  const ended = timed.length ? Math.max(...timed.map((entry) => entry.end)) : undefined;

  return {
    sessionId,
    requests: sessionCallChain(requests, sessionId),
    requestCount: requests.length,
    tokensIn: requests.reduce((total, request) => total + safeCount(request.tokens_in), 0),
    tokensOut: requests.reduce((total, request) => total + safeCount(request.tokens_out), 0),
    totalTokens: requests.reduce(
      (total, request) =>
        total + safeCount(request.tokens_in) + safeCount(request.tokens_out),
      0,
    ),
    costUsdMicros: requests.reduce(
      (total, request) => total + safeCount(request.cost_usd_micros),
      0,
    ),
    wallClockMs: started !== undefined && ended !== undefined ? ended - started : 0,
    worstStatus: worstStatus(requests),
    ...(started !== undefined
      ? { startedAt: new Date(started).toISOString() }
      : {}),
    ...(ended !== undefined ? { endedAt: new Date(ended).toISOString() } : {}),
    orphaned: false,
    children: [],
  };
}

function sessionOrder(a: SessionSummary, b: SessionSummary): number {
  const aTime = a.startedAt ? Date.parse(a.startedAt) : 0;
  const bTime = b.startedAt ? Date.parse(b.startedAt) : 0;
  return bTime - aTime || a.sessionId.localeCompare(b.sessionId);
}

function breakParentCycles(parentById: Map<string, string | undefined>): void {
  const visited = new Set<string>();
  for (const start of [...parentById.keys()].sort()) {
    if (visited.has(start)) continue;
    const path: string[] = [];
    const pathIndex = new Map<string, number>();
    let current: string | undefined = start;
    while (current !== undefined && parentById.has(current) && !visited.has(current)) {
      const cycleAt = pathIndex.get(current);
      if (cycleAt !== undefined) {
        const cycle = path.slice(cycleAt).sort();
        parentById.set(cycle[0], undefined);
        break;
      }
      pathIndex.set(current, path.length);
      path.push(current);
      current = parentById.get(current);
    }
    path.forEach((id) => visited.add(id));
  }
}

/** Build a bounded, deterministic hierarchy from the current request-ring snapshot. */
export function buildSessionForest(requests: readonly RequestLog[]): SessionForest {
  const grouped = new Map<string, RequestLog[]>();
  const declaredParent = new Map<string, string>();
  const ungrouped: RequestLog[] = [];

  for (const request of requests) {
    const sessionId =
      typeof request.session_id === "string" ? request.session_id.trim() : "";
    if (!sessionId) {
      ungrouped.push(request);
      continue;
    }
    const rows = grouped.get(sessionId) ?? [];
    rows.push(request);
    grouped.set(sessionId, rows);
    const parent =
      typeof request.parent_session_id === "string"
        ? request.parent_session_id.trim()
        : "";
    if (parent && parent !== sessionId && !declaredParent.has(sessionId)) {
      declaredParent.set(sessionId, parent);
    }
  }

  const byId = new Map<string, SessionSummary>();
  for (const [sessionId, rows] of [...grouped.entries()].sort(([a], [b]) =>
    a.localeCompare(b),
  )) {
    byId.set(sessionId, sessionSummary(sessionId, rows));
  }

  const parentById = new Map<string, string | undefined>();
  for (const sessionId of byId.keys()) {
    parentById.set(sessionId, declaredParent.get(sessionId));
  }
  breakParentCycles(parentById);

  const roots: SessionSummary[] = [];
  const orphans: SessionSummary[] = [];
  for (const [sessionId, summary] of byId) {
    const parentId = parentById.get(sessionId);
    if (!parentId) {
      roots.push(summary);
      continue;
    }
    summary.parentSessionId = parentId;
    const parent = byId.get(parentId);
    if (parent) {
      parent.children.push(summary);
    } else {
      summary.orphaned = true;
      orphans.push(summary);
    }
  }

  for (const summary of byId.values()) summary.children.sort(sessionOrder);
  roots.sort(sessionOrder);
  orphans.sort(sessionOrder);

  return { roots, orphans, ungrouped: [...ungrouped], byId };
}

/** Requests belonging to one session in chronological order. */
export function sessionCallChain(
  requests: readonly RequestLog[],
  sessionId: string,
): RequestLog[] {
  return requests
    .map((request, index) => ({ request, index }))
    .filter(({ request }) => request.session_id === sessionId)
    .sort((a, b) => {
      const aTime = timestampMillis(a.request);
      const bTime = timestampMillis(b.request);
      if (aTime === undefined && bTime === undefined) return a.index - b.index;
      if (aTime === undefined) return 1;
      if (bTime === undefined) return -1;
      return aTime - bTime || a.index - b.index;
    })
    .map(({ request }) => request);
}

export function discoverPropertyKeys(requests: readonly RequestLog[]): string[] {
  const keys = new Set<string>();
  for (const request of requests) {
    if (!request.properties || typeof request.properties !== "object") continue;
    Object.keys(request.properties).forEach((key) => keys.add(key));
  }
  return [...keys].sort();
}

export function matchesProperty(
  request: RequestLog,
  key: string,
  value?: string,
): boolean {
  if (!key || !request.properties || typeof request.properties !== "object") {
    return false;
  }
  if (!Object.prototype.hasOwnProperty.call(request.properties, key)) return false;
  return value === undefined || value === "" || request.properties[key] === value;
}

export function requestMatchesFilters(
  request: RequestLog,
  filters: RequestFilters,
): boolean {
  if (
    filters.method &&
    String(request.method ?? "").toUpperCase() !== filters.method.toUpperCase()
  ) {
    return false;
  }
  if (filters.origin && request.origin !== filters.origin) return false;
  if (filters.path && !pathOf(request).toLowerCase().includes(filters.path.toLowerCase())) {
    return false;
  }
  if (filters.status) {
    const status = statusOf(request);
    if (status === undefined) return false;
    const query = filters.status.trim();
    if (/^[1-5]xx$/i.test(query)) {
      if (String(status)[0] !== query[0]) return false;
    } else if (!String(status).startsWith(query)) {
      return false;
    }
  }
  if (filters.guardrailAction && request.guardrail_action !== filters.guardrailAction) {
    return false;
  }
  if (
    filters.guardrailCategory &&
    request.guardrail_category !== filters.guardrailCategory
  ) {
    return false;
  }
  if (filters.cacheStatus && request.cache_status !== filters.cacheStatus) return false;
  if (
    filters.retried !== undefined &&
    ((finiteNumber(request.retry_count) ?? 0) > 0) !== filters.retried
  ) {
    return false;
  }
  if (
    filters.propertyKey &&
    !matchesProperty(request, filters.propertyKey, filters.propertyValue)
  ) {
    return false;
  }
  return true;
}

function words(value: string): string {
  return value.replaceAll("_", " ");
}

export function gatewayBadges(request: RequestLog): GatewayBadge[] {
  const hasGatewayData = [
    "cache_status",
    "retry_count",
    "failover_engaged",
    "failover_from",
    "failover_to",
    "load_balancer_strategy",
    "load_balancer_target",
  ].some((key) => Object.prototype.hasOwnProperty.call(request, key));
  const badges: GatewayBadge[] = [];

  if (request.cache_status) {
    const status = request.cache_status;
    const labels: Record<string, string> = {
      disabled: "cache off",
      miss: "cache miss",
      hit: "cache hit",
      semantic_hit: "semantic hit",
    };
    badges.push({
      kind: "cache",
      label: labels[status] ?? `cache ${words(status)}`,
      tone: status === "hit" || status === "semantic_hit" ? "ok" : "neutral",
    });
  }

  const retries = finiteNumber(request.retry_count) ?? 0;
  if (retries > 0) {
    badges.push({ kind: "retry", label: `retry ×${retries}`, tone: "warn" });
  }
  if (request.failover_engaged || request.failover_from || request.failover_to) {
    const label =
      request.failover_from && request.failover_to
        ? `${request.failover_from} → ${request.failover_to}`
        : `failover${request.failover_to ? ` → ${request.failover_to}` : ""}`;
    badges.push({ kind: "failover", label, tone: "warn" });
  }
  if (request.load_balancer_strategy || request.load_balancer_target) {
    const strategy = request.load_balancer_strategy
      ? words(request.load_balancer_strategy)
      : "selected";
    badges.push({
      kind: "balancer",
      label: `${strategy}${request.load_balancer_target ? `: ${request.load_balancer_target}` : ""}`,
      tone: "info",
    });
  }
  if (request.guardrail_action) {
    const action = request.guardrail_action === "block" ? "blocked" : words(request.guardrail_action);
    badges.push({
      kind: "guardrail",
      label: `${action}${request.guardrail_category ? `: ${request.guardrail_category}` : ""}`,
      tone: request.guardrail_action === "block" ? "warn" : "info",
    });
  }

  if (!hasGatewayData && badges.length === 0) {
    return [
      { kind: "legacy", label: "gateway data unavailable", tone: "neutral" },
    ];
  }
  return badges;
}
