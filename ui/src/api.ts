/*
 * Shared client for the sbproxy admin API.
 *
 * Every call is same-origin (the SPA is served by the admin port,
 * already behind that port's HTTP Basic auth) and uses absolute paths
 * so the requests resolve regardless of the `/admin/ui/` mount prefix.
 * Response shapes are best effort: the server is not available at
 * build time, so callers should read fields defensively.
 */

export class ApiError extends Error {
  status: number;
  body: string;

  constructor(status: number, message: string, body = "") {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.body = body;
  }

  /** A short, human phrase for the common failure modes. */
  get hint(): string {
    switch (this.status) {
      case 401:
        return "Not authorized. The admin credentials were rejected.";
      case 403:
        return "Forbidden. This action is not permitted for the current credentials.";
      case 404:
        return "Not found. This endpoint may be disabled in the running configuration.";
      case 0:
        return "The request could not reach the server.";
      default:
        if (this.status >= 500) {
          return "The server returned an error. Check the sbproxy logs.";
        }
        return this.message || "Request failed.";
    }
  }
}

async function request(
  method: string,
  path: string,
  body?: unknown,
): Promise<Response> {
  const init: RequestInit = {
    method,
    credentials: "same-origin",
    headers: { Accept: "application/json" },
  };
  if (body !== undefined) {
    init.headers = { ...init.headers, "Content-Type": "application/json" };
    init.body = JSON.stringify(body);
  }
  let res: Response;
  try {
    res = await fetch(path, init);
  } catch (e) {
    throw new ApiError(0, `Network error contacting ${path}`, String(e));
  }
  if (!res.ok) {
    let text = "";
    try {
      text = await res.text();
    } catch {
      // ignore
    }
    throw new ApiError(res.status, `${method} ${path} failed (${res.status})`, text);
  }
  return res;
}

async function getJson<T>(path: string): Promise<T> {
  const res = await request("GET", path);
  return (await res.json()) as T;
}

async function getText(path: string): Promise<string> {
  const res = await request("GET", path);
  return await res.text();
}

async function sendJson<T>(
  method: string,
  path: string,
  body?: unknown,
): Promise<T> {
  const res = await request(method, path, body);
  const ct = res.headers.get("content-type") || "";
  if (ct.includes("application/json")) {
    return (await res.json()) as T;
  }
  return (await res.text()) as unknown as T;
}

/* ---- Types (best effort, all fields optional) ---- */

export interface HealthComponent {
  name?: string;
  status?: string;
  detail?: string;
  message?: string;
}

export interface HealthResponse {
  status?: string;
  version?: string;
  uptime_seconds?: number;
  uptime?: string;
  components?: HealthComponent[] | Record<string, unknown>;
  checks?: HealthComponent[] | Record<string, unknown>;
  [k: string]: unknown;
}

export interface StatsResponse {
  [k: string]: unknown;
}

export interface ModelHostStatus {
  status?: string;
  models?: ResidentModel[];
  resident?: ResidentModel[];
  vram_total_bytes?: number;
  vram_used_bytes?: number;
  vram_total?: number;
  vram_used?: number;
  [k: string]: unknown;
}

export interface ResidentModel {
  name?: string;
  id?: string;
  state?: string;
  status?: string;
  vram_bytes?: number;
  vram?: number;
  engine?: string;
  [k: string]: unknown;
}

export interface KeyPolicy {
  allowed_models?: string[];
  blocked_models?: string[];
  allowed_providers?: string[];
  blocked_providers?: string[];
  budget?: unknown;
  budget_usd?: number;
  tags?: string[];
  [k: string]: unknown;
}

export interface AdminKey {
  id?: string;
  name?: string;
  label?: string;
  prefix?: string;
  status?: string;
  state?: string;
  blocked?: boolean;
  revoked?: boolean;
  rotation_pending?: boolean;
  expires_at?: string;
  created_at?: string;
  tags?: string[];
  policy?: KeyPolicy;
  [k: string]: unknown;
}

export interface CreatedKey extends AdminKey {
  token?: string;
  plaintext?: string;
  secret?: string;
  key?: string;
}

export interface Credential {
  id?: string;
  name?: string;
  provider?: string;
  kind?: string;
  status?: string;
  created_at?: string;
  expires_at?: string;
  rotation_pending?: boolean;
  tags?: string[];
  [k: string]: unknown;
}

export interface DriftResponse {
  // Real server shape (GET /admin/drift).
  drift?: boolean;
  config_path?: string;
  loaded_revision?: string;
  loaded_content_hash?: string;
  on_disk_content_hash?: string;
  on_disk_size_bytes?: number;
  checked_at?: string;
  // Tolerated legacy / alternative shapes.
  in_sync?: boolean;
  drifted?: boolean;
  diff?: string;
  on_disk?: unknown;
  loaded?: unknown;
  changes?: unknown[];
  [k: string]: unknown;
}

export interface TargetHealth {
  name?: string;
  target?: string;
  url?: string;
  healthy?: boolean;
  status?: string;
  breaker?: string;
  breaker_state?: string;
  latency_ms?: number;
  [k: string]: unknown;
}

export interface RequestLog {
  id?: string;
  time?: string;
  timestamp?: string;
  ts?: string;
  method?: string;
  path?: string;
  uri?: string;
  status?: number;
  status_code?: number;
  duration_ms?: number;
  latency_ms?: number;
  upstream?: string;
  target?: string;
  client?: string;
  client_ip?: string;
  [k: string]: unknown;
}

export interface PromptEntry {
  host?: string;
  name?: string;
  pinned?: string;
  pinned_version?: string;
  active?: string;
  versions?: (string | { version?: string; created_at?: string })[];
  [k: string]: unknown;
}

/* ---- Endpoint helpers ---- */

/** Pull the first array we can find out of a loosely shaped response. */
export function asList<T>(value: unknown, ...keys: string[]): T[] {
  if (Array.isArray(value)) return value as T[];
  if (value && typeof value === "object") {
    const obj = value as Record<string, unknown>;
    for (const key of keys) {
      if (Array.isArray(obj[key])) return obj[key] as T[];
    }
    // Fall back to the first array-valued property.
    for (const v of Object.values(obj)) {
      if (Array.isArray(v)) return v as T[];
    }
  }
  return [];
}

export interface PlaygroundProvider {
  name: string;
  type?: string | null;
  models: string[];
  default_model?: string | null;
}
export interface PlaygroundEndpoint {
  origin: string;
  providers: PlaygroundProvider[];
}
export interface PlaygroundEndpoints {
  endpoints: PlaygroundEndpoint[];
}
export interface PlaygroundChatRequest {
  origin: string;
  request: Record<string, unknown>;
}
export interface PlaygroundChatResult {
  origin?: string;
  status?: number;
  model?: string;
  response?: Record<string, unknown>;
  usage?: { input_tokens: number; output_tokens: number };
  cost_usd?: number;
  latency_ms?: number;
  error?: string;
}

export const api = {
  // Overview
  health: () => getJson<HealthResponse>("/health"),
  stats: () => getJson<StatsResponse>("/api/stats"),
  modelHostStatus: () => getJson<ModelHostStatus>("/admin/model-host/status"),

  // Keys
  keys: () => getJson<unknown>("/admin/keys"),
  createKey: (body: unknown) => sendJson<CreatedKey>("POST", "/admin/keys", body),
  patchKey: (id: string, body: unknown) =>
    sendJson<AdminKey>("PATCH", `/admin/keys/${encodeURIComponent(id)}`, body),
  keyAction: (id: string, action: "revoke" | "block" | "unblock" | "rotate") =>
    sendJson<unknown>("POST", `/admin/keys/${encodeURIComponent(id)}/${action}`),
  deleteKey: (id: string) =>
    sendJson<unknown>("DELETE", `/admin/keys/${encodeURIComponent(id)}`),

  // Credentials
  credentials: () => getJson<unknown>("/admin/credentials"),
  createCredential: (body: unknown) =>
    sendJson<Credential>("POST", "/admin/credentials", body),
  patchCredential: (id: string, body: unknown) =>
    sendJson<Credential>(
      "PATCH",
      `/admin/credentials/${encodeURIComponent(id)}`,
      body,
    ),
  credentialAction: (
    id: string,
    action: "revoke" | "block" | "unblock" | "rotate",
  ) =>
    sendJson<unknown>(
      "POST",
      `/admin/credentials/${encodeURIComponent(id)}/${action}`,
    ),
  deleteCredential: (id: string) =>
    sendJson<unknown>("DELETE", `/admin/credentials/${encodeURIComponent(id)}`),

  // Config
  openapi: () => getJson<Record<string, unknown>>("/api/openapi.json"),
  drift: () => getJson<DriftResponse>("/admin/drift"),
  reload: () => sendJson<unknown>("POST", "/admin/reload"),
  targets: () => getJson<unknown>("/api/health/targets"),

  // Logs
  requests: () => getJson<unknown>("/api/requests"),

  // Metrics
  metrics: () => getText("/metrics"),

  // Prompts
  prompts: () => getJson<unknown>("/admin/prompts"),
  addPromptVersion: (host: string, name: string, body: unknown) =>
    sendJson<unknown>(
      "POST",
      `/admin/prompts/${encodeURIComponent(host)}/${encodeURIComponent(name)}/versions`,
      body,
    ),
  pinPrompt: (host: string, name: string, body: unknown) =>
    sendJson<unknown>(
      "PUT",
      `/admin/prompts/${encodeURIComponent(host)}/${encodeURIComponent(name)}/pin`,
      body,
    ),

  // Playground
  playgroundEndpoints: () =>
    getJson<PlaygroundEndpoints>("/admin/api/playground/endpoints"),
  playgroundChat: (body: PlaygroundChatRequest) =>
    sendJson<PlaygroundChatResult>("POST", "/admin/api/playground/chat", body),
};
