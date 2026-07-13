/*
 * Shared client for the sbproxy admin API.
 *
 * Every call is same-origin (the SPA is served by the admin port) and
 * uses absolute paths so the requests resolve regardless of the
 * `/admin/ui/` mount prefix. Response shapes are best effort: the server
 * is not available at build time, so legacy callers read fields
 * defensively. Cluster health and model management use strict contracts
 * that mirror the backend serde types.
 *
 * Auth: the SPA authenticates with a browser session (POST /admin/login)
 * and holds the returned CSRF token in memory (WOR-1758), sent as
 * `X-CSRF-Token` on every mutating request. Basic auth (no token) still
 * works for CI / scripting, where mutations are CSRF-exempt.
 */

// In-memory CSRF token for the current session; null when unauthenticated
// or authenticated via Basic. Set from the login / session responses.
let csrfToken: string | null = null;
export function setCsrfToken(token: string | null): void {
  csrfToken = token;
}

const MUTATING = new Set(["POST", "PUT", "PATCH", "DELETE"]);

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
  // Send the CSRF token on mutations under a browser session. Basic-auth
  // callers hold no token and are CSRF-exempt server-side.
  if (csrfToken && MUTATING.has(method.toUpperCase())) {
    init.headers = { ...init.headers, "X-CSRF-Token": csrfToken };
  }
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

/**
 * Send a raw (non-JSON) request body, e.g. a YAML config document. Keeps
 * the CSRF token on mutations; sets the given content type instead of
 * JSON-encoding the body. Throws ApiError on non-2xx (the caller reads
 * the detail for 400 invalid / 409 revision-mismatch).
 */
async function sendRaw(
  method: string,
  path: string,
  rawBody: string,
  contentType = "application/yaml",
): Promise<string> {
  const init: RequestInit = {
    method,
    credentials: "same-origin",
    headers: { Accept: "application/json", "Content-Type": contentType },
  };
  if (csrfToken && MUTATING.has(method.toUpperCase())) {
    init.headers = { ...init.headers, "X-CSRF-Token": csrfToken };
  }
  init.body = rawBody;
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
  return await res.text();
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

export interface DeviceVram {
  index?: number;
  name?: string;
  total_bytes?: number;
  free_bytes?: number;
}
export interface LocalServing {
  ready?: boolean;
  blockers?: string[];
  recommendation?: string;
}
export interface ModelHostStatus {
  // Real shape: {serving, models, vram, local_serving} or {serving:false, reason}.
  serving?: boolean;
  reason?: string;
  models?: ResidentModel[];
  vram?: {
    budget_bytes?: number;
    used_bytes?: number;
    free_bytes?: number;
    devices?: DeviceVram[];
  };
  // Doctor's admission verdict: why a serve: block would reject here.
  local_serving?: LocalServing;
  // Tolerated loose/legacy fields.
  status?: string;
  resident?: ResidentModel[];
  [k: string]: unknown;
}

export interface ResidentModel {
  name?: string;
  id?: string;
  // EngineState serializes as a string or a small tagged object.
  state?: string | Record<string, unknown>;
  status?: string;
  port?: number;
  vram_bytes?: number;
  keep_alive_secs?: number;
  engine?: string;
  [k: string]: unknown;
}

export interface KeyPolicy {
  allowed_models?: string[];
  blocked_models?: string[];
  allowed_providers?: string[];
  blocked_providers?: string[];
  require_pii_redaction?: string[];
  route_to_model?: string;
  inject_tools?: unknown[];
  principal_selectors?: unknown[];
  bypass_prompt_injection?: boolean;
  budget?: unknown;
  budget_usd?: number;
  max_budget_tokens?: number;
  max_budget_usd?: number;
  max_requests_per_minute?: number;
  max_tokens_per_minute?: number;
  priority?: string;
  inject_mcp?: unknown;
  metadata?: Record<string, string>;
  project?: string;
  user?: string;
  tenant_id?: string;
  tags?: string[];
  [k: string]: unknown;
}

export interface AdminKey {
  id?: string;
  key_id?: string;
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
  allowed_models?: string[];
  blocked_models?: string[];
  allowed_providers?: string[];
  blocked_providers?: string[];
  require_pii_redaction?: string[];
  route_to_model?: string;
  inject_tools?: unknown[];
  principal_selectors?: unknown[];
  bypass_prompt_injection?: boolean;
  max_requests_per_minute?: number;
  max_tokens_per_minute?: number;
  priority?: string;
  inject_mcp?: unknown;
  metadata?: Record<string, string>;
  budget?: unknown;
  project?: string;
  user?: string;
  tenant_id?: string;
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

export interface ConfigDoc {
  revision?: string;
  yaml?: string;
}

export interface AuditRow {
  timestamp?: string;
  action?: string;
  target_kind?: string;
  target_id?: string;
  reason?: string;
}

export interface ClusterMetrics {
  nodes?: number;
  metrics?: Record<string, number>;
}

/* ---- Strict cluster health and model management contracts ---- */

export type ClusterMode = "local" | "distributed";
export type ClusterNodeHealth = "healthy" | "degraded" | "unhealthy";
export type ClusterMembershipState =
  | "alive"
  | "suspect"
  | "dead"
  | "unreachable";
export type NodeRole = "gateway" | "worker" | "authority";
export type NodeReportedHealth = "ready" | "degraded" | "unhealthy";
export type DeploymentRuntimeState =
  | "configured"
  | "assigned"
  | "cached"
  | "preparing"
  | "ready"
  | "draining"
  | "stopped"
  | "failed";
export type RolloutPhase =
  | "stable"
  | "starting"
  | "waiting_for_readiness"
  | "draining_prior"
  | "timed_out";
export type PlacementRejectionReason =
  | "not_worker"
  | "node_unhealthy"
  | "required_labels"
  | "missing_endpoint"
  | "no_capacity"
  | "variant_incompatible"
  | "accelerator_incompatible"
  | "insufficient_memory"
  | "engine_unavailable"
  | "artifact_not_ready";

export interface ClusterSummary {
  total_nodes: number;
  healthy_nodes: number;
  degraded_nodes: number;
  unhealthy_nodes: number;
  eligible_workers: number;
  eligible_replicas: number;
  deployment_digest_mismatch: boolean;
  deployments: number;
  ready_deployments: number;
  rollouts_in_progress: number;
  unplaced_replicas: number;
}

export interface ClusterDeploymentAuthority {
  configured: boolean;
  read_only: boolean;
  verifying_key_id: string | null;
  active_revision: number | null;
  active_content_digest: string | null;
  signer_node_id: string | null;
}

export type EngineKind = "vllm" | "llama_cpp" | "embedded";
export type AcceleratorKind = "cpu" | "metal" | "cuda";

export interface PlacementAssignment {
  node_id: string;
  model_endpoint: string;
  variant_id: string;
  artifact_digest: string;
  engine: EngineKind;
  accelerator: AcceleratorKind;
  device_index: number;
  required_memory_bytes: number;
  available_memory_bytes: number;
  artifact_cached: boolean;
  failure_domains: Record<string, string>;
}

export interface VersionedPlacementAssignment {
  deployment_generation: number;
  assignment: PlacementAssignment;
}

export interface ClusterDeploymentRolloutStatus {
  deployment_id: string;
  model: string;
  generation: number;
  desired_replicas: number;
  placed_replicas: number;
  unplaced_replicas: number;
  phase: RolloutPhase;
  target_ready: boolean;
  timed_out: boolean;
  handoff_deadline_unix_ms: number;
  assignments: PlacementAssignment[];
  retained: VersionedPlacementAssignment[];
  draining: VersionedPlacementAssignment[];
  rejections: Record<string, PlacementRejectionReason>;
}

export interface NodeHealthSnapshot {
  state: NodeReportedHealth;
  reason_codes: string[];
}

export interface NodeReplicaSnapshot {
  deployment: string;
  deployment_generation: number;
  model: string;
  variant: string | null;
  engine: EngineKind | null;
  state: DeploymentRuntimeState;
  endpoint: string | null;
  artifact_digest: string | null;
  selected_devices: number[];
  reserved_memory_bytes: number | null;
  active_requests: number;
  queue_depth: number;
  adapters: string[];
  reason_code: string | null;
}

export interface ClusterNode {
  node_id: string;
  local: boolean;
  membership_state: ClusterMembershipState;
  address: string | null;
  last_ack_age_ms: number;
  incarnation: number;
  health: ClusterNodeHealth;
  unhealthy: boolean;
  unhealthy_reasons: string[];
  roles: NodeRole[];
  labels: Record<string, string>;
  model_endpoint: string | null;
  model_eligible: boolean;
  exclusion_reason: string | null;
  snapshot_age_ms: number | null;
  snapshot_generation: number | null;
  observed_schema_version: number | null;
  normalized_schema_version: number | null;
  reported_health: NodeHealthSnapshot | null;
  engine_count: number;
  device_count: number;
  ready_artifact_count: number;
  replicas: NodeReplicaSnapshot[];
}

export interface ClusterNodeAlert {
  node_id: string;
  health: ClusterNodeHealth;
  reasons: string[];
  membership_state: ClusterMembershipState;
  last_ack_age_ms: number;
  snapshot_age_ms: number | null;
  model_endpoint: string | null;
}

export interface ClusterStatusResponse {
  schema_version: number;
  configured: boolean;
  mode: ClusterMode;
  cluster_id: string;
  local_node_id: string;
  generated_at_unix_ms: number;
  directory_collected_at_unix_ms: number | null;
  directory_age_ms: number | null;
  summary: ClusterSummary;
  deployment_authority: ClusterDeploymentAuthority;
  deployments: ClusterDeploymentRolloutStatus[];
  nodes: ClusterNode[];
  unhealthy_nodes: ClusterNodeAlert[];
}

export type ArtifactFormat = "safetensors" | "gguf" | "pickle";
export type SupportLevel =
  | "stable"
  | "preview"
  | "config_only"
  | "unsupported";

export interface CatalogVariant {
  id: string;
  format: ArtifactFormat;
  quant: string;
  engines: EngineKind[];
  accelerators: AcceleratorKind[];
  min_memory_bytes: number;
  stability: SupportLevel;
}

export interface CatalogEntry {
  params: string;
  license: string;
  family: string;
  context_length: number;
  variants: CatalogVariant[];
}

export interface CatalogResponse {
  schema_version: number;
  catalog_revision: string;
  models: Record<string, CatalogEntry>;
}

export type ModelHostAuthority =
  | "file_managed"
  | "admin_managed"
  | "cluster_authority";
export type PullPolicy = "on_boot" | "on_demand" | "manual";
export type EngineChoice = "auto" | EngineKind;
export type RolloutPolicy = "rolling" | "recreate";

export interface ModelDeployment {
  model: string;
  variant: string | null;
  heterogeneous_variants: boolean;
  replicas: number;
  required_labels: Record<string, string>;
  spread_by: string[];
  pull: PullPolicy;
  warm: boolean;
  keep_alive_secs: number | null;
  max_concurrency: number | null;
  max_queue_depth: number;
  queue_timeout_ms: number;
  engine: EngineChoice;
  rollout: RolloutPolicy;
}

export interface DeploymentDocument {
  schema_version: number;
  authority: ModelHostAuthority;
  read_only: boolean;
  revision: number | null;
  content_digest: string | null;
  deployments: Record<string, ModelDeployment>;
}

export interface DeploymentReplacementRequest {
  expected_revision: number | null;
  deployments: Record<string, ModelDeployment>;
}

export interface ReconcilePlan {
  added: string[];
  changed: string[];
  removed: string[];
  preserved: string[];
}

export interface DeploymentMutationResponse {
  schema_version: number;
  revision: number;
  content_digest: string;
  plan: ReconcilePlan;
}

export interface ModelManagementErrorResponse {
  code: string;
  error: string;
  expected_revision?: number;
  actual_revision?: number;
}

export interface ClusterDeploymentBundleDraft {
  catalog_revision: string;
  revision: number;
  deployments: Record<string, ModelDeployment>;
}

export interface ClusterDeploymentBundle extends ClusterDeploymentBundleDraft {
  schema_version: number;
  content_digest: string;
}

export interface ClusterDeploymentDocument {
  schema_version: number;
  bundle: ClusterDeploymentBundle;
  signer_node_id: string;
  signer_key_id: string;
  read_only: boolean;
}

export interface ClusterDeploymentMutationResponse {
  schema_version: number;
  revision: number;
  content_digest: string;
  signer_node_id: string;
  signer_key_id: string;
  status: "published";
}

export interface WorkspaceStatus {
  workspace?: string;
  tier?: string;
  suspended?: boolean;
  cooldown_secs?: number | null;
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

export interface LogLevelInfo {
  level: string;
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
  debug?: boolean;
}
export interface PlaygroundChatResult {
  origin?: string;
  status?: number;
  model?: string;
  response?: Record<string, unknown>;
  usage?: { input_tokens: number; output_tokens: number };
  cost_usd?: number;
  latency_ms?: number;
  debug?: { request_id?: string; config_revision?: string };
  error?: string;
}
export interface CacheStatus {
  enabled: boolean;
  backend?: string;
  prefix_purge_supported?: boolean;
}
export interface SemanticDecision {
  reason: string;
  score?: number | null;
  threshold: number;
  scope: string;
  at_unix: number;
}
export interface SemanticCacheDebug {
  caches: { origin: string; recent: SemanticDecision[] }[];
}

export interface SessionInfo {
  authenticated: boolean;
  username?: string;
  role?: string;
  via_session?: boolean;
  csrf_token?: string | null;
}
export interface LoginResult {
  role: string;
  username: string;
  csrf_token: string;
}

export const api = {
  // Auth (WOR-1758)
  session: () => getJson<SessionInfo>("/admin/session"),
  login: async (username: string, password: string): Promise<LoginResult> => {
    const r = await sendJson<LoginResult>("POST", "/admin/login", { username, password });
    setCsrfToken(r.csrf_token ?? null);
    return r;
  },
  logout: async (): Promise<void> => {
    try {
      await sendJson("POST", "/admin/logout");
    } finally {
      setCsrfToken(null);
    }
  },

  // Overview
  health: () => getJson<HealthResponse>("/health"),
  stats: () => getJson<StatsResponse>("/api/stats"),
  modelHostStatus: () => getJson<ModelHostStatus>("/admin/model-host/status"),
  modelHostCatalog: () =>
    getJson<CatalogResponse>("/admin/model-host/catalog"),
  modelHostDeployments: () =>
    getJson<DeploymentDocument>("/admin/model-host/deployments"),
  replaceModelHostDeployments: (request: DeploymentReplacementRequest) =>
    sendJson<DeploymentMutationResponse>(
      "PUT",
      "/admin/model-host/deployments",
      request,
    ),
  // Load (spawn/ready) or evict (unload to free VRAM) a model (WOR-1765).
  modelHostLoad: (model: string) =>
    sendJson<unknown>("POST", "/admin/model-host/load", { model }),
  modelHostEvict: (model: string) =>
    sendJson<unknown>("POST", "/admin/model-host/evict", { model }),

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

  // Cache (WOR-1754 / WOR-1755)
  // Runtime log level (WOR-1759)
  logLevel: () => getJson<LogLevelInfo>("/admin/log-level"),
  setLogLevel: (level: string) => sendJson<LogLevelInfo>("PUT", "/admin/log-level", { level }),

  // Live config read + write (WOR-1763). putConfig sends the raw YAML body
  // with optimistic concurrency (if_match=<revision>); ApiError carries
  // the 400 (invalid) / 409 (revision mismatch) detail.
  config: () => getJson<ConfigDoc>("/admin/config"),
  putConfig: (yaml: string, ifMatch?: string) =>
    sendRaw(
      "PUT",
      ifMatch ? `/admin/config?if_match=${encodeURIComponent(ifMatch)}` : "/admin/config",
      yaml,
    ),

  // Rate-limit budget audit trail (WOR-1761) + fleet metrics (WOR-1762).
  auditRecent: (limit = 100) => getJson<AuditRow[]>(`/api/audit/recent?limit=${limit}`),
  clusterStatus: () => getJson<ClusterStatusResponse>("/admin/cluster/status"),
  clusterDeployments: () =>
    getJson<ClusterDeploymentDocument>("/admin/cluster/deployments"),
  publishClusterDeployments: (draft: ClusterDeploymentBundleDraft) =>
    sendJson<ClusterDeploymentMutationResponse>(
      "POST",
      "/admin/cluster/deployments",
      draft,
    ),
  clusterMetrics: () => getJson<ClusterMetrics>("/admin/cluster/metrics"),

  // Rate-limit budget state + manual resume (WOR-1764).
  budgetSnapshot: () => getJson<WorkspaceStatus[]>("/api/rate_limits/budget"),
  resumeWorkspace: (workspace: string) =>
    sendJson<unknown>("POST", "/api/rate_limits/resume", { workspace }),

  cacheStatus: () => getJson<CacheStatus>("/admin/cache"),
  cachePurge: (body: { key?: string; prefix?: string }) =>
    sendJson<unknown>("POST", "/admin/cache/purge", body),
  evictKeyPolicy: (id?: string) =>
    sendJson<unknown>("POST", "/admin/cache/key-policy/evict", id ? { id } : {}),
  semanticCache: () => getJson<SemanticCacheDebug>("/admin/cache/semantic"),
};
