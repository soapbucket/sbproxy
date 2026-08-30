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
 *
 * Every call also carries `X-Requested-With: XMLHttpRequest` (WOR-2688).
 * The admin server reads it on a 401 and answers without the
 * `WWW-Authenticate: Basic` challenge, so a session that lapses mid-use
 * drops the operator on this app's sign-in page instead of the browser's
 * own credential dialog, whose Cancel button leaves the console wedged
 * until a hard reload. It marks the caller and nothing else: the server
 * resolves credentials the same way with or without it, so a request
 * carrying the header and no session is refused exactly as before.
 */

/**
 * Marks a request as this app's own, so the server suppresses the Basic
 * challenge on a 401 (WOR-2688). Sent on every call, safe and unmutating.
 */
const CLIENT_MARKER_HEADERS = { "X-Requested-With": "XMLHttpRequest" } as const;

// In-memory CSRF token for the current session; null when unauthenticated
// Called when the server rejects a request as unauthenticated, so the app
// can drop to the sign-in screen instead of leaving the operator on a shell
// where every panel quietly errors. Registered by `useAuth`; a callback
// rather than a direct import because `useAuth` already imports this module.
let onUnauthorized: (() => void) | null = null;

/** Register the handler invoked when a request comes back 401. */
export function setUnauthorizedHandler(handler: (() => void) | null): void {
  onUnauthorized = handler;
}

let onWarning: ((msg: string) => void) | null = null;
export function setWarningHandler(handler: ((msg: string) => void) | null): void {
  onWarning = handler;
}

/**
 * Paths that legitimately answer 401 without meaning "your session died":
 * the login attempt itself, and the session probe used to discover that
 * there is no session yet. Firing the handler for these would fight the
 * sign-in flow.
 */
function isAuthProbePath(path: string): boolean {
  return path.startsWith("/admin/login") || path.startsWith("/admin/session");
}

// or authenticated via Basic. Set from the login / session responses.
let csrfToken: string | null = null;
export function setCsrfToken(token: string | null): void {
  csrfToken = token;
}

const MUTATING = new Set(["POST", "PUT", "PATCH", "DELETE"]);
const MAX_SAFE_JSON_INTEGER = BigInt(Number.MAX_SAFE_INTEGER);

export class UnsafeJsonIntegerError extends RangeError {
  constructor(value: string | number) {
    super(
      `JSON integer ${String(value)} is outside JavaScript's safe integer range`,
    );
    this.name = "UnsafeJsonIntegerError";
  }
}

function assertSafeIntegerValue(value: unknown): void {
  if (
    typeof value === "number" &&
    Number.isInteger(value) &&
    !Number.isSafeInteger(value)
  ) {
    throw new UnsafeJsonIntegerError(value);
  }
}

function stringifyJsonSafely(value: unknown): string | undefined {
  return JSON.stringify(value, (_key, candidate: unknown) => {
    assertSafeIntegerValue(candidate);
    return candidate;
  });
}

function isDigit(character: string | undefined): boolean {
  return character !== undefined && character >= "0" && character <= "9";
}

function jsonNumberEnd(raw: string, start: number): number | null {
  let cursor = start;
  if (raw[cursor] === "-") cursor += 1;

  if (raw[cursor] === "0") {
    cursor += 1;
  } else {
    if (!isDigit(raw[cursor])) return null;
    while (isDigit(raw[cursor])) cursor += 1;
  }

  if (raw[cursor] === ".") {
    cursor += 1;
    if (!isDigit(raw[cursor])) return null;
    while (isDigit(raw[cursor])) cursor += 1;
  }

  if (raw[cursor] === "e" || raw[cursor] === "E") {
    cursor += 1;
    if (raw[cursor] === "+" || raw[cursor] === "-") cursor += 1;
    if (!isDigit(raw[cursor])) return null;
    while (isDigit(raw[cursor])) cursor += 1;
  }

  return cursor;
}

function assertSafeJsonNumberToken(token: string): void {
  if (!token.includes(".") && !token.includes("e") && !token.includes("E")) {
    const magnitude = BigInt(token.startsWith("-") ? token.slice(1) : token);
    if (magnitude > MAX_SAFE_JSON_INTEGER) {
      throw new UnsafeJsonIntegerError(token);
    }
    return;
  }

  const value = Number(token);
  if (
    !Number.isFinite(value) ||
    (Number.isInteger(value) && !Number.isSafeInteger(value))
  ) {
    throw new UnsafeJsonIntegerError(token);
  }
}

function assertSafeJsonIntegers(raw: string): void {
  let cursor = 0;
  while (cursor < raw.length) {
    if (raw[cursor] === '"') {
      cursor += 1;
      while (cursor < raw.length) {
        if (raw[cursor] === "\\") {
          cursor += 2;
        } else if (raw[cursor] === '"') {
          cursor += 1;
          break;
        } else {
          cursor += 1;
        }
      }
      continue;
    }

    if (raw[cursor] === "-" || isDigit(raw[cursor])) {
      const end = jsonNumberEnd(raw, cursor);
      if (end !== null) {
        assertSafeJsonNumberToken(raw.slice(cursor, end));
        cursor = end;
        continue;
      }
    }
    cursor += 1;
  }
}

async function parseJsonResponse<T>(response: Response): Promise<T> {
  const raw = await response.text();
  assertSafeJsonIntegers(raw);
  return JSON.parse(raw) as T;
}

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
    headers: { Accept: "application/json", ...CLIENT_MARKER_HEADERS },
  };
  // Send the CSRF token on mutations under a browser session. Basic-auth
  // callers hold no token and are CSRF-exempt server-side.
  if (csrfToken && MUTATING.has(method.toUpperCase())) {
    init.headers = { ...init.headers, "X-CSRF-Token": csrfToken };
  }
  if (body !== undefined) {
    init.headers = { ...init.headers, "Content-Type": "application/json" };
    init.body = stringifyJsonSafely(body);
  }
  let res: Response;
  try {
    res = await fetch(path, init);
  } catch (e) {
    throw new ApiError(0, `Network error contacting ${path}`, String(e));
  }
  const warning = res.headers?.get("Warning") || res.headers?.get("X-Warning") || res.headers?.get("X-SB-Warning");
  if (warning) {
    onWarning?.(warning);
  }
  if (!res.ok) {
    let text = "";
    try {
      text = await res.text();
    } catch {
      // ignore
    }
    if (res.status === 401 && !isAuthProbePath(path)) {
      // The session lapsed mid-use. Tell the app so it can send the
      // operator to sign in, rather than leaving them on a console where
      // every panel reports "Not authorized" with no way forward.
      onUnauthorized?.();
    }
    throw new ApiError(res.status, `${method} ${path} failed (${res.status})`, text);
  }
  return res;
}

async function getJson<T>(path: string): Promise<T> {
  const res = await request("GET", path);
  return await parseJsonResponse<T>(res);
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
    return await parseJsonResponse<T>(res);
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
    headers: {
      Accept: "application/json",
      "Content-Type": contentType,
      ...CLIENT_MARKER_HEADERS,
    },
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
    if (res.status === 401 && !isAuthProbePath(path)) {
      // The session lapsed mid-use. Tell the app so it can send the
      // operator to sign in, rather than leaving them on a console where
      // every panel reports "Not authorized" with no way forward.
      onUnauthorized?.();
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


/** One externalized compression record, content-free. */
export interface CompressionRecord {
  id: string;
  backend: string;
  consistency: string;
  tenant_id: string;
  origin: string;
  logical_version: number;
  protected_prefix_count: number;
  covered_history_count: number;
  covered_input_tokens: number;
  summary_tokens: number;
  summarizer_provider: string;
  summarizer_model: string;
  writer_node: string;
  conflict_detected: boolean;
  created_at_unix_ms: number;
  updated_at_unix_ms: number;
  expires_at_unix_ms: number;
  kind: string;
}

export interface CompressionSessionPage {
  records: CompressionRecord[];
  next_cursor?: string | null;
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

export type ExtensionRuntime =
  | "rust"
  | "javascript"
  | "wasm"
  | "proxy_wasm"
  | "rego";

export type ExtensionHookKind =
  | "action"
  | "auth"
  | "policy"
  | "transform"
  | "startup"
  | "identity"
  | "ml_classifier"
  | "anomaly_detector"
  | "mcp"
  | "proxy_wasm_filter"
  | "ai_tool_call"
  | "ai_guardrail_input"
  | "ai_guardrail_output"
  | "ai_stream_event"
  | "ai_close"
  | "payment";

export type ExtensionDispatch = "exclusive" | "chain";
export type ExtensionBodyMode = "none" | "buffered" | "streamed";
export type ExtensionRegistrationSource = "link_time" | "directory" | "git";
export type ExtensionState =
  | "installed"
  | "available"
  | "active"
  | "failed"
  | "shadowed"
  | "not_evaluated"
  | "unconsumed";
export type ExtensionScopeMode = "running" | "doctor";

export interface ExtensionInventoryScope {
  mode: ExtensionScopeMode;
  proxy_version: string;
  config_revision: string | null;
}

export interface ExtensionInventorySummary {
  bundles: number;
  hooks: number;
  active: number;
  available: number;
  failed: number;
  collisions: number;
}

export interface ExtensionLoadRecord {
  phase: string;
  status: string;
  detail: string | null;
}

export interface ExtensionBundleRecord {
  id: string;
  name: string;
  version: string;
  package: string | null;
  source: ExtensionRegistrationSource;
  runtime: ExtensionRuntime;
  state: ExtensionState;
  hook_ids: string[];
  load: ExtensionLoadRecord;
}

export interface ExtensionExecution {
  phase: string;
  body_mode: ExtensionBodyMode;
  timeout_ms: number | null;
  max_buffer_bytes: number | null;
}

export interface ExtensionHookRecord {
  id: string;
  bundle_id: string;
  kind: ExtensionHookKind;
  registration: ExtensionRegistrationSource;
  dispatch: ExtensionDispatch;
  match_key: string;
  position: number | null;
  state: ExtensionState;
  detail: string | null;
  runtime: ExtensionRuntime;
  execution: ExtensionExecution;
  capabilities: string[];
}

export interface ExtensionCollision {
  match_key: string;
  registrations: string[];
  winner: string | null;
  resolution: string;
}

export interface ExtensionInventorySnapshot {
  schema_version: number;
  scope: ExtensionInventoryScope;
  summary: ExtensionInventorySummary;
  bundles: ExtensionBundleRecord[];
  hooks: ExtensionHookRecord[];
  collisions: ExtensionCollision[];
}

export interface DeviceVram {
  index?: number;
  name?: string;
  total_bytes?: number;
  free_bytes?: number;
  compute_utilization?: number;
  memory_occupancy?: number;
}
export interface LocalServing {
  ready?: boolean;
  blockers?: string[];
  recommendation?: string;
}
export interface ModelHostStatus {
  // Managed runtime shape. `models` remains as a compatibility mirror of
  // `deployments`; new UI code keys lifecycle actions by `deployment`.
  serving?: boolean;
  reason?: string;
  runtime_revision?: number;
  deployments?: DeploymentRuntimeStatus[];
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
  /** Managed-runtime mirror rows key by deployment, not name. */
  deployment?: string;
  memory?: Record<string, unknown>;
  // EngineState serializes as a string or a small tagged object.
  state?: string | Record<string, unknown>;
  status?: string;
  port?: number;
  vram_bytes?: number;
  keep_alive_secs?: number;
  engine?: string;
  [k: string]: unknown;
}

export type EngineAvailability =
  | "available"
  | "acquirable"
  | "incompatible"
  | "blocked";

export interface RuntimeMemoryEstimate {
  device_index: number;
  weight_bytes: number;
  kv_bytes: number;
  runtime_overhead_bytes: number;
  safety_margin_bytes: number;
  total_bytes: number;
}

export interface DeploymentRuntimeStatus {
  deployment: string;
  generation: number;
  state: DeploymentRuntimeState;
  active_requests: number;
  queued_requests: number;
  engine: EngineKind | null;
  driver_availability: EngineAvailability | null;
  artifact_digest: string | null;
  selected_devices: number[];
  memory: RuntimeMemoryEstimate | null;
  port: number | null;
  reason_code: string | null;
  job_id: string | null;
  last_error: string | null;
}

export interface KeyPolicy {
  allowed_models?: string[];
  blocked_models?: string[];
  allowed_providers?: string[];
  blocked_providers?: string[];
  allowed_tools?: string[] | null;
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

/** A temporary, auto-expiring raise on top of a key's base budget
 *  (WOR-2561). Present on the key document only while unexpired; the
 *  server evaluates expiry lazily on read, so a listed override is an
 *  active one. */
export interface KeyBudgetOverride {
  max_tokens_increase?: number | null;
  max_cost_usd_increase?: number | null;
  expires_at: string;
  granted_by: string;
  granted_at: string;
  reason?: string | null;
}

/** Grant body for `POST /admin/keys/{id}/budget-override`. One of
 *  `ttl_secs` or `expires_at` names the expiry. */
export interface KeyBudgetOverrideGrant {
  max_tokens_increase?: number;
  max_cost_usd_increase?: number;
  ttl_secs?: number;
  expires_at?: string;
  reason?: string;
}

export interface AdminKey {
  id?: string;
  key_id?: string;
  policy_revision: number;
  policy_digest?: string | null;
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
  allowed_tools?: string[] | null;
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
  max_budget_tokens?: number;
  max_budget_usd?: number;
  /** Active temporary raise on the base budget, when one is granted. */
  budget_override?: KeyBudgetOverride | null;
  /** The budget currently enforced: base plus any active override. */
  effective_budget?: { max_tokens?: number | null; max_cost_usd?: number | null } | null;
  project?: string;
  user?: string;
  tenant_id?: string;
  policy?: KeyPolicy;
  [k: string]: unknown;
}

export interface CreatedKey {
  token: string;
  key: AdminKey;
}

/**
 * Result of a key lifecycle action.
 *
 * `rotate` mints a new secret and is the only action that returns one, so
 * `token` is optional. WOR-2345: this was typed `unknown` and the caller
 * discarded the body, which meant rotating a key from the console threw
 * the new secret away. Typing it is what makes forgetting it a compile
 * error rather than a silent lockout once the grace window lapses.
 */
export interface KeyActionResult {
  token?: string;
  grace_expires_at?: string;
  key?: AdminKey;
}

/** Minimal, strictly-typed key listing for selectors (e.g. the playground's
 *  virtual-key picker). `api.keys()` above stays loosely typed for the
 *  full Keys view; this mirrors the same `GET /admin/keys` response. */
export type AdminKeyStatus = "active" | "blocked" | "revoked";

export interface AdminKeySummary {
  key_id: string;
  name: string | null;
  status: AdminKeyStatus;
}

export interface AdminKeysListResponse {
  keys: AdminKeySummary[];
}

export type KeyPolicyMutationKind = "patch" | "action";

export interface KeyPolicyMutationDescriptor {
  kind: KeyPolicyMutationKind;
  fields: string[];
}

export interface KeyPolicyFieldDescriptor {
  wire_name: string;
  mutation: KeyPolicyMutationDescriptor;
  editor: string;
  clear_semantics: string;
  preview_field: string;
  enforcement_proof: string;
}

export interface KeyPolicySchema {
  schema_version: number;
  fields: KeyPolicyFieldDescriptor[];
}

export interface EffectivePolicyPreviewEvidence {
  schema_version: number;
  key_id: string;
  display_name?: string | null;
  source?: string;
  status: string;
  expires_at?: string | null;
  tenant_id: string;
}

export interface EffectivePolicyDecision {
  allowed: boolean;
  reason_code?: string;
}

export type EffectivePolicyDecisionName =
  | "lifecycle"
  | "tenant"
  | "model"
  | "provider"
  | "tools"
  | "principal"
  | "rate_limits"
  | "budget"
  | "priority"
  | "guardrails";

export interface EffectivePolicyDecisions {
  allowed: boolean;
  lifecycle?: EffectivePolicyDecision;
  tenant?: EffectivePolicyDecision;
  model?: EffectivePolicyDecision;
  provider?: EffectivePolicyDecision;
  tools?: EffectivePolicyDecision;
  principal?: EffectivePolicyDecision;
  rate_limits?: EffectivePolicyDecision;
  budget?: EffectivePolicyDecision;
  priority?: EffectivePolicyDecision;
  guardrails?: EffectivePolicyDecision;
}

export interface EffectivePolicyPreview {
  effective_policy: EffectivePolicyPreviewEvidence;
  policy_version: {
    revision: number;
    digest: string;
  };
  decisions: EffectivePolicyDecisions;
}

// Governed-key usage (WOR-1845). GET /admin/keys/{id}/usage returns a
// snapshot of the reserve/settle ledger for one key: four counter
// dimensions plus the health of the backend that served them. `limit` and
// `remaining` are null when the dimension has no configured cap; window
// dimensions carry a `reset_at_millis`, lifetime dimensions do not.
export type GovernanceConsistency = "approximate" | "strict";
export type GovernanceBackendStatus = "healthy" | "degraded" | "unavailable";

export interface GovernanceCounterSnapshot {
  limit: number | null;
  used: number;
  reserved: number;
  remaining: number | null;
  reset_at_millis: number | null;
}

export interface GovernanceBackendHealth {
  backend: string;
  consistency: GovernanceConsistency;
  status: GovernanceBackendStatus;
  checked_at_millis: number;
}

export interface GovernanceSnapshot {
  key_id: string;
  policy_revision: number;
  requests_per_window: GovernanceCounterSnapshot;
  tokens_per_window: GovernanceCounterSnapshot;
  total_tokens: GovernanceCounterSnapshot;
  total_micro_usd: GovernanceCounterSnapshot;
  backend: GovernanceBackendHealth;
}

const EFFECTIVE_POLICY_DECISION_NAMES: readonly EffectivePolicyDecisionName[] = [
  "lifecycle",
  "tenant",
  "model",
  "provider",
  "tools",
  "principal",
  "rate_limits",
  "budget",
  "priority",
  "guardrails",
];

function responseObject(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${label} must be a JSON object`);
  }
  return value as Record<string, unknown>;
}

function responseString(
  object: Record<string, unknown>,
  field: string,
  label: string,
): string {
  const value = object[field];
  if (typeof value !== "string") {
    throw new TypeError(`${label}.${field} must be a string`);
  }
  return value;
}

function responseSafeInteger(
  object: Record<string, unknown>,
  field: string,
  label: string,
): number {
  const value = object[field];
  if (!Number.isSafeInteger(value) || (value as number) < 1) {
    throw new TypeError(`${label}.${field} must be a positive safe integer`);
  }
  return value as number;
}

function responseNonNegativeSafeInteger(
  object: Record<string, unknown>,
  field: string,
  label: string,
): number {
  const value = object[field];
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    throw new TypeError(`${label}.${field} must be a non-negative safe integer`);
  }
  return value as number;
}

function responseNullableNonNegativeSafeInteger(
  object: Record<string, unknown>,
  field: string,
  label: string,
): number | null {
  if (object[field] === null) return null;
  return responseNonNegativeSafeInteger(object, field, label);
}

function optionalNullableResponseString(
  object: Record<string, unknown>,
  field: string,
  label: string,
): string | null | undefined {
  const value = object[field];
  if (value === undefined || value === null || typeof value === "string") {
    return value;
  }
  throw new TypeError(`${label}.${field} must be a string or null`);
}

function decodeKeyPolicySchema(value: unknown): KeyPolicySchema {
  const document = responseObject(value, "policy schema");
  const schemaVersion = responseSafeInteger(
    document,
    "schema_version",
    "policy schema",
  );
  if (!Array.isArray(document.fields)) {
    throw new TypeError("policy schema.fields must be an array");
  }
  const fields = document.fields.map((value, index): KeyPolicyFieldDescriptor => {
    const label = `policy schema.fields[${index}]`;
    const field = responseObject(value, label);
    const mutation = responseObject(field.mutation, `${label}.mutation`);
    const kind = mutation.kind;
    if (kind !== "patch" && kind !== "action") {
      throw new TypeError(`${label}.mutation.kind is not supported`);
    }
    if (
      !Array.isArray(mutation.fields) ||
      mutation.fields.some((name) => typeof name !== "string")
    ) {
      throw new TypeError(`${label}.mutation.fields must be a string array`);
    }
    return {
      wire_name: responseString(field, "wire_name", label),
      mutation: {
        kind,
        fields: [...mutation.fields] as string[],
      },
      editor: responseString(field, "editor", label),
      clear_semantics: responseString(field, "clear_semantics", label),
      preview_field: responseString(field, "preview_field", label),
      enforcement_proof: responseString(field, "enforcement_proof", label),
    };
  });
  return { schema_version: schemaVersion, fields };
}

function decodeEffectivePolicyPreview(value: unknown): EffectivePolicyPreview {
  const document = responseObject(value, "effective policy preview");
  const rawPolicy = responseObject(
    document.effective_policy,
    "effective policy preview.effective_policy",
  );
  const rawVersion = responseObject(
    document.policy_version,
    "effective policy preview.policy_version",
  );
  const rawDecisions = responseObject(
    document.decisions,
    "effective policy preview.decisions",
  );
  if (typeof rawDecisions.allowed !== "boolean") {
    throw new TypeError(
      "effective policy preview.decisions.allowed must be a boolean",
    );
  }

  const effectivePolicy: EffectivePolicyPreviewEvidence = {
    schema_version: responseSafeInteger(
      rawPolicy,
      "schema_version",
      "effective policy preview.effective_policy",
    ),
    key_id: responseString(
      rawPolicy,
      "key_id",
      "effective policy preview.effective_policy",
    ),
    status: responseString(
      rawPolicy,
      "status",
      "effective policy preview.effective_policy",
    ),
    tenant_id: responseString(
      rawPolicy,
      "tenant_id",
      "effective policy preview.effective_policy",
    ),
  };
  for (const field of ["display_name", "expires_at"] as const) {
    const optional = optionalNullableResponseString(
      rawPolicy,
      field,
      "effective policy preview.effective_policy",
    );
    if (optional !== undefined) effectivePolicy[field] = optional;
  }
  if (rawPolicy.source !== undefined) {
    effectivePolicy.source = responseString(
      rawPolicy,
      "source",
      "effective policy preview.effective_policy",
    );
  }

  const decisions: EffectivePolicyDecisions = {
    allowed: rawDecisions.allowed,
  };
  for (const name of EFFECTIVE_POLICY_DECISION_NAMES) {
    if (rawDecisions[name] === undefined) continue;
    const label = `effective policy preview.decisions.${name}`;
    const rawDecision = responseObject(rawDecisions[name], label);
    if (typeof rawDecision.allowed !== "boolean") {
      throw new TypeError(`${label}.allowed must be a boolean`);
    }
    const reasonCode = optionalNullableResponseString(
      rawDecision,
      "reason_code",
      label,
    );
    decisions[name] = {
      allowed: rawDecision.allowed,
      ...(typeof reasonCode === "string" ? { reason_code: reasonCode } : {}),
    };
  }

  return {
    effective_policy: effectivePolicy,
    policy_version: {
      revision: responseSafeInteger(
        rawVersion,
        "revision",
        "effective policy preview.policy_version",
      ),
      digest: responseString(
        rawVersion,
        "digest",
        "effective policy preview.policy_version",
      ),
    },
    decisions,
  };
}

const GOVERNANCE_CONSISTENCIES: readonly GovernanceConsistency[] = [
  "approximate",
  "strict",
];
const GOVERNANCE_BACKEND_STATUSES: readonly GovernanceBackendStatus[] = [
  "healthy",
  "degraded",
  "unavailable",
];

function decodeGovernanceCounterSnapshot(
  value: unknown,
  label: string,
): GovernanceCounterSnapshot {
  const counter = responseObject(value, label);
  return {
    limit: responseNullableNonNegativeSafeInteger(counter, "limit", label),
    used: responseNonNegativeSafeInteger(counter, "used", label),
    reserved: responseNonNegativeSafeInteger(counter, "reserved", label),
    remaining: responseNullableNonNegativeSafeInteger(counter, "remaining", label),
    reset_at_millis: responseNullableNonNegativeSafeInteger(
      counter,
      "reset_at_millis",
      label,
    ),
  };
}

function decodeGovernanceBackendHealth(
  value: unknown,
  label: string,
): GovernanceBackendHealth {
  const backend = responseObject(value, label);
  const consistency = backend.consistency;
  if (!GOVERNANCE_CONSISTENCIES.includes(consistency as GovernanceConsistency)) {
    throw new TypeError(`${label}.consistency is not supported`);
  }
  const status = backend.status;
  if (!GOVERNANCE_BACKEND_STATUSES.includes(status as GovernanceBackendStatus)) {
    throw new TypeError(`${label}.status is not supported`);
  }
  return {
    backend: responseString(backend, "backend", label),
    consistency: consistency as GovernanceConsistency,
    status: status as GovernanceBackendStatus,
    checked_at_millis: responseNonNegativeSafeInteger(
      backend,
      "checked_at_millis",
      label,
    ),
  };
}

/** Decode GET /admin/keys/{id}/usage's `usage` payload (a GovernanceSnapshot). */
function decodeGovernanceSnapshot(value: unknown): GovernanceSnapshot {
  const document = responseObject(value, "governance usage");
  return {
    key_id: responseString(document, "key_id", "governance usage"),
    policy_revision: responseSafeInteger(
      document,
      "policy_revision",
      "governance usage",
    ),
    requests_per_window: decodeGovernanceCounterSnapshot(
      document.requests_per_window,
      "governance usage.requests_per_window",
    ),
    tokens_per_window: decodeGovernanceCounterSnapshot(
      document.tokens_per_window,
      "governance usage.tokens_per_window",
    ),
    total_tokens: decodeGovernanceCounterSnapshot(
      document.total_tokens,
      "governance usage.total_tokens",
    ),
    total_micro_usd: decodeGovernanceCounterSnapshot(
      document.total_micro_usd,
      "governance usage.total_micro_usd",
    ),
    backend: decodeGovernanceBackendHealth(document.backend, "governance usage.backend"),
  };
}

export interface KeyPolicyDraft {
  name: string | null;
  expires_at: string | null;
  allowed_models: string[];
  blocked_models: string[];
  allowed_providers: string[];
  blocked_providers: string[];
  allowed_tools: string[] | null;
  require_pii_redaction: string[];
  route_to_model: string | null;
  max_requests_per_minute: number | null;
  max_tokens_per_minute: number | null;
  priority: string | null;
  max_budget_tokens: number | null;
  max_budget_usd: number | null;
  project: string | null;
  user: string | null;
  tenant_id: string | null;
  bypass_prompt_injection: boolean;
  principal_selectors: unknown[];
  inject_tools: unknown[];
  inject_mcp: Record<string, unknown> | null;
  metadata: Record<string, string>;
  tags: string[];
}

export interface AdminKeyPolicyPatch {
  expected_revision: number;
  name?: string | null;
  expires_at?: string | null;
  allowed_models?: string[];
  blocked_models?: string[];
  allowed_providers?: string[];
  blocked_providers?: string[];
  allowed_tools?: string[] | null;
  require_pii_redaction?: string[];
  route_to_model?: string | null;
  max_requests_per_minute?: number | null;
  max_tokens_per_minute?: number | null;
  priority?: string | null;
  max_budget_tokens?: number | null;
  max_budget_usd?: number | null;
  project?: string | null;
  user?: string | null;
  tenant?: string | null;
  bypass_prompt_injection?: boolean;
  principal_selectors?: unknown[];
  inject_tools?: unknown[];
  inject_mcp?: Record<string, unknown> | null;
  metadata?: Record<string, string>;
  tags?: string[];
}

function keyPolicyField(key: AdminKey, field: keyof KeyPolicy): unknown {
  const direct = key[field as keyof AdminKey];
  return direct !== undefined ? direct : key.policy?.[field];
}

function cloneJson<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function stringList(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string")
    : [];
}

function nullableStringList(value: unknown): string[] | null {
  return Array.isArray(value) ? stringList(value) : null;
}

function jsonList(value: unknown): unknown[] {
  return Array.isArray(value) ? cloneJson(value) : [];
}

function nullableString(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function nullableNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function jsonObject(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? cloneJson(value as Record<string, unknown>)
    : null;
}

function stringRecord(value: unknown): Record<string, string> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  return Object.fromEntries(
    Object.entries(value).filter(
      (entry): entry is [string, string] => typeof entry[1] === "string",
    ),
  );
}

function budgetField(key: AdminKey, field: "max_tokens" | "max_cost_usd"): number | null {
  const budget = keyPolicyField(key, "budget");
  if (!budget || typeof budget !== "object" || Array.isArray(budget)) return null;
  return nullableNumber((budget as Record<string, unknown>)[field]);
}

export function keyPolicyDraft(key: AdminKey): KeyPolicyDraft {
  const maxBudgetTokens =
    nullableNumber(keyPolicyField(key, "max_budget_tokens")) ??
    budgetField(key, "max_tokens");
  const maxBudgetUsd =
    nullableNumber(keyPolicyField(key, "max_budget_usd")) ??
    nullableNumber(keyPolicyField(key, "budget_usd")) ??
    budgetField(key, "max_cost_usd");

  return {
    name: nullableString(key.name),
    expires_at: nullableString(key.expires_at),
    allowed_models: stringList(keyPolicyField(key, "allowed_models")),
    blocked_models: stringList(keyPolicyField(key, "blocked_models")),
    allowed_providers: stringList(keyPolicyField(key, "allowed_providers")),
    blocked_providers: stringList(keyPolicyField(key, "blocked_providers")),
    allowed_tools: nullableStringList(keyPolicyField(key, "allowed_tools")),
    require_pii_redaction: stringList(
      keyPolicyField(key, "require_pii_redaction"),
    ),
    route_to_model: nullableString(keyPolicyField(key, "route_to_model")),
    max_requests_per_minute: nullableNumber(
      keyPolicyField(key, "max_requests_per_minute"),
    ),
    max_tokens_per_minute: nullableNumber(
      keyPolicyField(key, "max_tokens_per_minute"),
    ),
    priority: nullableString(keyPolicyField(key, "priority")),
    max_budget_tokens: maxBudgetTokens,
    max_budget_usd: maxBudgetUsd,
    project: nullableString(keyPolicyField(key, "project")),
    user: nullableString(keyPolicyField(key, "user")),
    tenant_id: nullableString(keyPolicyField(key, "tenant_id")),
    bypass_prompt_injection:
      keyPolicyField(key, "bypass_prompt_injection") === true,
    principal_selectors: jsonList(
      keyPolicyField(key, "principal_selectors"),
    ),
    inject_tools: jsonList(keyPolicyField(key, "inject_tools")),
    inject_mcp: jsonObject(keyPolicyField(key, "inject_mcp")),
    metadata: stringRecord(keyPolicyField(key, "metadata")),
    tags: stringList(keyPolicyField(key, "tags")),
  };
}

function canonicalJson(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalJson);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.entries(value)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, child]) => [key, canonicalJson(child)]),
  );
}

function sameJson(left: unknown, right: unknown): boolean {
  return JSON.stringify(canonicalJson(left)) === JSON.stringify(canonicalJson(right));
}

export function buildKeyPolicyPatch(
  baseline: AdminKey,
  draft: KeyPolicyDraft,
): AdminKeyPolicyPatch {
  if (!Number.isSafeInteger(baseline.policy_revision) || baseline.policy_revision < 1) {
    throw new TypeError("policy_revision must be a safe integer of at least 1");
  }
  const before = keyPolicyDraft(baseline);
  const patch: AdminKeyPolicyPatch = {
    expected_revision: baseline.policy_revision,
  };

  if (before.name !== draft.name) patch.name = draft.name;
  if (before.expires_at !== draft.expires_at) {
    patch.expires_at = draft.expires_at;
  }
  if (!sameJson(before.allowed_models, draft.allowed_models)) {
    patch.allowed_models = [...draft.allowed_models];
  }
  if (!sameJson(before.blocked_models, draft.blocked_models)) {
    patch.blocked_models = [...draft.blocked_models];
  }
  if (!sameJson(before.allowed_providers, draft.allowed_providers)) {
    patch.allowed_providers = [...draft.allowed_providers];
  }
  if (!sameJson(before.blocked_providers, draft.blocked_providers)) {
    patch.blocked_providers = [...draft.blocked_providers];
  }
  if (!sameJson(before.allowed_tools, draft.allowed_tools)) {
    patch.allowed_tools =
      draft.allowed_tools === null ? null : [...draft.allowed_tools];
  }
  if (!sameJson(before.require_pii_redaction, draft.require_pii_redaction)) {
    patch.require_pii_redaction = [...draft.require_pii_redaction];
  }
  if (before.route_to_model !== draft.route_to_model) {
    patch.route_to_model = draft.route_to_model;
  }
  if (before.max_requests_per_minute !== draft.max_requests_per_minute) {
    patch.max_requests_per_minute = draft.max_requests_per_minute;
  }
  if (before.max_tokens_per_minute !== draft.max_tokens_per_minute) {
    patch.max_tokens_per_minute = draft.max_tokens_per_minute;
  }
  if (before.priority !== draft.priority) {
    patch.priority = draft.priority;
  }
  if (before.max_budget_tokens !== draft.max_budget_tokens) {
    patch.max_budget_tokens = draft.max_budget_tokens;
  }
  if (before.max_budget_usd !== draft.max_budget_usd) {
    patch.max_budget_usd = draft.max_budget_usd;
  }
  if (before.project !== draft.project) patch.project = draft.project;
  if (before.user !== draft.user) patch.user = draft.user;
  if (before.tenant_id !== draft.tenant_id) patch.tenant = draft.tenant_id;
  if (before.bypass_prompt_injection !== draft.bypass_prompt_injection) {
    patch.bypass_prompt_injection = draft.bypass_prompt_injection;
  }
  if (!sameJson(before.principal_selectors, draft.principal_selectors)) {
    patch.principal_selectors = cloneJson(draft.principal_selectors);
  }
  if (!sameJson(before.inject_tools, draft.inject_tools)) {
    patch.inject_tools = cloneJson(draft.inject_tools);
  }
  if (!sameJson(before.inject_mcp, draft.inject_mcp)) {
    patch.inject_mcp = draft.inject_mcp === null ? null : cloneJson(draft.inject_mcp);
  }
  if (!sameJson(before.metadata, draft.metadata)) {
    patch.metadata = { ...draft.metadata };
  }
  if (!sameJson(before.tags, draft.tags)) patch.tags = [...draft.tags];

  return patch;
}

export function rebaseKeyPolicyDraft(
  current: AdminKey,
  localPatch: AdminKeyPolicyPatch,
): KeyPolicyDraft {
  const draft = keyPolicyDraft(current);
  if ("name" in localPatch) draft.name = localPatch.name ?? null;
  if ("expires_at" in localPatch) {
    draft.expires_at = localPatch.expires_at ?? null;
  }
  if (localPatch.allowed_models !== undefined) {
    draft.allowed_models = [...localPatch.allowed_models];
  }
  if (localPatch.blocked_models !== undefined) {
    draft.blocked_models = [...localPatch.blocked_models];
  }
  if (localPatch.allowed_providers !== undefined) {
    draft.allowed_providers = [...localPatch.allowed_providers];
  }
  if (localPatch.blocked_providers !== undefined) {
    draft.blocked_providers = [...localPatch.blocked_providers];
  }
  if ("allowed_tools" in localPatch) {
    draft.allowed_tools =
      localPatch.allowed_tools === null || localPatch.allowed_tools === undefined
        ? null
        : [...localPatch.allowed_tools];
  }
  if (localPatch.require_pii_redaction !== undefined) {
    draft.require_pii_redaction = [...localPatch.require_pii_redaction];
  }
  if ("route_to_model" in localPatch) {
    draft.route_to_model = localPatch.route_to_model ?? null;
  }
  if ("max_requests_per_minute" in localPatch) {
    draft.max_requests_per_minute = localPatch.max_requests_per_minute ?? null;
  }
  if ("max_tokens_per_minute" in localPatch) {
    draft.max_tokens_per_minute = localPatch.max_tokens_per_minute ?? null;
  }
  if ("priority" in localPatch) draft.priority = localPatch.priority ?? null;
  if ("max_budget_tokens" in localPatch) {
    draft.max_budget_tokens = localPatch.max_budget_tokens ?? null;
  }
  if ("max_budget_usd" in localPatch) {
    draft.max_budget_usd = localPatch.max_budget_usd ?? null;
  }
  if ("project" in localPatch) draft.project = localPatch.project ?? null;
  if ("user" in localPatch) draft.user = localPatch.user ?? null;
  if ("tenant" in localPatch) draft.tenant_id = localPatch.tenant ?? null;
  if (localPatch.bypass_prompt_injection !== undefined) {
    draft.bypass_prompt_injection = localPatch.bypass_prompt_injection;
  }
  if (localPatch.principal_selectors !== undefined) {
    draft.principal_selectors = cloneJson(localPatch.principal_selectors);
  }
  if (localPatch.inject_tools !== undefined) {
    draft.inject_tools = cloneJson(localPatch.inject_tools);
  }
  if ("inject_mcp" in localPatch) {
    draft.inject_mcp = localPatch.inject_mcp === null || localPatch.inject_mcp === undefined
      ? null
      : cloneJson(localPatch.inject_mcp);
  }
  if (localPatch.metadata !== undefined) {
    draft.metadata = { ...localPatch.metadata };
  }
  if (localPatch.tags !== undefined) draft.tags = [...localPatch.tags];
  return draft;
}

function assertKeyPolicyPatch(patch: AdminKeyPolicyPatch): void {
  if (!Number.isSafeInteger(patch.expected_revision) || patch.expected_revision < 1) {
    throw new TypeError("expected_revision must be a safe integer of at least 1");
  }
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

/// Where one leaf of the running config came from. `local` and
/// `authority` arrive as bare strings; a git leaf carries the resolved
/// commit, which is the part worth showing an operator.
export type ConfigProvenance =
  | "local"
  | "authority"
  | { git: { repo: string; reference: string; commit: string } };

export interface ConfigLayers {
  base?:
    | { kind: "local" }
    | { kind: "git"; repo: string; reference: string; commit: string };
  authority?: {
    authority_id: string;
    revision: number;
    mode: "overlay" | "replace";
  } | null;
}

export interface EffectiveConfigResponse {
  // GET /admin/config/effective.
  yaml?: string;
  provenance?: Record<string, ConfigProvenance>;
  layers?: ConfigLayers;
  // True only when this node's own file is the whole configuration, which
  // is the condition under which the editor may offer a write.
  locally_owned?: boolean;
  locally_owned_leaves?: number;
  total_leaves?: number;
  [k: string]: unknown;
}

/// Body of a 409 the write guard produced. Distinguished from a revision
/// mismatch by `code`, because the two need different advice: one says
/// reload and reapply, the other says this is not your config to edit.
export interface ConfigWriteConflict {
  code?: string;
  error?: string;
  conflicts?: { path: string; owner: ConfigProvenance | "suppressed" }[];
  layers?: ConfigLayers;
  remedy?: string;
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
  /** WOR-2328: the target's authored zone label. Selection prefers
   *  targets matching the pipeline's `proxy_zone`. */
  zone?: string | null;
  [k: string]: unknown;
}

export interface ConfigDoc {
  revision?: string;
  yaml?: string;
}

/// One config revision in the durable history ring (WOR-2456/2457).
/// `blast_radius` compares this entry to the one before it, so the
/// first entry in a lineage always carries `null`. `degraded` names the
/// subsystems that did not pick up this revision cleanly; an empty
/// array means the revision applied everywhere.
export type ConfigHistoryState = "applied" | "good" | "failed" | "reverted";
export type ConfigHistoryBlastRadius =
  | "hitless"
  | "reload"
  | "restart"
  | "breaking";

export interface ConfigHistoryEntry {
  revision: number;
  digest: string;
  provenance: string;
  state: ConfigHistoryState;
  /** RFC 3339, UTC, millisecond precision (e.g. "2026-08-16T10:15:32.456Z").
   *  Not epoch millis: `toDate` in `../lib/format` still handles it
   *  correctly, but through its ISO-string branch, not its numeric-ms
   *  heuristic -- `Number()` on an RFC 3339 string is NaN, so the
   *  numeric branch never fires for this field. */
  applied_at: string;
  actor: string;
  blast_radius: ConfigHistoryBlastRadius | null;
  degraded: string[];
}

/** GET /admin/config/history. Entries arrive newest first. 404s with
 *  `{"error":"config history is not enabled"}` when
 *  proxy.config_history.enabled is off or the store is absent. 503s
 *  with `{"error":"config history failed to open at boot: <reason>"}`
 *  when the block is enabled but the ring could not open -- a real
 *  error, not the disabled empty state; `isConfigHistoryDisabled`
 *  (`./lib/config-history`) only ever matches the 404. */
export interface ConfigHistoryResponse {
  lineage: string;
  lkg_revision: number | null;
  entries: ConfigHistoryEntry[];
}

/** GET /admin/config/history/{digest}. `document` is the stored
 *  pre-resolution YAML; `plan_text` is the rendered plan() diff against
 *  the running config. 404s the same way as the list route, plus for an
 *  unknown digest; 503s the same way as the list route too. */
export interface ConfigHistoryDetail {
  entry: ConfigHistoryEntry;
  document: string;
  plan_text: string;
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

/** Cluster-wide VRAM aggregation. Distinct from `ModelHostStatus.vram`
 *  above, which is this node's own local view only. */
export interface ClusterVramStatus {
  budget_bytes: number;
  used_bytes: number;
  free_bytes: number;
  devices: DeviceVram[];
}

export interface ClusterVramNode {
  node_id: string;
  vram: ClusterVramStatus;
}

export interface ClusterVramSummary {
  total_bytes: number;
  used_bytes: number;
  free_bytes: number;
  device_count: number;
  node_count: number;
}

export interface ClusterVramResponse {
  schema_version: number;
  generated_at_unix_ms: number;
  directory_collected_at_unix_ms: number | null;
  cluster: ClusterVramSummary;
  nodes: ClusterVramNode[];
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
  download_size_bytes: number;
  certification: string;
  stability: SupportLevel;
}

export interface CatalogEntry {
  params: string;
  license: string;
  family: string;
  context_length: number;
  /** Pickle variants stay unavailable unless the logical model opts in. */
  allow_pickle?: boolean;
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
export type ColdStartPolicy = "wait" | "reject" | "fallback";

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
  cold_start: ColdStartPolicy;
}

export interface ModelDeploymentRequest {
  model: string;
  variant?: string | null;
  heterogeneous_variants?: boolean;
  replicas?: number;
  required_labels?: Record<string, string>;
  spread_by?: string[];
  pull?: PullPolicy;
  warm?: boolean;
  keep_alive_secs?: number | null;
  max_concurrency?: number | null;
  max_queue_depth?: number;
  queue_timeout_ms?: number;
  engine?: EngineChoice;
  rollout?: RolloutPolicy;
  cold_start?: ColdStartPolicy;
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
  deployments: Record<string, ModelDeploymentRequest>;
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

/* ---- Artifact cache storage (WOR-1910) ---- */

// One durable ready artifact in the verified weight cache, as reported by
// GET /admin/model-host/files. `resident` marks artifacts backing a
// currently ready replica; the server refuses to delete those.
export interface ModelHostArtifactFile {
  logical_model: string;
  variant_id: string;
  artifact_digest: string;
  total_size_bytes: number;
  last_accessed_ms: number;
  resident: boolean;
}

export interface ModelHostFilesResponse {
  schema_version: number;
  // Absent when no model host is configured (no artifact cache is open).
  cache_root?: string;
  total_bytes: number;
  artifacts: ModelHostArtifactFile[];
  // Configured weight-cache disk budget in bytes, when the server reports
  // it. An explicit null means no budget is configured, so cache GC has
  // nothing to enforce. Absent on servers that do not report the budget.
  cache_budget_bytes?: number | null;
}

// DELETE /admin/model-host/artifacts/{digest} success report. Refusals
// (resident, configured, pinned, busy) come back as a 409 whose body
// carries `{code, error}` like the other model-host mutation routes.
export interface ArtifactRemovalReport {
  artifact_digest: string;
  removed: boolean;
  reclaimed_bytes: number;
  job_id?: string | null;
}

// POST /admin/model-host/gc result: deterministic cache-budget collection.
export interface GcReport {
  before_bytes: number;
  after_bytes: number;
  reclaimed_bytes: number;
  deleted_artifacts: string[];
  skipped_artifacts: Record<string, string>;
  budget_unsatisfied_bytes: number;
}

/* ---- Durable operation jobs (queued / in-flight lifecycle work) ---- */

export type OperationKind =
  | "pull"
  | "verify"
  | "provision"
  | "launch"
  | "load"
  | "drain"
  | "stop"
  | "rollout"
  | "delete"
  | "reset";

export type OperationState =
  | "queued"
  | "downloading"
  | "verifying"
  | "ready"
  | "failed"
  | "deleting"
  | "deleted";

export interface OperationProgress {
  completed_bytes: number;
  total_bytes: number;
  current_file: string | null;
}

// Mirrors sbproxy_model_host::jobs::OperationJob. `subject` is the
// deployment id or artifact digest the operation acts on.
export interface OperationJob {
  id: string;
  kind: OperationKind;
  subject: string;
  state: OperationState;
  progress: OperationProgress;
  created_at_ms: number;
  updated_at_ms: number;
  terminal_at_ms: number | null;
  error: string | null;
}

export interface JobsListResponse {
  schema_version: number;
  jobs: OperationJob[];
}

export interface JobDetailResponse {
  schema_version: number;
  job: OperationJob;
}

export interface ClusterDeploymentBundleDraft {
  catalog_revision: string;
  revision: number;
  deployments: Record<string, ModelDeploymentRequest>;
}

export interface ClusterDeploymentBundle {
  schema_version: number;
  catalog_revision: string;
  revision: number;
  deployments: Record<string, ModelDeployment>;
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
  // WOR-1874 correlation + AI columns on the ring entry.
  request_id?: string;
  trace_id?: string;
  session_id?: string;
  parent_session_id?: string;
  properties?: Record<string, string>;
  cache_status?: "disabled" | "miss" | "hit" | "semantic_hit" | string;
  retry_count?: number;
  failover_engaged?: boolean;
  failover_from?: string;
  failover_to?: string;
  // WOR-2556: which typed trigger drove an AI reroute, when one did.
  // Closed vocabulary: "context_window" | "content_policy" | "generic".
  failover_trigger?: string;
  load_balancer_strategy?: string;
  load_balancer_target?: string;
  /** WOR-2328 zone-locality verdict for the selected target:
   *  "local" (stayed in the proxy's own zone) or "spilled" (no
   *  same-zone target was healthy). Absent when the stage did not
   *  engage. */
  zone_locality?: "local" | "spilled" | string;
  /** Why the strategy picked that target, when it decides per request. */
  routing_detail?: string;
  provider?: string;
  model?: string;
  tokens_in?: number;
  tokens_out?: number;
  cost_usd_micros?: number;
  guardrail_category?: string;
  guardrail_action?: string;
  origin?: string;
  // WOR-2093 key accountability columns.
  api_key_id?: string;
  key_mode?: "none" | "minted" | "native" | string;
  key_provider?: string;
  // Which secret the AI attempt presented upstream, the outbound
  // counterpart to key_mode. Absent on rows the AI gateway did not
  // dispatch.
  credential_source?: "provider_entry" | "native_caller" | "fallback" | string;
  tenant_id?: string;
  user_id?: string;
  // WOR-2094 explainability columns.
  error_class?: string;
  config_revision?: string;
  policy_version?: string;
  policy_decisions?: string[];
  deny_reason?: string;
  [k: string]: unknown;
}

export interface RequestFilters {
  method?: string;
  status?: string;
  path?: string;
  origin?: string;
  sessionId?: string;
  guardrailAction?: string;
  guardrailCategory?: string;
  cacheStatus?: string;
  retried?: boolean;
  propertyKey?: string;
  propertyValue?: string;
  // WOR-2093: server-side key accountability filters.
  apiKeyId?: string;
  keyMode?: "none" | "minted" | "native";
  // WOR-2578: reporting-dimension filters (exact matches).
  model?: string;
  tenant?: string;
  user?: string;
}

// WOR-2578: multi-dimension aggregation of the request ring.
export interface RequestReportRow {
  /** Dimension name to value; an empty value means unattributed. */
  group: Record<string, string>;
  requests: number;
  tokens_in: number;
  tokens_out: number;
  cost_usd_micros: number;
}

export interface RequestReportTotals {
  requests: number;
  tokens_in: number;
  tokens_out: number;
  cost_usd_micros: number;
}

export interface RequestReportResponse {
  schema_version: number;
  group_by: string[];
  rows: RequestReportRow[];
  totals: RequestReportTotals;
}

// WOR-2575: routing decision ring entry (GET /api/routing-decisions).
export interface RoutingDecisionCandidate {
  provider: string;
  model?: string;
}

export interface RoutingDecision {
  timestamp?: string;
  origin?: string;
  request_id?: string;
  tenant_id?: string;
  strategy?: string;
  requested_model?: string;
  selected_provider?: string;
  selected_model?: string;
  reason?: string;
  candidates?: RoutingDecisionCandidate[];
  attempted?: string[];
  attempts?: number;
  failover_engaged?: boolean;
  failover_from?: string;
  failover_to?: string;
  status?: number;
  latency_ms?: number;
  // Open, additive detail map. Later columns (typed fallback triggers,
  // eligibility filters, price-ceiling exclusions, semantic-match
  // scores) land as keys here, not as a schema change.
  detail?: Record<string, unknown>;
  [k: string]: unknown;
}

export interface RoutingDecisionFilters {
  origin?: string;
  strategy?: string;
  provider?: string;
  model?: string;
  since?: string;
  until?: string;
  limit?: number;
}

/** One MCP approval hold from `GET /api/mcp/approvals`. */
export interface McpHold {
  id: string;
  snapshot: string;
  tool_digest: string;
  tool_name: string;
  origin: string;
  principal_id: string;
  tenant_id: string;
  reason: string;
  created_at: number;
  expires_at: number;
  state: "pending" | { approved: { by: string; at_unix: number } } | { denied: { by: string; at_unix: number } };
}

export interface McpApprovalsResponse {
  enabled: boolean;
  holds: McpHold[];
  console_page?: string;
}

function holdStateLabel(state: McpHold["state"]): string {
  if (state === "pending") return "pending";
  if (state && typeof state === "object" && "approved" in state) return "approved";
  if (state && typeof state === "object" && "denied" in state) return "denied";
  return "unknown";
}

export { holdStateLabel };

export type AlertRuleState = "inactive" | "ok" | "firing";
export type AlertDeliveryStatus = "untested" | "healthy" | "failing";
export type AlertHistoryEvent = "fired" | "resolved" | "test";

export interface AlertRule {
  rule: string;
  description: string;
  thresholds: number[];
  minimum_samples?: number;
  state: AlertRuleState;
  reading?: number;
  sample_count?: number;
  last_evaluated_at?: string;
}

export interface AlertDeliveryHealth {
  status: AlertDeliveryStatus;
  last_attempt_at?: string;
  error?: string;
}

export interface AlertChannel {
  index: number;
  type: "webhook" | "slack" | "pagerduty" | "log" | string;
  target?: string;
  routing_key_configured?: boolean;
  health: AlertDeliveryHealth;
}

export interface AlertPayload {
  rule: string;
  severity: "warning" | "critical" | string;
  message: string;
  timestamp: string;
  labels: Record<string, string>;
  resolved: boolean;
}

export interface AlertHistoryEntry {
  event: AlertHistoryEvent;
  channel_index?: number;
  alert: AlertPayload;
}

export interface AlertSnapshot {
  enabled: boolean;
  authority: "file";
  read_only: boolean;
  rules: AlertRule[];
  channels: AlertChannel[];
  history: AlertHistoryEntry[];
}

// WOR-1870: UI settings served by the admin API.
export interface UiSettings {
  trace_url_template?: string | null;
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

/**
 * Flatten `GET /admin/prompts` into the row shape the Prompts page renders.
 *
 * The endpoint returns a doubly-nested map:
 *
 * ```json
 * { "hosts": { "<host>": { "prompts": { "<name>": {
 *     "default_version": "...", "effective_version": "...",
 *     "versions": ["1", "2"] } } } } }
 * ```
 *
 * WOR-2343: the page used the generic `asList` helper, which looks for a
 * known key (`prompts`, `overlays`, `items`, `data`) or the first
 * array-valued property. `hosts` is in neither category, and its value is
 * an object, so the helper returned `[]` and the page rendered empty
 * forever, with no error anywhere. The feature underneath works end to
 * end; only this projection was missing.
 *
 * `default_version` is the operator's pin and `effective_version` is what
 * `PromptStore::render` would actually choose, which is the pinned
 * version when one is set and the highest numeric label otherwise. Both
 * are carried so the page can show the pin without implying an unpinned
 * prompt has no active version.
 */
export function flattenPromptOverlay(data: unknown): PromptEntry[] {
  const hosts = (data as { hosts?: unknown } | null)?.hosts;
  if (!hosts || typeof hosts !== "object") return [];
  const rows: PromptEntry[] = [];
  for (const [host, hostEntry] of Object.entries(hosts as Record<string, unknown>)) {
    const prompts = (hostEntry as { prompts?: unknown } | null)?.prompts;
    if (!prompts || typeof prompts !== "object") continue;
    for (const [name, entry] of Object.entries(prompts as Record<string, unknown>)) {
      const e = (entry ?? {}) as {
        default_version?: string | null;
        effective_version?: string | null;
        versions?: unknown;
      };
      rows.push({
        host,
        name,
        pinned: e.default_version ?? undefined,
        active: e.effective_version ?? undefined,
        versions: Array.isArray(e.versions) ? (e.versions as string[]) : [],
      });
    }
  }
  // Stable ordering so a poll does not reshuffle the page under the
  // operator; `Object.entries` order is insertion order from the server's
  // map, which is not guaranteed to be meaningful.
  rows.sort(
    (a, b) =>
      (a.host ?? "").localeCompare(b.host ?? "") ||
      (a.name ?? "").localeCompare(b.name ?? ""),
  );
  return rows;
}

// WOR-2094: one normalized audit event from the bounded runtime sample.
export interface AuditEvent {
  timestamp: string;
  channel: "security" | "key" | "config" | "admin" | "policy" | string;
  kind: string;
  actor?: string;
  tenant_id?: string;
  api_key_id?: string;
  request_id?: string;
  detail?: string;
}

export interface AuditEventFilters {
  limit?: number;
  channel?: string;
  kind?: string;
  keyId?: string;
}

// WOR-2579: the tamper-evident chain viewer (GET /api/audit/chain).
// One status object per channel; only channels the request walked carry
// verification fields, and a disabled channel carries just its name.
export interface AuditChainChannel {
  channel: "security" | "config" | "key" | "admin" | string;
  enabled: boolean;
  path?: string;
  key_id?: string;
  chain_entries?: number;
  verified_entries?: number;
  ok?: boolean;
  broken_seq?: number | null;
  reason?: string | null;
  total_matched?: number;
  next_before_seq?: number | null;
  error?: string;
}

export interface AuditChainEntry {
  channel: string;
  seq: number;
  recorded_at: string;
  actor?: string | null;
  event: Record<string, unknown>;
}

export interface AuditChainResponse {
  channels: AuditChainChannel[];
  entries: AuditChainEntry[];
}

export interface AuditChainFilters {
  channel?: string;
  actor?: string;
  since?: string;
  until?: string;
  beforeSeq?: number;
  limit?: number;
}

// WOR-2096: one redacted content sample for one request.
export interface CapturedMessage {
  role: string;
  content: string;
}

export interface ContentSample {
  request_id: string;
  api_key_id?: string;
  tenant_id: string;
  origin: string;
  model?: string;
  captured_at: string;
  input_messages: CapturedMessage[];
  output_text?: string;
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
  /** The server refuses `/chat` without this exact value: the route
   *  skips key policy, budgets, and guardrails, so the bypass must be
   *  explicit. The UI never sets it; the Playground page dispatches
   *  through `playgroundDispatch` instead. */
  bypass_governance: true;
  debug?: boolean;
}
export interface PlaygroundChatResult {
  origin?: string;
  // Present on responses from `playgroundDispatch`: the virtual key the
  // request was dispatched as.
  key_id?: string;
  status?: number;
  model?: string;
  response?: Record<string, unknown>;
  usage?: { input_tokens: number; output_tokens: number };
  cost_usd?: number;
  latency_ms?: number;
  debug?: { request_id?: string; config_revision?: string };
  error?: string;
}
/** Body for `playgroundDispatch`: same as `PlaygroundChatRequest` plus the
 *  virtual key to impersonate through the real data-plane dispatch path. */
export interface PlaygroundDispatchRequest {
  key_id: string;
  origin: string;
  request: Record<string, unknown>;
  debug?: boolean;
}
export interface CacheStatus {
  enabled: boolean;
  backend?: string;
  prefix_purge_supported?: boolean;
}
export interface SemanticDecision {
  /**
   * One of `hit`, `no_entry`, `expired`, `below_threshold`,
   * `incompatible`, or `backend_error`. Mirrors `CacheDecision.reason` in
   * crates/sbproxy-ai/src/semantic_cache.rs.
   */
  reason: string;
  score?: number | null;
  threshold: number;
  /** Unix seconds when the lookup happened. */
  at_unix: number;
  // WOR-2344: `scope` was declared here as a required string long after
  // the 2026-08-01 distributed-cache rewrite stopped emitting it, so
  // every read was `undefined` while TypeScript insisted it was a string.
  // The cross-tenant guarantee it described is intact; only the
  // admin-visible field went away.
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

/** A console login, as reported by `/api/admin/users`. Never carries a password. */
export interface AdminUser {
  username: string;
  role: "admin" | "read_only";
  /** The top-level admin credential, which always has the full-access role. */
  primary: boolean;
}

export interface AdminUsersResponse {
  users: AdminUser[];
}

/** Where a registration sits in the owner-approval queue. */
export type AgentRegistrationState =
  | "pending"
  | "approved"
  | "rejected"
  | "revoked";

/** What a submitter said about their agent. Mirrors the server's
 *  `AgentMetadata`; no credential material appears here, because the
 *  server's read shape has nowhere to put any. */
export interface AgentMetadata {
  vendor: string;
  purpose: string;
  contact_url: string;
  expected_user_agents: string[];
  expected_reverse_dns_suffixes: string[];
  expected_keyids: string[];
  requested_scopes: string[];
}

/** One row of the approval queue. */
export interface AgentRegistration {
  agent_id: string;
  tenant: string;
  client_id: string;
  metadata: AgentMetadata;
  state: AgentRegistrationState;
  reason: string | null;
  decided_by: string | null;
  created_at: string;
  updated_at: string;
  rotated_at: string | null;
}

/** One agent the verified catalog names. */
export interface AgentCatalogEntry {
  agent_id: string;
  vendor: string;
  purpose: string;
  expected_user_agents: string[];
  expected_reverse_dns_suffixes: string[];
  expected_keyids: string[];
  reputation_score: number;
  flags: string[];
}

/** `GET /admin/agent-registry/catalog`. */
export interface AgentCatalogResponse {
  generated_at: string | null;
  expires_at: string | null;
  expired: boolean;
  entries: AgentCatalogEntry[];
}

/** `GET /admin/agent-registry`. `feed_configured` and `bootstrap_keys` are
 *  what separate "the publisher sent nothing" from "no feed is wired up". */
export interface AgentRegistrySummary {
  /** The tenant the queue counts cover: a tenant name, or `all`. */
  scope: string;
  /** Whether this operator may read the catalog and refresh the feed. */
  catalog_writable: boolean;
  catalog_entries: number;
  catalog_generated_at: string | null;
  catalog_expires_at: string | null;
  catalog_expired: boolean;
  pending: number;
  approved: number;
  rejected: number;
  revoked: number;
  feed_configured: boolean;
  bootstrap_keys: number;
}

/** One webhook subscription. The signing secret is never here: the
 *  server's read shape has nowhere to put one. */
export interface NotifySubscription {
  subscription_id: string;
  url: string;
  event_types: string[];
  signing_key_id: string;
  active: boolean;
  /** Whether this subscription was allowed to name a wildcard that reaches
   *  the per-request lifecycle events. */
  allow_firehose: boolean;
  created_at: string;
  updated_at: string;
}

/** One delivery that ran out of attempts. */
export interface NotifyDeadLetter {
  delivery_id: string;
  subscription_id: string;
  event_id: string;
  event_type: string;
  attempts: number;
  last_status: number | null;
  last_reason: string;
  moved_at: string;
}

/** `GET /admin/notifications`. */
export interface NotifierSummary {
  subscriptions: number;
  active_subscriptions: number;
  deadletters: number;
  deadletter_capacity: number;
  max_attempts: number;
}

/** A configured RBAC operator, as reported by `/api/operators`. Never
 *  carries a password_hash. Config-only: managed by editing
 *  `proxy.admin.operators` and reloading, not through this API. */
export interface OperatorSummary {
  username: string;
  role: "admin" | "read_only";
  /** Billing tenant this login is narrowed to on the meter routes.
   *  Absent means the whole deployment. */
  tenant?: string;
}

// Windowed spend from the durable usage rollups (WOR-1875).
export interface SpendWindowBucket {
  ts_secs: number;
  group: string;
  requests: number;
  tokens_in: number;
  tokens_out: number;
  cost_usd_micros: number;
  ok: number;
  blocked: number;
  error: number;
}

export interface SpendWindowTotals {
  requests: number;
  tokens_in: number;
  tokens_out: number;
  cost_usd_micros: number;
  ok: number;
  blocked: number;
  error: number;
}

export interface SpendWindowResponse {
  from: number;
  to: number;
  group_by: string;
  bucket_secs: number;
  buckets: SpendWindowBucket[];
  totals: SpendWindowTotals;
  property_keys: string[];
}

/* ---- Attested metering (WOR-2131) ---- */

/**
 * Whether the meter is switched off, switched on and empty, or reporting.
 *
 * The distinction the whole meter view exists to make. A page of zeros
 * cannot tell "attestation is off" from "attestation is on and has
 * recorded nothing", and those have different next steps.
 */
export type MeterState = "off" | "idle" | "reporting";

/** One unit total, with its provenance kept beside the count. */
export interface MeterUnitRow {
  /** The key the row is grouped under, per the request's `group_by`. */
  group: string;
  tenant: string;
  unit: string;
  /** `measured`, `route_weight`, or `origin_header`. */
  source: string;
  count: number;
}

/** One node whose units are inside the cluster and outside the total. */
export interface MeterUncoveredNode {
  node_id: string;
  /** `never_reported`, `stale`, `not_live`, `unreachable`, `unreadable`. */
  gap: string;
  /** The last chain head this node was ever seen at, or null if never. */
  last_known_seq: number | null;
  last_seen_at: string | null;
}

/** Which nodes a cluster total covers, and which it does not. */
export interface MeterCoverage {
  complete: boolean;
  expected: number;
  answered: string[];
  uncovered: MeterUncoveredNode[];
  gathered_at: string;
}

/** One row of the per-node chain-head table. */
export interface MeterNodeRow {
  node_id: string;
  covered: boolean;
  local: boolean;
  head_seq?: number;
  head_hash?: string;
  claims?: number;
  observed_at?: string;
  gap?: string;
  last_known_seq?: number | null;
  last_seen_at?: string | null;
}

/** Records the meter owed and could not write, per tenant and posture. */
export interface MeterGapRow {
  tenant: string;
  /** `closed`, `open`, `degraded`, or `observe`. */
  failure_mode: string;
  count: number;
}

/** This node's own chain, as read from disk. */
export interface MeterChain {
  node_id: string;
  present: boolean;
  entries: number;
  head_hash: string;
  damaged_at_seq: number | null;
  damage_reason: string | null;
}

/** The attestation posture this generation runs under. */
export interface MeterAttestation {
  configured: boolean;
  role?: string;
  failure_mode?: string;
  signing_key_id?: string | null;
  ledger_path?: string;
}

export interface MeterSummary {
  schema_version: number;
  state: MeterState;
  reason: string | null;
  group_by: string;
  tenant: string | null;
  gathered_at: string;
  attestation: MeterAttestation;
  chain: MeterChain | null;
  /** Null when no mesh is configured: one chain, nothing to fan out over. */
  coverage: MeterCoverage | null;
  nodes: MeterNodeRow[];
  totals: MeterUnitRow[];
  claims: number;
  gaps: {
    total: number;
    by_tenant: MeterGapRow[];
    divergence_total: number;
  };
}

/** One receipt: the chain link, then the document the link attests to. */
export interface MeterReceipt {
  seq: number;
  recorded_at: string;
  prev_hash: string;
  entry_hash: string;
  /** Hex Ed25519 over the entry digest, when the chain is signed. */
  signature?: string;
  claims: Record<string, unknown>;
}

export interface MeterReceiptPage {
  schema_version: number;
  state: MeterState;
  reason: string | null;
  node_id: string;
  tenant: string | null;
  since_seq: number;
  limit: number;
  receipts: MeterReceipt[];
  next_since_seq: number | null;
  damaged_at_seq?: number | null;
  damage_reason?: string | null;
}

/** The verdict of one chain verification run. */
export interface MeterVerifyResult {
  schema_version: number;
  state: MeterState;
  /** `ok`, `broken`, `not_started`, or `unreadable`. */
  outcome: string;
  node_id: string;
  entries?: number;
  /** The first sequence number that failed, when the outcome is `broken`. */
  broken_seq?: number | null;
  reason?: string | null;
  verified_at: string;
}

function requestsParams(filters: RequestFilters = {}): URLSearchParams {
  const params = new URLSearchParams();
  if (filters.method) params.set("method", filters.method);
  if (filters.status && /^\d{3}$/.test(filters.status)) {
    params.set("status", filters.status);
  }
  if (filters.path) params.set("path", filters.path);
  if (filters.guardrailAction) {
    params.set("guardrail_action", filters.guardrailAction);
  }
  if (filters.guardrailCategory) {
    params.set("guardrail_category", filters.guardrailCategory);
  }
  if (filters.cacheStatus) params.set("cache_status", filters.cacheStatus);
  if (filters.retried !== undefined) {
    params.set("retried", String(filters.retried));
  }
  if (filters.propertyKey) {
    params.set("property_key", filters.propertyKey);
    if (filters.propertyValue) {
      params.set("property_value", filters.propertyValue);
    }
  }
  // WOR-2093: these three filter server-side now; the views still apply
  // the same predicates client-side so live-tail rows stay consistent.
  if (filters.sessionId) params.set("session_id", filters.sessionId);
  if (filters.apiKeyId) params.set("api_key_id", filters.apiKeyId);
  if (filters.keyMode) params.set("key_mode", filters.keyMode);
  // WOR-2578: reporting-dimension filters, shared verbatim by the
  // snapshot, the report, and the export.
  if (filters.model) params.set("model", filters.model);
  if (filters.tenant) params.set("tenant", filters.tenant);
  if (filters.user) params.set("user", filters.user);
  return params;
}

function requestsPath(filters: RequestFilters = {}): string {
  const query = requestsParams(filters).toString();
  return query ? `/api/requests?${query}` : "/api/requests";
}

// WOR-2575: routing-decisions ring query. Server-side filter params
// mirror the admin API's RoutingDecisionFilter, snake_case on the wire.
function routingDecisionsPath(filters: RoutingDecisionFilters = {}): string {
  const params = new URLSearchParams();
  if (filters.origin) params.set("origin", filters.origin);
  if (filters.strategy) params.set("strategy", filters.strategy);
  if (filters.provider) params.set("provider", filters.provider);
  if (filters.model) params.set("model", filters.model);
  if (filters.since) params.set("since", filters.since);
  if (filters.until) params.set("until", filters.until);
  if (filters.limit) params.set("limit", String(filters.limit));
  const query = params.toString();
  return query
    ? `/api/routing-decisions?${query}`
    : "/api/routing-decisions";
}

function requestsReportPath(groupBy: string[], filters: RequestFilters = {}): string {
  const params = requestsParams(filters);
  params.set("group_by", groupBy.join(","));
  return `/api/requests/report?${params.toString()}`;
}

function requestsExportPath(format: "csv" | "jsonl", filters: RequestFilters = {}): string {
  const params = requestsParams(filters);
  params.set("format", format);
  return `/api/requests/export?${params.toString()}`;
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
  /** Compression session records: the externalized context state the AI
   *  gateway keeps per conversation. Content is never included here; the
   *  detail route gates summary text behind its own audited call. */
  compressionSessions: (limit?: number, cursor?: string) => {
    const q = new URLSearchParams();
    if (limit) q.set("limit", String(limit));
    if (cursor) q.set("cursor", cursor);
    const qs = q.toString();
    return getJson<CompressionSessionPage>(
      `/admin/compression/sessions${qs ? `?${qs}` : ""}`,
    );
  },
  health: () => getJson<HealthResponse>("/health"),
  stats: () => getJson<StatsResponse>("/api/stats"),
  extensions: () => getJson<ExtensionInventorySnapshot>("/api/extensions"),
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
  modelHostLoad: (deployment: string) =>
    sendJson<unknown>("POST", "/admin/model-host/load", { deployment }),
  modelHostStop: (deployment: string) =>
    sendJson<unknown>("POST", "/admin/model-host/stop", { deployment }),
  modelHostReset: (deployment: string) =>
    sendJson<unknown>("POST", "/admin/model-host/reset", { deployment }),
  modelHostEvict: (deployment: string) =>
    sendJson<unknown>("POST", "/admin/model-host/evict", { deployment }),
  // Artifact cache storage (WOR-1910): inventory, exact delete, cache GC.
  modelHostFiles: () =>
    getJson<ModelHostFilesResponse>("/admin/model-host/files"),
  deleteModelHostArtifact: (digest: string) =>
    sendJson<ArtifactRemovalReport>(
      "DELETE",
      `/admin/model-host/artifacts/${encodeURIComponent(digest)}`,
    ),
  modelHostGc: () => sendJson<GcReport>("POST", "/admin/model-host/gc"),
  // Durable operation jobs (queued/in-flight lifecycle + pull/verify work).
  modelHostJobs: () => getJson<JobsListResponse>("/admin/model-host/jobs"),
  modelHostJob: (id: string) =>
    getJson<JobDetailResponse>(`/admin/model-host/jobs/${encodeURIComponent(id)}`),
  // SSE tail of one job's durable state, with `Last-Event-ID` replay across
  // a reconnect (the browser's EventSource resends it automatically).
  modelHostJobStreamUrl: (id: string) =>
    `/admin/model-host/jobs/${encodeURIComponent(id)}/stream`,

  // Keys
  keys: () => getJson<unknown>("/admin/keys"),
  // Typed, minimal key listing for selectors; see `AdminKeySummary` above.
  keysList: () => getJson<AdminKeysListResponse>("/admin/keys"),
  keyPolicySchema: async () =>
    decodeKeyPolicySchema(
      await getJson<unknown>("/admin/keys/policy-schema"),
    ),
  key: async (id: string) => {
    const document = await getJson<{ key: AdminKey }>(
      `/admin/keys/${encodeURIComponent(id)}`,
    );
    return document.key;
  },
  keyUsage: async (id: string) => {
    const document = await getJson<{ usage: unknown }>(
      `/admin/keys/${encodeURIComponent(id)}/usage`,
    );
    return decodeGovernanceSnapshot(document.usage);
  },
  createKey: (body: unknown) => sendJson<CreatedKey>("POST", "/admin/keys", body),
  patchKey: async (id: string, patch: AdminKeyPolicyPatch) => {
    assertKeyPolicyPatch(patch);
    const document = await sendJson<{ key: AdminKey }>(
      "PATCH",
      `/admin/keys/${encodeURIComponent(id)}`,
      patch,
    );
    return document.key;
  },
  previewKeyPolicy: async (id: string) =>
    decodeEffectivePolicyPreview(
      await sendJson<unknown>(
        "POST",
        `/admin/keys/${encodeURIComponent(id)}/effective-policy/preview`,
        {},
      ),
    ),
  keyAction: (id: string, action: "revoke" | "block" | "unblock" | "rotate") =>
    sendJson<KeyActionResult>(
      "POST",
      `/admin/keys/${encodeURIComponent(id)}/${action}`,
    ),
  // WOR-2561: temporary, auto-expiring budget overrides. The grant raises
  // the key's effective budget until `expires_at`; the base budget resumes
  // on its own after that, so clearing is only for ending a raise early.
  grantBudgetOverride: async (id: string, grant: KeyBudgetOverrideGrant) => {
    const document = await sendJson<{ key: AdminKey }>(
      "POST",
      `/admin/keys/${encodeURIComponent(id)}/budget-override`,
      grant,
    );
    return document.key;
  },
  clearBudgetOverride: async (id: string) => {
    const document = await sendJson<{ key: AdminKey }>(
      "DELETE",
      `/admin/keys/${encodeURIComponent(id)}/budget-override`,
    );
    return document.key;
  },
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
  requests: (filters: RequestFilters = {}) =>
    getJson<RequestLog[]>(requestsPath(filters)),
  // WOR-2578: multi-dimension aggregation of the same filtered ring.
  requestsReport: (groupBy: string[], filters: RequestFilters = {}) =>
    getJson<RequestReportResponse>(requestsReportPath(groupBy, filters)),
  // WOR-2578: the raw export of the filtered view, as a URL for
  // copying or a right-click save. A bare <a download> on it works,
  // but it never enters `request()`'s failure handling, so a lapsed
  // session saves `{"error":"Unauthorized"}` under the name
  // `requests.csv` with nothing on screen; the console clicks through
  // `requestsExport` below instead.
  requestsExportUrl: (format: "csv" | "jsonl", filters: RequestFilters = {}) =>
    requestsExportPath(format, filters),
  // The same bytes through the typed client, so a 401 routes the
  // operator to sign-in and any other status renders as an error
  // rather than as a downloaded file. Bounded server-side by
  // `proxy.admin.max_log_entries`, which is what makes holding the
  // response acceptable here.
  requestsExport: (format: "csv" | "jsonl", filters: RequestFilters = {}) =>
    getText(requestsExportPath(format, filters)),
  // WOR-1870: operator UI settings (trace deep-link template).
  uiSettings: () => getJson<UiSettings>("/api/ui-settings"),
  // WOR-1870: SSE live tail of the request ring. EventSource sends the
  // session cookie same-origin; the server enforces auth on connect.
  requestsStreamUrl: () => "/api/requests/stream",
  // WOR-2575: recent routing decisions ("why was this request routed
  // here"), newest first from the in-memory ring.
  routingDecisions: (filters: RoutingDecisionFilters = {}) =>
    getJson<RoutingDecision[]>(routingDecisionsPath(filters)),
  // WOR-2588: parked MCP Confirm / approval.tools holds.
  mcpApprovals: () => getJson<McpApprovalsResponse>("/api/mcp/approvals"),
  approveMcpHold: (id: string, approvedBy: string) =>
    sendJson<McpHold>(
      "POST",
      `/api/mcp/approvals/${encodeURIComponent(id)}/approve`,
      { approved_by: approvedBy },
    ),
  denyMcpHold: (id: string, approvedBy: string) =>
    sendJson<McpHold>(
      "POST",
      `/api/mcp/approvals/${encodeURIComponent(id)}/deny`,
      { approved_by: approvedBy },
    ),

  // WOR-2094: unified audit sample (security/key/config/admin/policy).
  auditEvents: (filters: AuditEventFilters = {}) => {
    const params = new URLSearchParams();
    if (filters.limit) params.set("limit", String(filters.limit));
    if (filters.channel) params.set("channel", filters.channel);
    if (filters.kind) params.set("kind", filters.kind);
    if (filters.keyId) params.set("key_id", filters.keyId);
    const query = params.toString();
    return getJson<AuditEvent[]>(
      query ? `/api/audit/events?${query}` : "/api/audit/events",
    );
  },
  // WOR-2579: the durable, tamper-evident chains, read with verification.
  // Without a channel the response merges the newest window across every
  // enabled chain; `beforeSeq` pages one channel further back.
  auditChain: (filters: AuditChainFilters = {}) => {
    const params = new URLSearchParams();
    if (filters.channel) params.set("channel", filters.channel);
    if (filters.actor) params.set("actor", filters.actor);
    if (filters.since) params.set("since", filters.since);
    if (filters.until) params.set("until", filters.until);
    if (filters.beforeSeq !== undefined)
      params.set("before_seq", String(filters.beforeSeq));
    if (filters.limit) params.set("limit", String(filters.limit));
    const query = params.toString();
    return getJson<AuditChainResponse>(
      query ? `/api/audit/chain?${query}` : "/api/audit/chain",
    );
  },
  // WOR-2096: one request's redacted content sample (admin role only;
  // the server audits every read).
  requestContent: (requestId: string) =>
    getJson<ContentSample>(
      `/api/requests/${encodeURIComponent(requestId)}/content`,
    ),

  // File-authoritative alert runtime state and targeted channel probes.
  alerts: () => getJson<AlertSnapshot>("/api/alerts"),
  testAlertChannel: async (channelIndex: number): Promise<void> => {
    await sendJson("POST", "/api/alerts/test", { channel_index: channelIndex });
  },

  // Metrics
  metrics: () => getText("/metrics"),
  // Who can sign in to this console. Passwords are never returned;
  // accounts are managed in config, not through this route.
  adminUsers: () => getJson<AdminUsersResponse>("/api/admin/users"),
  // Configured RBAC operators only (excludes the top-level admin
  // credential). password_hash is never returned.
  operators: () => getJson<OperatorSummary[]>("/api/operators"),

  // Agent registry (WOR-2664). Every one of these is 404 when
  // `proxy.agent_registry` is absent or disabled, which is what the view
  // renders as "not configured" rather than as an error.
  agentRegistrySummary: () =>
    getJson<AgentRegistrySummary>("/admin/agent-registry"),
  agentRegistryCatalog: () =>
    getJson<AgentCatalogResponse>("/admin/agent-registry/catalog"),
  agentRegistryRefresh: () =>
    sendJson<{ entries: number }>("POST", "/admin/agent-registry/refresh"),
  agentRegistrations: (state?: AgentRegistrationState) =>
    getJson<{ items: AgentRegistration[] }>(
      state
        ? `/admin/agent-registry/registrations?state=${encodeURIComponent(state)}`
        : "/admin/agent-registry/registrations",
    ),
  // The reason is optional on approve and revoke and required on reject;
  // the server enforces that, and the view disables the button rather than
  // letting an operator discover it from a 400.
  agentRegistrationDecide: (
    agentId: string,
    decision: "approve" | "reject" | "revoke",
    reason?: string,
  ) =>
    sendJson<AgentRegistration>(
      "POST",
      `/admin/agent-registry/registrations/${encodeURIComponent(agentId)}/${decision}`,
      reason ? { reason } : {},
    ),

  // Outbound webhook notifications (WOR-2669). 404 when
  // `proxy.notifications` is absent or disabled.
  notifySummary: () => getJson<NotifierSummary>("/admin/notifications"),
  notifySubscriptions: () =>
    getJson<{ items: NotifySubscription[] }>("/admin/notifications/subscriptions"),
  // The signing secret is in this response and in no other. The view shows
  // it once and does not store it.
  notifyCreateSubscription: (
    url: string,
    eventTypes: string[],
    allowFirehose = false,
  ) =>
    sendJson<{ subscription: NotifySubscription; signing_secret: string }>(
      "POST",
      "/admin/notifications/subscriptions",
      { url, event_types: eventTypes, allow_firehose: allowFirehose },
    ),
  notifySetActive: (subscriptionId: string, active: boolean) =>
    sendJson<NotifySubscription>(
      "PATCH",
      `/admin/notifications/subscriptions/${encodeURIComponent(subscriptionId)}`,
      { active },
    ),
  notifyRotate: (subscriptionId: string) =>
    sendJson<{ subscription: NotifySubscription; signing_secret: string }>(
      "POST",
      `/admin/notifications/subscriptions/${encodeURIComponent(subscriptionId)}/rotate`,
    ),
  notifyDeleteSubscription: (subscriptionId: string) =>
    sendJson<{ deleted: boolean }>(
      "DELETE",
      `/admin/notifications/subscriptions/${encodeURIComponent(subscriptionId)}`,
    ),
  // Paged, oldest first. The records carry no event body: the queue holds
  // up to 10,000 of them and this is re-fetched after every action.
  notifyDeadletters: (after?: string, limit = 50) => {
    const params = new URLSearchParams({ limit: String(limit) });
    if (after) params.set("after", after);
    return getJson<{ items: NotifyDeadLetter[]; next: string | null }>(
      `/admin/notifications/deadletters?${params.toString()}`,
    );
  },
  notifyReplay: (deliveryId: string) =>
    sendJson<{ event_id: string; replayed: boolean }>(
      "POST",
      `/admin/notifications/deadletters/${encodeURIComponent(deliveryId)}/replay`,
    ),
  // How a record whose stored event no longer deserializes leaves the
  // queue: a replay of one refuses before it would have been removed.
  notifyDiscardDeadletter: (deliveryId: string) =>
    sendJson<{ deleted: boolean }>(
      "DELETE",
      `/admin/notifications/deadletters/${encodeURIComponent(deliveryId)}`,
    ),

  // Attested metering (WOR-2131). All three are tenant-scoped server-side
  // from the authenticated operator; passing `tenant` narrows further and
  // is refused with 403 when it names somebody the operator may not read.
  meterSummary: (groupBy = "tenant", tenant?: string) => {
    const params = new URLSearchParams({ group_by: groupBy });
    if (tenant) params.set("tenant", tenant);
    return getJson<MeterSummary>(`/api/meter/summary?${params.toString()}`);
  },
  meterReceipts: (sinceSeq = 0, tenant?: string, limit?: number) => {
    const params = new URLSearchParams({ since_seq: String(sinceSeq) });
    if (tenant) params.set("tenant", tenant);
    if (limit) params.set("limit", String(limit));
    return getJson<MeterReceiptPage>(`/api/meter/receipts?${params.toString()}`);
  },
  // A POST because it walks the whole chain file. The connection handler's
  // RBAC gate therefore restricts it to the admin role.
  meterVerify: () => sendJson<MeterVerifyResult>("POST", "/api/meter/verify"),

  // Windowed spend history from the durable rollups (WOR-1875).
  spendWindow: (window: string, groupBy: string) =>
    getJson<SpendWindowResponse>(
      `/api/usage/spend?window=${encodeURIComponent(window)}&group_by=${encodeURIComponent(groupBy)}`,
    ),
  /**
   * The same rollup query over an explicit range, in Unix seconds.
   *
   * `window=` only ever means "ending now", so the prior equal-length
   * period, which is what turns a total into a change, is unreachable
   * through it. The server takes `from`/`to` on the same route and
   * requires `from < to`; anything else is a 400.
   */
  spendRange: (fromSecs: number, toSecs: number, groupBy: string) =>
    getJson<SpendWindowResponse>(
      `/api/usage/spend?from=${Math.floor(fromSecs)}&to=${Math.floor(toSecs)}` +
        `&group_by=${encodeURIComponent(groupBy)}`,
    ),

  // Prompts
  prompts: () => getJson<unknown>("/admin/prompts"),
  addPromptVersion: (
    host: string,
    name: string,
    // Typed to the endpoint's AddVersionBody so a field rename on either
    // side fails the typecheck lane instead of 400ing at runtime.
    body: { version: string; template: string; variables?: Record<string, unknown> },
  ) =>
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
  // Ungoverned engine call, kept for scripting only: the server refuses
  // it unless the body carries `bypass_governance: true`, and audits
  // every completion. The UI does not call this.
  playgroundChat: (body: PlaygroundChatRequest) =>
    sendJson<PlaygroundChatResult>("POST", "/admin/api/playground/chat", body),
  // Real dispatch: runs the request through the actual data-plane pipeline
  // for a chosen virtual key (key policy, governance, routing, and
  // guardrails all apply), rather than calling the engine/AiClient
  // directly the way `playgroundChat` above does.
  playgroundDispatch: (body: PlaygroundDispatchRequest) =>
    sendJson<PlaygroundChatResult>("POST", "/admin/api/playground/dispatch", body),

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

  // What is actually running, and who owns each part of it. `config` above
  // returns this node's own file, which on a git-sourced node is nothing
  // but the pointer that selected the repository.
  effectiveConfig: () =>
    getJson<EffectiveConfigResponse>("/admin/config/effective"),

  // The config JSON Schema, generated from the running binary's own types.
  // Around 300KB, so it is fetched once per page load and not per edit.
  configSchema: () => getJson<Record<string, unknown>>("/admin/config/schema"),

  // Durable config revision history (WOR-2456/2457): the applied/good/
  // failed/reverted timeline behind the LKG rollback store. Opt-in, so a
  // 404 here commonly means proxy.config_history.enabled is off rather
  // than a real failure.
  configHistory: () => getJson<ConfigHistoryResponse>("/admin/config/history"),
  configHistoryEntry: (digest: string) =>
    getJson<ConfigHistoryDetail>(
      `/admin/config/history/${encodeURIComponent(digest)}`,
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
  clusterVram: () => getJson<ClusterVramResponse>("/admin/cluster/vram"),

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
