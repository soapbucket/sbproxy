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
    headers: { Accept: "application/json" },
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
  provider?: string;
  model?: string;
  tokens_in?: number;
  tokens_out?: number;
  cost_usd_micros?: number;
  guardrail_category?: string;
  guardrail_action?: string;
  origin?: string;
  [k: string]: unknown;
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

  // Keys
  keys: () => getJson<unknown>("/admin/keys"),
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
  // WOR-1870: operator UI settings (trace deep-link template).
  uiSettings: () => getJson<UiSettings>("/api/ui-settings"),
  // WOR-1870: SSE live tail of the request ring. EventSource sends the
  // session cookie same-origin; the server enforces auth on connect.
  requestsStreamUrl: () => "/api/requests/stream",

  // Metrics
  metrics: () => getText("/metrics"),
  // Windowed spend history from the durable rollups (WOR-1875).
  spendWindow: (window: string, groupBy: string) =>
    getJson<SpendWindowResponse>(
      `/api/usage/spend?window=${encodeURIComponent(window)}&group_by=${encodeURIComponent(groupBy)}`,
    ),

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
