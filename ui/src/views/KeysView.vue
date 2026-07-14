<script setup lang="ts">
import { computed, onMounted, reactive, ref } from "vue";
import {
  api,
  asList,
  ApiError,
  buildKeyPolicyPatch,
  keyPolicyDraft,
  rebaseKeyPolicyDraft,
  type AdminKey,
  type AdminKeyPolicyPatch,
  type EffectivePolicyDecisionName,
  type EffectivePolicyPreview,
  type KeyPolicyDraft,
} from "../api";
import { useAsync } from "../composables/useAsync";
import { formatUsd, formatTime, shortId } from "../lib/format";
import PageHeader from "../components/PageHeader.vue";
import StatusBadge from "../components/StatusBadge.vue";
import ErrorState from "../components/ErrorState.vue";
import EmptyState from "../components/EmptyState.vue";
import ModalDialog from "../components/ModalDialog.vue";
import CopyText from "../components/CopyText.vue";

const keysReq = useAsync(() => api.keys());
const keys = computed<AdminKey[]>(() => asList<AdminKey>(keysReq.data.value, "keys", "items", "data"));
const policySchemaReq = useAsync(() => api.keyPolicySchema());

onMounted(() => {
  void keysReq.run();
  void policySchemaReq.run();
});

// ---- helpers ----
function keyId(k: AdminKey): string {
  return String(k.id ?? k.key_id ?? k.prefix ?? k.name ?? "");
}
function toList(s: string): string[] {
  return s
    .split(/[,\n]/)
    .map((x) => x.trim())
    .filter(Boolean);
}
function fromList(v: unknown): string {
  return Array.isArray(v) ? v.join(", ") : "";
}
function budgetOf(k: AdminKey): number | undefined {
  return keyPolicyDraft(k).max_budget_usd ?? undefined;
}
function allowedToolsOf(k: AdminKey): string[] | null {
  return keyPolicyDraft(k).allowed_tools;
}
function supportsPolicyField(wireName: string, patchField = wireName): boolean {
  return (
    policySchemaReq.data.value?.fields.some(
      (field) =>
        field.wire_name === wireName &&
        field.mutation.kind === "patch" &&
        field.mutation.fields.includes(patchField),
    ) ?? false
  );
}
function supportsPolicyAction(action: "block" | "unblock" | "revoke"): boolean {
  return (
    policySchemaReq.data.value?.fields.some(
      (field) =>
        field.wire_name === "status" &&
        field.mutation.kind === "action" &&
        field.mutation.fields.includes(action),
    ) ?? false
  );
}
function jsonText(v: unknown): string {
  if (!Array.isArray(v) || v.length === 0) return "";
  return JSON.stringify(v, null, 2);
}
function parseJsonArray(s: string): unknown[] | undefined {
  if (!s.trim()) return undefined;
  const parsed = JSON.parse(s);
  if (!Array.isArray(parsed)) throw new Error("Expected a JSON array.");
  return parsed;
}
function jsonObjectText(v: unknown): string {
  if (!v || typeof v !== "object" || Array.isArray(v)) return "";
  return JSON.stringify(v, null, 2);
}
function parseJsonObject(s: string): Record<string, unknown> | undefined {
  if (!s.trim()) return undefined;
  const parsed = JSON.parse(s);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("Expected a JSON object.");
  }
  return parsed as Record<string, unknown>;
}
// Metadata is edited as one `key = value` pair per line.
function metadataText(v: unknown): string {
  if (!v || typeof v !== "object" || Array.isArray(v)) return "";
  return Object.entries(v as Record<string, string>)
    .map(([k, val]) => `${k} = ${val}`)
    .join("\n");
}
function parseMetadata(s: string): Record<string, string> | undefined {
  const lines = s
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean);
  if (!lines.length) return undefined;
  const out: Record<string, string> = {};
  for (const line of lines) {
    const eq = line.indexOf("=");
    if (eq < 1) throw new Error(`Metadata line "${line}" is not "key = value".`);
    out[line.slice(0, eq).trim()] = line.slice(eq + 1).trim();
  }
  return out;
}
function parseOptionalNumber(
  value: string,
  label: string,
  integer = false,
): number | null {
  const trimmed = value.trim();
  if (!trimmed) return null;
  const parsed = Number(trimmed);
  if (
    !Number.isFinite(parsed) ||
    parsed < 0 ||
    (integer && !Number.isSafeInteger(parsed))
  ) {
    throw new Error(`${label} must be a non-negative ${integer ? "integer" : "number"}.`);
  }
  return parsed;
}
const PRIORITY_LANES = ["interactive", "standard", "batch"] as const;

// ---- create ----
const showCreate = ref(false);
const createForm = reactive({
  name: "",
  allowed_models: "",
  blocked_models: "",
  allowed_providers: "",
  blocked_providers: "",
  allowed_tools_mode: "unrestricted" as "unrestricted" | "allowlist",
  allowed_tools: "",
  require_pii_redaction: "",
  route_to_model: "",
  max_requests_per_minute: "",
  max_tokens_per_minute: "",
  priority: "",
  max_budget_tokens: "",
  budget_usd: "",
  project: "",
  user: "",
  tenant_id: "",
  bypass_prompt_injection: false,
  principal_selectors: "",
  inject_tools: "",
  inject_mcp: "",
  metadata: "",
  tags: "",
  expires_at: "",
});
const createBusy = ref(false);
const createError = ref<ApiError | null>(null);
const createdToken = ref<string | null>(null);
const createdMeta = ref<AdminKey | null>(null);

function resetCreate() {
  Object.assign(createForm, {
    name: "",
    allowed_models: "",
    blocked_models: "",
    allowed_providers: "",
    blocked_providers: "",
    allowed_tools_mode: "unrestricted",
    allowed_tools: "",
    require_pii_redaction: "",
    route_to_model: "",
    max_requests_per_minute: "",
    max_tokens_per_minute: "",
    priority: "",
    max_budget_tokens: "",
    budget_usd: "",
    project: "",
    user: "",
    tenant_id: "",
    bypass_prompt_injection: false,
    principal_selectors: "",
    inject_tools: "",
    inject_mcp: "",
    metadata: "",
    tags: "",
    expires_at: "",
  });
  createError.value = null;
}

function buildPolicy(f: typeof createForm) {
  const policy: Record<string, unknown> = {};
  if (f.allowed_models) policy.allowed_models = toList(f.allowed_models);
  if (f.blocked_models) policy.blocked_models = toList(f.blocked_models);
  if (f.allowed_providers) policy.allowed_providers = toList(f.allowed_providers);
  if (f.blocked_providers) policy.blocked_providers = toList(f.blocked_providers);
  if (f.allowed_tools_mode === "allowlist") {
    policy.allowed_tools = toList(f.allowed_tools);
  }
  if (f.require_pii_redaction) policy.require_pii_redaction = toList(f.require_pii_redaction);
  if (f.route_to_model) policy.route_to_model = f.route_to_model.trim();
  if (f.max_requests_per_minute && !Number.isNaN(Number(f.max_requests_per_minute))) {
    policy.max_requests_per_minute = Number(f.max_requests_per_minute);
  }
  if (f.max_tokens_per_minute && !Number.isNaN(Number(f.max_tokens_per_minute))) {
    policy.max_tokens_per_minute = Number(f.max_tokens_per_minute);
  }
  if (f.priority) policy.priority = f.priority;
  if (f.max_budget_tokens && !Number.isNaN(Number(f.max_budget_tokens))) {
    policy.max_budget_tokens = Number(f.max_budget_tokens);
  }
  if (f.budget_usd && !Number.isNaN(Number(f.budget_usd))) {
    policy.max_budget_usd = Number(f.budget_usd);
  }
  if (f.project) policy.project = f.project.trim();
  if (f.user) policy.user = f.user.trim();
  if (f.tenant_id) policy.tenant = f.tenant_id.trim();
  if (f.bypass_prompt_injection) policy.bypass_prompt_injection = true;
  const principalSelectors = parseJsonArray(f.principal_selectors);
  if (principalSelectors) policy.principal_selectors = principalSelectors;
  const injectTools = parseJsonArray(f.inject_tools);
  if (injectTools) policy.inject_tools = injectTools;
  const injectMcp = parseJsonObject(f.inject_mcp);
  if (injectMcp) policy.inject_mcp = injectMcp;
  const metadata = parseMetadata(f.metadata);
  if (metadata) policy.metadata = metadata;
  if (f.tags) policy.tags = toList(f.tags);
  return policy;
}

async function submitCreate() {
  createBusy.value = true;
  createError.value = null;
  try {
    const body: Record<string, unknown> = buildPolicy(createForm);
    if (createForm.name) body.name = createForm.name;
    if (createForm.tags) body.tags = toList(createForm.tags);
    if (createForm.expires_at) body.expires_at = createForm.expires_at;
    const created = await api.createKey(body);
    const token = created.token;
    createdMeta.value = created.key;
    showCreate.value = false;
    resetCreate();
    if (token) {
      createdToken.value = token;
    }
    keysReq.run();
  } catch (e) {
    createError.value = e instanceof ApiError ? e : new ApiError(0, String(e));
  } finally {
    createBusy.value = false;
  }
}

// ---- edit policy ----
const editBaseline = ref<AdminKey | null>(null);
const editForm = reactive({
  name: "",
  expires_at: "",
  allowed_models: "",
  blocked_models: "",
  allowed_providers: "",
  blocked_providers: "",
  allowed_tools_mode: "unrestricted" as "unrestricted" | "allowlist",
  allowed_tools: "",
  require_pii_redaction: "",
  route_to_model: "",
  max_requests_per_minute: "",
  max_tokens_per_minute: "",
  priority: "",
  max_budget_tokens: "",
  budget_usd: "",
  project: "",
  user: "",
  tenant_id: "",
  bypass_prompt_injection: false,
  principal_selectors: "",
  inject_tools: "",
  inject_mcp: "",
  metadata: "",
  tags: "",
});
const editBusy = ref(false);
const editError = ref<ApiError | null>(null);
const conflictDetected = ref(false);
const conflictBusy = ref(false);
const conflictCurrent = ref<AdminKey | null>(null);
const conflictError = ref<ApiError | null>(null);
const pendingLocalPatch = ref<AdminKeyPolicyPatch | null>(null);
const preview = ref<EffectivePolicyPreview | null>(null);
const previewBusy = ref(false);
const previewError = ref<ApiError | null>(null);
let previewInvocation = 0;

const PREVIEW_DECISIONS: readonly [EffectivePolicyDecisionName, string][] = [
  ["lifecycle", "Lifecycle"],
  ["tenant", "Tenant"],
  ["model", "Model"],
  ["provider", "Provider"],
  ["tools", "Caller tools"],
  ["principal", "Principal"],
  ["rate_limits", "Rate limits"],
  ["budget", "Budget"],
  ["priority", "Priority"],
  ["guardrails", "Guardrails"],
];
const previewDecisionRows = computed(() => {
  if (!preview.value) return [];
  return PREVIEW_DECISIONS.flatMap(([name, label]) => {
    const decision = preview.value?.decisions[name];
    return decision
      ? [
          {
            name,
            label,
            allowed: decision.allowed,
            reasonCode:
              decision.reason_code ?? (decision.allowed ? "allowed" : "denied"),
          },
        ]
      : [];
  });
});

async function loadPreview(key = editBaseline.value) {
  if (!key) return;
  const invocation = ++previewInvocation;
  previewBusy.value = true;
  preview.value = null;
  previewError.value = null;
  try {
    const loaded = await api.previewKeyPolicy(keyId(key));
    if (invocation !== previewInvocation) return;
    preview.value = loaded;
  } catch (e) {
    if (invocation !== previewInvocation) return;
    preview.value = null;
    previewError.value =
      e instanceof ApiError ? e : new ApiError(0, String(e));
  } finally {
    if (invocation === previewInvocation) previewBusy.value = false;
  }
}

function clearConflict() {
  conflictDetected.value = false;
  conflictCurrent.value = null;
  conflictError.value = null;
  pendingLocalPatch.value = null;
}

function fillEditForm(draft: KeyPolicyDraft) {
  Object.assign(editForm, {
    name: draft.name ?? "",
    expires_at: draft.expires_at ?? "",
    allowed_models: fromList(draft.allowed_models),
    blocked_models: fromList(draft.blocked_models),
    allowed_providers: fromList(draft.allowed_providers),
    blocked_providers: fromList(draft.blocked_providers),
    allowed_tools_mode:
      draft.allowed_tools === null ? "unrestricted" : "allowlist",
    allowed_tools: fromList(draft.allowed_tools ?? []),
    require_pii_redaction: fromList(draft.require_pii_redaction),
    route_to_model: draft.route_to_model ?? "",
    max_requests_per_minute:
      draft.max_requests_per_minute === null
        ? ""
        : String(draft.max_requests_per_minute),
    max_tokens_per_minute:
      draft.max_tokens_per_minute === null
        ? ""
        : String(draft.max_tokens_per_minute),
    priority: draft.priority ?? "",
    max_budget_tokens:
      draft.max_budget_tokens === null ? "" : String(draft.max_budget_tokens),
    budget_usd:
      draft.max_budget_usd === null ? "" : String(draft.max_budget_usd),
    project: draft.project ?? "",
    user: draft.user ?? "",
    tenant_id: draft.tenant_id ?? "",
    bypass_prompt_injection: draft.bypass_prompt_injection,
    principal_selectors: jsonText(draft.principal_selectors),
    inject_tools: jsonText(draft.inject_tools),
    inject_mcp: jsonObjectText(draft.inject_mcp),
    metadata: metadataText(draft.metadata),
    tags: fromList(draft.tags),
  });
}

function draftFromEditForm(): KeyPolicyDraft {
  return {
    name: editForm.name.trim() || null,
    expires_at: editForm.expires_at.trim() || null,
    allowed_models: toList(editForm.allowed_models),
    blocked_models: toList(editForm.blocked_models),
    allowed_providers: toList(editForm.allowed_providers),
    blocked_providers: toList(editForm.blocked_providers),
    allowed_tools:
      editForm.allowed_tools_mode === "unrestricted"
        ? null
        : toList(editForm.allowed_tools),
    require_pii_redaction: toList(editForm.require_pii_redaction),
    route_to_model: editForm.route_to_model.trim() || null,
    max_requests_per_minute: parseOptionalNumber(
      editForm.max_requests_per_minute,
      "Requests per minute",
      true,
    ),
    max_tokens_per_minute: parseOptionalNumber(
      editForm.max_tokens_per_minute,
      "Tokens per minute",
      true,
    ),
    priority: editForm.priority || null,
    max_budget_tokens: parseOptionalNumber(
      editForm.max_budget_tokens,
      "Budget tokens",
      true,
    ),
    max_budget_usd: parseOptionalNumber(editForm.budget_usd, "Budget USD"),
    project: editForm.project.trim() || null,
    user: editForm.user.trim() || null,
    tenant_id: editForm.tenant_id.trim() || null,
    bypass_prompt_injection: editForm.bypass_prompt_injection,
    principal_selectors: parseJsonArray(editForm.principal_selectors) ?? [],
    inject_tools: parseJsonArray(editForm.inject_tools) ?? [],
    inject_mcp: parseJsonObject(editForm.inject_mcp) ?? null,
    metadata: parseMetadata(editForm.metadata) ?? {},
    tags: toList(editForm.tags),
  };
}

function openEdit(k: AdminKey) {
  editBaseline.value = k;
  editError.value = null;
  clearConflict();
  fillEditForm(keyPolicyDraft(k));
  void loadPreview(k);
}

function closeEdit() {
  previewInvocation += 1;
  editBaseline.value = null;
  editError.value = null;
  previewBusy.value = false;
  preview.value = null;
  previewError.value = null;
  clearConflict();
}

async function refetchConflict() {
  if (!editBaseline.value) return;
  conflictBusy.value = true;
  conflictError.value = null;
  try {
    const current = await api.key(keyId(editBaseline.value));
    conflictCurrent.value = current;
    await loadPreview(current);
    void keysReq.run();
  } catch (e) {
    conflictError.value =
      e instanceof ApiError ? e : new ApiError(0, String(e));
  } finally {
    conflictBusy.value = false;
  }
}

function rebasePreservedEdits() {
  if (!conflictCurrent.value || !pendingLocalPatch.value) return;
  const current = conflictCurrent.value;
  const rebased = rebaseKeyPolicyDraft(current, pendingLocalPatch.value);
  editBaseline.value = current;
  fillEditForm(rebased);
  editError.value = null;
  clearConflict();
}

function loadCurrentPolicy() {
  if (!conflictCurrent.value) return;
  const current = conflictCurrent.value;
  openEdit(current);
}

async function submitEdit() {
  if (!editBaseline.value) return;
  editBusy.value = true;
  editError.value = null;
  let patch: AdminKeyPolicyPatch | null = null;
  try {
    const baseline = editBaseline.value;
    patch = buildKeyPolicyPatch(baseline, draftFromEditForm());
    if (Object.keys(patch).length === 1) {
      closeEdit();
      return;
    }
    await api.patchKey(keyId(baseline), patch);
    closeEdit();
    void keysReq.run();
  } catch (e) {
    if (e instanceof ApiError && e.status === 409 && patch) {
      pendingLocalPatch.value = patch;
      conflictDetected.value = true;
      editError.value = null;
      await refetchConflict();
    } else {
      editError.value =
        e instanceof ApiError ? e : new ApiError(400, String(e));
    }
  } finally {
    editBusy.value = false;
  }
}

// ---- row actions ----
const rowBusy = ref<string | null>(null);
const actionError = ref<string | null>(null);

async function doAction(
  k: AdminKey,
  action: "revoke" | "block" | "unblock" | "rotate",
) {
  const id = keyId(k);
  if (action === "revoke" && !confirm(`Revoke key ${id}? This cannot be undone.`)) return;
  rowBusy.value = id + action;
  actionError.value = null;
  try {
    await api.keyAction(id, action);
    keysReq.run();
  } catch (e) {
    actionError.value = e instanceof ApiError ? `${action}: ${e.hint}` : String(e);
  } finally {
    rowBusy.value = null;
  }
}

async function doDelete(k: AdminKey) {
  const id = keyId(k);
  if (!confirm(`Delete key ${id}? This permanently removes it.`)) return;
  rowBusy.value = id + "delete";
  actionError.value = null;
  try {
    await api.deleteKey(id);
    keysReq.run();
  } catch (e) {
    actionError.value = e instanceof ApiError ? `delete: ${e.hint}` : String(e);
  } finally {
    rowBusy.value = null;
  }
}

function statusOf(k: AdminKey): string {
  if (k.revoked) return "revoked";
  if (k.blocked) return "blocked";
  return String(k.status ?? k.state ?? "active");
}
</script>

<template>
  <PageHeader
    title="Keys"
    subtitle="API keys and their policy: allowed and blocked models and providers, budget, tags, and expiry."
  >
    <template #actions>
      <button class="sb-btn" @click="keysReq.run">Refresh</button>
      <button
        class="sb-btn sb-btn--primary"
        :disabled="!policySchemaReq.succeeded.value"
        title="Policy controls load from the running server"
        @click="showCreate = true"
      >
        Create key
      </button>
    </template>
  </PageHeader>

  <p class="notice" v-if="actionError">{{ actionError }}</p>
  <ErrorState
    v-if="policySchemaReq.error.value"
    :error="policySchemaReq.error.value"
    title="Policy controls unavailable"
    @retry="policySchemaReq.run"
  />
  <p v-else-if="policySchemaReq.loading.value" class="sb-faint" aria-live="polite">
    Loading policy controls from this server...
  </p>

  <ErrorState v-if="keysReq.error.value" :error="keysReq.error.value" @retry="keysReq.run" />
  <EmptyState v-else-if="!keys.length" message="No keys yet.">
    <button
      class="sb-btn sb-btn--primary"
      :disabled="!policySchemaReq.succeeded.value"
      @click="showCreate = true"
    >
      Create the first key
    </button>
  </EmptyState>

  <div class="table-wrap" v-else>
    <table class="sb-table">
      <thead>
        <tr>
          <th>Key</th>
          <th>Status</th>
          <th>Policy</th>
          <th>Budget</th>
          <th>Expiry</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="(k, i) in keys" :key="i">
          <td>
            <div class="kname">{{ k.name ?? k.label ?? "(unnamed)" }}</div>
            <div class="sb-id">{{ shortId(keyId(k)) }}</div>
            <div class="policy-evidence">
              Policy revision <span class="sb-mono">{{ k.policy_revision }}</span>
              <template v-if="k.policy_digest">
                <span aria-hidden="true"> / </span>
                digest <span class="sb-mono digest">{{ k.policy_digest }}</span>
              </template>
              <template v-else-if="!k.tenant_id">
                <span aria-hidden="true"> / </span>
                digest is origin-scoped
              </template>
            </div>
            <div class="tags" v-if="(k.tags ?? k.policy?.tags)?.length">
              <span class="tag" v-for="t in (k.tags ?? k.policy?.tags)" :key="t">{{ t }}</span>
            </div>
          </td>
          <td>
            <StatusBadge :label="statusOf(k)" />
            <div v-if="k.rotation_pending" style="margin-top: 4px">
              <StatusBadge label="rotation pending" tone="warn" />
            </div>
          </td>
          <td class="policy">
            <div v-if="(k.allowed_models ?? k.policy?.allowed_models)?.length" class="pol">
              <span class="pol__k">allow models</span>
              <span class="sb-mono">{{ (k.allowed_models ?? k.policy?.allowed_models)?.join(", ") }}</span>
            </div>
            <div v-if="(k.blocked_models ?? k.policy?.blocked_models)?.length" class="pol">
              <span class="pol__k pol__k--block">block models</span>
              <span class="sb-mono">{{ (k.blocked_models ?? k.policy?.blocked_models)?.join(", ") }}</span>
            </div>
            <div v-if="(k.allowed_providers ?? k.policy?.allowed_providers)?.length" class="pol">
              <span class="pol__k">allow providers</span>
              <span class="sb-mono">{{ (k.allowed_providers ?? k.policy?.allowed_providers)?.join(", ") }}</span>
            </div>
            <div v-if="(k.blocked_providers ?? k.policy?.blocked_providers)?.length" class="pol">
              <span class="pol__k pol__k--block">block providers</span>
              <span class="sb-mono">{{ (k.blocked_providers ?? k.policy?.blocked_providers)?.join(", ") }}</span>
            </div>
            <div v-if="allowedToolsOf(k) !== null" class="pol">
              <span class="pol__k">allow tools</span>
              <span class="sb-mono">
                {{ allowedToolsOf(k)?.length ? allowedToolsOf(k)?.join(", ") : "none" }}
              </span>
            </div>
            <div v-if="k.route_to_model ?? k.policy?.route_to_model" class="pol">
              <span class="pol__k">pin model</span>
              <span class="sb-mono">{{ k.route_to_model ?? k.policy?.route_to_model }}</span>
            </div>
            <div v-if="(k.require_pii_redaction ?? k.policy?.require_pii_redaction)?.length" class="pol">
              <span class="pol__k">redact</span>
              <span class="sb-mono">{{ (k.require_pii_redaction ?? k.policy?.require_pii_redaction)?.join(", ") }}</span>
            </div>
            <div v-if="k.max_requests_per_minute" class="pol">
              <span class="pol__k">rpm</span>
              <span class="sb-mono">{{ k.max_requests_per_minute }}</span>
            </div>
            <div v-if="k.max_tokens_per_minute" class="pol">
              <span class="pol__k">tpm</span>
              <span class="sb-mono">{{ k.max_tokens_per_minute }}</span>
            </div>
            <div v-if="k.priority ?? k.policy?.priority" class="pol">
              <span class="pol__k">priority</span>
              <span class="sb-mono">{{ k.priority ?? k.policy?.priority }}</span>
            </div>
            <div v-if="k.inject_mcp ?? k.policy?.inject_mcp" class="pol">
              <span class="pol__k">mcp tools</span>
              <span class="sb-mono">{{ (k.inject_mcp as any)?.ref ?? "injected" }}</span>
            </div>
            <div v-if="k.bypass_prompt_injection ?? k.policy?.bypass_prompt_injection" class="pol">
              <span class="pol__k pol__k--block">prompt scan</span>
              <span class="sb-mono">bypassed</span>
            </div>
            <span
              class="sb-faint"
              v-if="
                !(k.allowed_models ?? k.policy?.allowed_models)?.length &&
                !(k.blocked_models ?? k.policy?.blocked_models)?.length &&
                !(k.allowed_providers ?? k.policy?.allowed_providers)?.length &&
                !(k.blocked_providers ?? k.policy?.blocked_providers)?.length &&
                allowedToolsOf(k) === null &&
                !(k.route_to_model ?? k.policy?.route_to_model) &&
                !(k.require_pii_redaction ?? k.policy?.require_pii_redaction)?.length &&
                !k.max_requests_per_minute &&
                !k.max_tokens_per_minute &&
                !(k.priority ?? k.policy?.priority) &&
                !(k.inject_mcp ?? k.policy?.inject_mcp) &&
                !(k.bypass_prompt_injection ?? k.policy?.bypass_prompt_injection)
              "
            >
              no restrictions
            </span>
          </td>
          <td>{{ budgetOf(k) !== undefined ? formatUsd(budgetOf(k)) : "n/a" }}</td>
          <td>{{ k.expires_at ? formatTime(k.expires_at) : "never" }}</td>
          <td class="actions">
            <button
              class="sb-btn sb-btn--sm"
              :disabled="
                !policySchemaReq.succeeded.value || statusOf(k) === 'revoked'
              "
              @click="openEdit(k)"
            >
              Edit
            </button>
            <button
              v-if="statusOf(k) !== 'revoked'"
              class="sb-btn sb-btn--sm"
              :disabled="rowBusy === keyId(k) + 'rotate'"
              @click="doAction(k, 'rotate')"
            >
              Rotate
            </button>
            <button
              v-if="statusOf(k) === 'active' && supportsPolicyAction('block')"
              class="sb-btn sb-btn--sm"
              :disabled="rowBusy === keyId(k) + 'block'"
              @click="doAction(k, 'block')"
            >
              Block
            </button>
            <button
              v-else-if="
                statusOf(k) === 'blocked' && supportsPolicyAction('unblock')
              "
              class="sb-btn sb-btn--sm"
              :disabled="rowBusy === keyId(k) + 'unblock'"
              @click="doAction(k, 'unblock')"
            >
              Unblock
            </button>
            <button
              v-if="
                statusOf(k) !== 'revoked' && supportsPolicyAction('revoke')
              "
              class="sb-btn sb-btn--sm sb-btn--danger"
              :disabled="rowBusy === keyId(k) + 'revoke'"
              @click="doAction(k, 'revoke')"
            >
              Revoke
            </button>
            <button
              class="sb-btn sb-btn--sm sb-btn--danger"
              :disabled="rowBusy === keyId(k) + 'delete'"
              @click="doDelete(k)"
            >
              Delete
            </button>
          </td>
        </tr>
      </tbody>
    </table>
  </div>

  <!-- Create modal -->
  <ModalDialog v-if="showCreate" title="Create key" @close="showCreate = false">
    <ErrorState v-if="createError" :error="createError" title="Create failed" @retry="submitCreate" />
    <form @submit.prevent="submitCreate">
      <div
        v-if="supportsPolicyField('display_name', 'name')"
        class="sb-field"
      >
        <label class="sb-label">Name</label>
        <input class="sb-input" v-model="createForm.name" placeholder="team-frontend" />
      </div>
      <div class="two">
        <div v-if="supportsPolicyField('allowed_models')" class="sb-field">
          <label class="sb-label">Allowed models</label>
          <input class="sb-input" v-model="createForm.allowed_models" placeholder="comma separated" />
        </div>
        <div v-if="supportsPolicyField('blocked_models')" class="sb-field">
          <label class="sb-label">Blocked models</label>
          <input class="sb-input" v-model="createForm.blocked_models" placeholder="comma separated" />
        </div>
      </div>
      <div class="two">
        <div v-if="supportsPolicyField('allowed_providers')" class="sb-field">
          <label class="sb-label">Allowed providers</label>
          <input class="sb-input" v-model="createForm.allowed_providers" placeholder="openai, anthropic" />
        </div>
        <div v-if="supportsPolicyField('blocked_providers')" class="sb-field">
          <label class="sb-label">Blocked providers</label>
          <input class="sb-input" v-model="createForm.blocked_providers" placeholder="comma separated" />
        </div>
      </div>
      <div v-if="supportsPolicyField('allowed_tools')" class="two">
        <div class="sb-field">
          <label class="sb-label">Caller-supplied tools</label>
          <select class="sb-input" v-model="createForm.allowed_tools_mode">
            <option value="unrestricted">Unrestricted</option>
            <option value="allowlist">Use allowlist</option>
          </select>
        </div>
        <div v-if="createForm.allowed_tools_mode === 'allowlist'" class="sb-field">
          <label class="sb-label">Allowed tool names</label>
          <input class="sb-input" v-model="createForm.allowed_tools" />
          <p class="field-help">An empty allowlist blocks all caller-supplied tools.</p>
        </div>
        <div v-else class="sb-field">
          <label class="sb-label">Behavior</label>
          <p class="field-help">All caller-supplied tools are unrestricted.</p>
        </div>
      </div>
      <div class="two">
        <div
          v-if="supportsPolicyField('budget', 'max_budget_usd')"
          class="sb-field"
        >
          <label class="sb-label">Budget (USD)</label>
          <input class="sb-input" v-model="createForm.budget_usd" inputmode="decimal" placeholder="100" />
        </div>
        <div
          v-if="supportsPolicyField('budget', 'max_budget_tokens')"
          class="sb-field"
        >
          <label class="sb-label">Budget tokens</label>
          <input class="sb-input" v-model="createForm.max_budget_tokens" inputmode="numeric" placeholder="1000000" />
        </div>
      </div>
      <div class="two">
        <div v-if="supportsPolicyField('max_requests_per_minute')" class="sb-field">
          <label class="sb-label">Requests per minute</label>
          <input class="sb-input" v-model="createForm.max_requests_per_minute" inputmode="numeric" placeholder="60" />
        </div>
        <div v-if="supportsPolicyField('max_tokens_per_minute')" class="sb-field">
          <label class="sb-label">Tokens per minute</label>
          <input class="sb-input" v-model="createForm.max_tokens_per_minute" inputmode="numeric" placeholder="100000" />
        </div>
      </div>
      <div class="two">
        <div v-if="supportsPolicyField('priority')" class="sb-field">
          <label class="sb-label">Priority lane</label>
          <select class="sb-input" v-model="createForm.priority">
            <option value="">standard (default)</option>
            <option v-for="p in PRIORITY_LANES" :key="p" :value="p">{{ p }}</option>
          </select>
        </div>
        <div v-if="supportsPolicyField('route_to_model')" class="sb-field">
          <label class="sb-label">Route to model</label>
          <input class="sb-input" v-model="createForm.route_to_model" placeholder="qwen2.5-coder:1.5b" />
        </div>
      </div>
      <div class="two">
        <div v-if="supportsPolicyField('expires_at')" class="sb-field">
          <label class="sb-label">Expires at (ISO 8601)</label>
          <input class="sb-input" v-model="createForm.expires_at" placeholder="2026-12-31T00:00:00Z" />
        </div>
        <div v-if="supportsPolicyField('require_pii_redaction')" class="sb-field">
          <label class="sb-label">Require PII redaction</label>
          <input class="sb-input" v-model="createForm.require_pii_redaction" placeholder="email, credit_card" />
        </div>
      </div>
      <div class="two">
        <div v-if="supportsPolicyField('project')" class="sb-field">
          <label class="sb-label">Project</label>
          <input class="sb-input" v-model="createForm.project" placeholder="frontend" />
        </div>
        <div v-if="supportsPolicyField('user')" class="sb-field">
          <label class="sb-label">User</label>
          <input class="sb-input" v-model="createForm.user" placeholder="team or service" />
        </div>
      </div>
      <div class="two">
        <div v-if="supportsPolicyField('tenant_id', 'tenant')" class="sb-field">
          <label class="sb-label">Tenant</label>
          <input class="sb-input" v-model="createForm.tenant_id" placeholder="default" />
        </div>
        <div
          v-if="supportsPolicyField('bypass_prompt_injection')"
          class="sb-field checkbox-field"
        >
          <label class="sb-label">Prompt-injection scan</label>
          <label class="checkline">
            <input type="checkbox" v-model="createForm.bypass_prompt_injection" />
            <span>Bypass for this trusted key</span>
          </label>
        </div>
      </div>
      <div v-if="supportsPolicyField('tags')" class="sb-field">
        <label class="sb-label">Tags</label>
        <input class="sb-input" v-model="createForm.tags" placeholder="comma separated" />
      </div>
      <div v-if="supportsPolicyField('principal_selectors')" class="sb-field">
        <label class="sb-label">Principal selectors (JSON array)</label>
        <textarea class="sb-input textarea" v-model="createForm.principal_selectors" placeholder='[{"project":"frontend"}]'></textarea>
      </div>
      <div v-if="supportsPolicyField('inject_tools')" class="sb-field">
        <label class="sb-label">Inject tools (JSON array)</label>
        <textarea class="sb-input textarea" v-model="createForm.inject_tools" placeholder='[{"type":"function","function":{"name":"search"}}]'></textarea>
      </div>
      <div v-if="supportsPolicyField('inject_mcp')" class="sb-field">
        <label class="sb-label">Inject MCP gateway (JSON object)</label>
        <textarea class="sb-input textarea" v-model="createForm.inject_mcp" placeholder='{"ref": "toolhub"}'></textarea>
      </div>
      <div v-if="supportsPolicyField('metadata')" class="sb-field">
        <label class="sb-label">Metadata (key = value per line)</label>
        <textarea class="sb-input textarea" v-model="createForm.metadata" placeholder="owner = platform-team&#10;cost-center = 1234"></textarea>
      </div>
    </form>
    <template #footer>
      <button class="sb-btn" @click="showCreate = false">Cancel</button>
      <button class="sb-btn sb-btn--primary" :disabled="createBusy" @click="submitCreate">
        {{ createBusy ? "Creating..." : "Create key" }}
      </button>
    </template>
  </ModalDialog>

  <!-- Copy-once token modal -->
  <ModalDialog v-if="createdToken" title="Key created" @close="createdToken = null">
    <p class="warn-line">
      This is the only time the token is shown. Copy it now and store it somewhere safe.
      It cannot be retrieved again.
    </p>
    <CopyText :value="createdToken" mono />
    <p class="sb-faint" style="margin-top: 12px" v-if="createdMeta">
      Key id: <span class="sb-mono">{{ keyId(createdMeta) }}</span>
    </p>
    <template #footer>
      <button class="sb-btn sb-btn--primary" @click="createdToken = null">Done</button>
    </template>
  </ModalDialog>

  <!-- Edit modal -->
  <ModalDialog v-if="editBaseline" title="Edit policy" @close="closeEdit">
    <p class="edit-evidence">
      Editing <span class="sb-mono">{{ shortId(keyId(editBaseline)) }}</span>.
      Leave a field empty to clear it.
      <br />
      Policy revision
      <span class="sb-mono">{{ editBaseline.policy_revision }}</span>
      <template v-if="editBaseline.policy_digest">
        <span aria-hidden="true"> / </span>
        digest
        <span class="sb-mono digest">{{ editBaseline.policy_digest }}</span>
      </template>
      <template v-else-if="!editBaseline.tenant_id">
        <span aria-hidden="true"> / </span>
        digest is origin-scoped; refresh preview for the selected tenant
      </template>
    </p>
    <section class="preview-panel" aria-live="polite">
      <div class="preview-panel__header">
        <strong>Effective policy preview</strong>
        <button
          class="sb-btn sb-btn--sm"
          type="button"
          :disabled="previewBusy"
          @click="loadPreview()"
        >
          {{ previewBusy ? "Refreshing..." : "Refresh preview" }}
        </button>
      </div>
      <p class="field-help">
        Preview reflects the saved revision. Save edits before evaluating the
        updated policy.
      </p>
      <p v-if="previewBusy && !preview" class="sb-faint">Resolving policy...</p>
      <ErrorState
        v-else-if="previewError"
        :error="previewError"
        title="Preview unavailable"
        @retry="loadPreview()"
      />
      <template v-else-if="preview">
        <div class="preview-summary">
          <StatusBadge
            :label="preview.decisions.allowed ? 'allowed' : 'denied'"
            :tone="preview.decisions.allowed ? 'ok' : 'err'"
          />
          <span>
            revision
            <span class="sb-mono">{{ preview.policy_version.revision }}</span>
          </span>
          <span>
            digest
            <span class="sb-mono digest">{{ preview.policy_version.digest }}</span>
          </span>
          <span>
            status
            <span class="sb-mono">{{ preview.effective_policy.status }}</span>
          </span>
          <span>
            tenant
            <span class="sb-mono">{{ preview.effective_policy.tenant_id }}</span>
          </span>
        </div>
        <ul v-if="previewDecisionRows.length" class="decision-list" aria-label="Policy decisions">
          <li v-for="decision in previewDecisionRows" :key="decision.name">
            <span>{{ decision.label }}</span>
            <StatusBadge
              :label="decision.allowed ? 'allow' : 'deny'"
              :tone="decision.allowed ? 'ok' : 'err'"
            />
            <span class="sb-mono decision-reason">{{ decision.reasonCode }}</span>
          </li>
        </ul>
      </template>
    </section>
    <ErrorState v-if="editError" :error="editError" title="Update failed" @retry="submitEdit" />
    <section
      v-if="conflictDetected"
      class="conflict-notice"
      role="alert"
      aria-live="assertive"
    >
      <strong>The policy changed on the server.</strong>
      <p>Your edits are preserved. Load the current policy or rebase your changed fields before saving again.</p>
      <p v-if="conflictCurrent" class="conflict-evidence">
        Current policy revision
        <span class="sb-mono">{{ conflictCurrent.policy_revision }}</span>
        <template v-if="conflictCurrent.policy_digest">
          <span aria-hidden="true"> / </span>
          digest
          <span class="sb-mono digest">{{ conflictCurrent.policy_digest }}</span>
        </template>
      </p>
      <p v-if="conflictError">{{ conflictError.hint }}</p>
      <div class="conflict-actions">
        <button
          class="sb-btn sb-btn--sm"
          type="button"
          :disabled="conflictBusy"
          @click="refetchConflict"
        >
          {{ conflictBusy ? "Refreshing..." : "Refresh current policy" }}
        </button>
        <button
          v-if="conflictCurrent"
          class="sb-btn sb-btn--sm"
          type="button"
          @click="loadCurrentPolicy"
        >
          Load current policy
        </button>
        <button
          v-if="conflictCurrent"
          class="sb-btn sb-btn--sm sb-btn--primary"
          type="button"
          @click="rebasePreservedEdits"
        >
          Rebase preserved edits
        </button>
      </div>
    </section>
    <div class="two">
      <div
        v-if="supportsPolicyField('display_name', 'name')"
        class="sb-field"
      >
        <label class="sb-label">Name</label>
        <input class="sb-input" v-model="editForm.name" />
      </div>
      <div v-if="supportsPolicyField('expires_at')" class="sb-field">
        <label class="sb-label">Expires at (ISO 8601)</label>
        <input
          class="sb-input"
          v-model="editForm.expires_at"
          placeholder="2026-12-31T00:00:00Z"
        />
      </div>
    </div>
    <div class="two">
      <div v-if="supportsPolicyField('allowed_models')" class="sb-field">
        <label class="sb-label">Allowed models</label>
        <input class="sb-input" v-model="editForm.allowed_models" />
      </div>
      <div v-if="supportsPolicyField('blocked_models')" class="sb-field">
        <label class="sb-label">Blocked models</label>
        <input class="sb-input" v-model="editForm.blocked_models" />
      </div>
    </div>
    <div class="two">
      <div v-if="supportsPolicyField('allowed_providers')" class="sb-field">
        <label class="sb-label">Allowed providers</label>
        <input class="sb-input" v-model="editForm.allowed_providers" />
      </div>
      <div v-if="supportsPolicyField('blocked_providers')" class="sb-field">
        <label class="sb-label">Blocked providers</label>
        <input class="sb-input" v-model="editForm.blocked_providers" />
      </div>
    </div>
    <div v-if="supportsPolicyField('allowed_tools')" class="two">
      <div class="sb-field">
        <label class="sb-label">Caller-supplied tools</label>
        <select class="sb-input" v-model="editForm.allowed_tools_mode">
          <option value="unrestricted">Unrestricted</option>
          <option value="allowlist">Use allowlist</option>
        </select>
      </div>
      <div v-if="editForm.allowed_tools_mode === 'allowlist'" class="sb-field">
        <label class="sb-label">Allowed tool names</label>
        <input class="sb-input" v-model="editForm.allowed_tools" />
        <p class="field-help">An empty allowlist blocks all caller-supplied tools.</p>
      </div>
      <div v-else class="sb-field">
        <label class="sb-label">Behavior</label>
        <p class="field-help">All caller-supplied tools are unrestricted.</p>
      </div>
    </div>
    <div class="two">
      <div
        v-if="supportsPolicyField('budget', 'max_budget_usd')"
        class="sb-field"
      >
        <label class="sb-label">Budget (USD)</label>
        <input class="sb-input" v-model="editForm.budget_usd" inputmode="decimal" />
      </div>
      <div
        v-if="supportsPolicyField('budget', 'max_budget_tokens')"
        class="sb-field"
      >
        <label class="sb-label">Budget tokens</label>
        <input class="sb-input" v-model="editForm.max_budget_tokens" inputmode="numeric" />
      </div>
    </div>
    <div class="two">
      <div v-if="supportsPolicyField('max_requests_per_minute')" class="sb-field">
        <label class="sb-label">Requests per minute</label>
        <input class="sb-input" v-model="editForm.max_requests_per_minute" inputmode="numeric" />
      </div>
      <div v-if="supportsPolicyField('max_tokens_per_minute')" class="sb-field">
        <label class="sb-label">Tokens per minute</label>
        <input class="sb-input" v-model="editForm.max_tokens_per_minute" inputmode="numeric" />
      </div>
    </div>
    <div class="two">
      <div v-if="supportsPolicyField('priority')" class="sb-field">
        <label class="sb-label">Priority lane</label>
        <select class="sb-input" v-model="editForm.priority">
          <option value="">standard (default)</option>
          <option v-for="p in PRIORITY_LANES" :key="p" :value="p">{{ p }}</option>
        </select>
      </div>
      <div v-if="supportsPolicyField('route_to_model')" class="sb-field">
        <label class="sb-label">Route to model</label>
        <input class="sb-input" v-model="editForm.route_to_model" />
      </div>
    </div>
    <div class="two">
      <div v-if="supportsPolicyField('require_pii_redaction')" class="sb-field">
        <label class="sb-label">Require PII redaction</label>
        <input class="sb-input" v-model="editForm.require_pii_redaction" />
      </div>
      <div v-if="supportsPolicyField('tags')" class="sb-field">
        <label class="sb-label">Tags</label>
        <input class="sb-input" v-model="editForm.tags" />
      </div>
    </div>
    <div class="two">
      <div v-if="supportsPolicyField('project')" class="sb-field">
        <label class="sb-label">Project</label>
        <input class="sb-input" v-model="editForm.project" />
      </div>
      <div v-if="supportsPolicyField('user')" class="sb-field">
        <label class="sb-label">User</label>
        <input class="sb-input" v-model="editForm.user" />
      </div>
    </div>
    <div class="two">
      <div v-if="supportsPolicyField('tenant_id', 'tenant')" class="sb-field">
        <label class="sb-label">Tenant</label>
        <input class="sb-input" v-model="editForm.tenant_id" />
      </div>
      <div
        v-if="supportsPolicyField('bypass_prompt_injection')"
        class="sb-field checkbox-field"
      >
        <label class="sb-label">Prompt-injection scan</label>
        <label class="checkline">
          <input type="checkbox" v-model="editForm.bypass_prompt_injection" />
          <span>Bypass for this trusted key</span>
        </label>
      </div>
    </div>
    <div v-if="supportsPolicyField('principal_selectors')" class="sb-field">
      <label class="sb-label">Principal selectors (JSON array)</label>
      <textarea class="sb-input textarea" v-model="editForm.principal_selectors"></textarea>
    </div>
    <div v-if="supportsPolicyField('inject_tools')" class="sb-field">
      <label class="sb-label">Inject tools (JSON array)</label>
      <textarea class="sb-input textarea" v-model="editForm.inject_tools"></textarea>
    </div>
    <div v-if="supportsPolicyField('inject_mcp')" class="sb-field">
      <label class="sb-label">Inject MCP gateway (JSON object)</label>
      <textarea class="sb-input textarea" v-model="editForm.inject_mcp" placeholder='{"ref": "toolhub"}'></textarea>
    </div>
    <div v-if="supportsPolicyField('metadata')" class="sb-field">
      <label class="sb-label">Metadata (key = value per line)</label>
      <textarea class="sb-input textarea" v-model="editForm.metadata"></textarea>
    </div>
    <template #footer>
      <button class="sb-btn" @click="closeEdit">Cancel</button>
      <button
        class="sb-btn sb-btn--primary"
        :disabled="editBusy || conflictDetected"
        @click="submitEdit"
      >
        {{ editBusy ? "Saving..." : "Save policy" }}
      </button>
    </template>
  </ModalDialog>
</template>

<style scoped>
.table-wrap {
  border: 1px solid var(--sb-border);
  border-radius: var(--sb-radius);
  overflow-x: auto;
}
.kname {
  font-weight: 600;
}
.policy-evidence,
.edit-evidence,
.conflict-evidence {
  color: var(--sb-text-muted);
  font-size: 0.78rem;
  overflow-wrap: anywhere;
}
.policy-evidence {
  margin-top: 3px;
}
.edit-evidence {
  margin-bottom: 12px;
}
.digest {
  overflow-wrap: anywhere;
}
.preview-panel {
  background: var(--sb-surface-2);
  border: 1px solid var(--sb-border);
  border-radius: var(--sb-radius-sm);
  margin-bottom: 12px;
  padding: 10px 12px;
}
.preview-panel__header,
.preview-summary {
  align-items: center;
  display: flex;
  flex-wrap: wrap;
  gap: 8px 12px;
}
.preview-panel__header {
  justify-content: space-between;
}
.preview-summary {
  color: var(--sb-text-muted);
  font-size: 0.78rem;
  margin-top: 10px;
}
.decision-list {
  display: grid;
  gap: 4px;
  list-style: none;
  margin: 10px 0 0;
  padding: 0;
}
.decision-list li {
  align-items: center;
  display: grid;
  font-size: 0.78rem;
  gap: 8px;
  grid-template-columns: minmax(84px, 1fr) auto minmax(120px, 2fr);
}
.decision-reason {
  color: var(--sb-text-muted);
  overflow-wrap: anywhere;
}
.tags {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
  margin-top: 6px;
}
.tag {
  font-size: 0.72rem;
  padding: 1px 8px;
  border-radius: var(--sb-radius-pill);
  background: var(--sb-surface-2);
  color: var(--sb-text-muted);
  border: 1px solid var(--sb-border);
}
.policy {
  min-width: 240px;
  font-size: 0.8rem;
}
.pol {
  display: flex;
  gap: 8px;
  margin-bottom: 2px;
}
.pol__k {
  color: var(--sb-ok);
  font-size: 0.7rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  min-width: 96px;
  flex: none;
  padding-top: 2px;
}
.pol__k--block {
  color: var(--sb-err);
}
.actions {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
  justify-content: flex-end;
  min-width: 200px;
}
.two {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: var(--sb-space-3);
}
@media (max-width: 560px) {
  .two {
    grid-template-columns: 1fr;
  }
  .decision-list li {
    grid-template-columns: 1fr auto;
  }
  .decision-reason {
    grid-column: 1 / -1;
  }
}
.warn-line {
  background: var(--sb-warn-bg);
  border: 1px solid rgba(180, 83, 9, 0.3);
  border-radius: var(--sb-radius-sm);
  padding: 10px 12px;
  color: var(--sb-warn-fg);
  font-size: 0.85rem;
}
.conflict-notice {
  background: var(--sb-warn-bg);
  border: 1px solid rgba(180, 83, 9, 0.3);
  border-radius: var(--sb-radius-sm);
  color: var(--sb-warn-fg);
  margin-bottom: 12px;
  padding: 10px 12px;
}
.conflict-notice p {
  margin: 6px 0 0;
}
.conflict-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin-top: 10px;
}
.notice {
  background: var(--sb-err-bg);
  border: 1px solid rgba(180, 34, 63, 0.3);
  border-radius: var(--sb-radius-sm);
  padding: 8px 12px;
  color: var(--sb-err);
  font-size: 0.85rem;
}
.textarea {
  min-height: 86px;
  font-family: var(--sb-font-mono);
}
.field-help {
  color: var(--sb-text-muted);
  font-size: 0.78rem;
  margin: 5px 0 0;
}
.checkbox-field {
  align-self: end;
}
.checkline {
  display: flex;
  align-items: center;
  gap: 8px;
  color: var(--sb-text-muted);
  font-size: 0.85rem;
}
</style>
