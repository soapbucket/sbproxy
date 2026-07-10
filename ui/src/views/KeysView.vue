<script setup lang="ts">
import { computed, onMounted, reactive, ref } from "vue";
import { api, asList, ApiError, type AdminKey, type CreatedKey } from "../api";
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

onMounted(keysReq.run);

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
function listOf(k: AdminKey, field: keyof AdminKey): string {
  return fromList(k[field] ?? k.policy?.[field as string]);
}
function stringOf(k: AdminKey, field: keyof AdminKey): string {
  const v = k[field] ?? k.policy?.[field as string];
  return typeof v === "string" ? v : "";
}
function boolOf(k: AdminKey, field: keyof AdminKey): boolean {
  return Boolean(k[field] ?? k.policy?.[field as string]);
}
function budgetOf(k: AdminKey): number | undefined {
  if (typeof k.policy?.max_budget_usd === "number") return k.policy.max_budget_usd;
  if (typeof k.policy?.budget_usd === "number") return k.policy.budget_usd;
  const b = (k.budget ?? k.policy?.budget) as any;
  if (typeof b === "number") return b;
  if (b && typeof b === "object" && typeof b.max_cost_usd === "number") return b.max_cost_usd;
  if (b && typeof b === "object" && typeof b.usd === "number") return b.usd;
  return undefined;
}
function tokenBudgetOf(k: AdminKey): number | undefined {
  const b = (k.budget ?? k.policy?.budget) as any;
  if (b && typeof b === "object" && typeof b.max_tokens === "number") return b.max_tokens;
  return undefined;
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
const PRIORITY_LANES = ["interactive", "standard", "batch"] as const;

// ---- create ----
const showCreate = ref(false);
const createForm = reactive({
  name: "",
  allowed_models: "",
  blocked_models: "",
  allowed_providers: "",
  blocked_providers: "",
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
const createdMeta = ref<CreatedKey | null>(null);

function resetCreate() {
  Object.assign(createForm, {
    name: "",
    allowed_models: "",
    blocked_models: "",
    allowed_providers: "",
    blocked_providers: "",
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
    const token =
      created?.token ?? created?.plaintext ?? created?.secret ?? created?.key ?? null;
    createdMeta.value = created;
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
const editing = ref<AdminKey | null>(null);
const editForm = reactive({
  allowed_models: "",
  blocked_models: "",
  allowed_providers: "",
  blocked_providers: "",
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

function openEdit(k: AdminKey) {
  editing.value = k;
  editError.value = null;
  Object.assign(editForm, {
    allowed_models: listOf(k, "allowed_models"),
    blocked_models: listOf(k, "blocked_models"),
    allowed_providers: listOf(k, "allowed_providers"),
    blocked_providers: listOf(k, "blocked_providers"),
    require_pii_redaction: listOf(k, "require_pii_redaction"),
    route_to_model: stringOf(k, "route_to_model"),
    max_requests_per_minute:
      typeof k.max_requests_per_minute === "number" ? String(k.max_requests_per_minute) : "",
    max_tokens_per_minute:
      typeof k.max_tokens_per_minute === "number" ? String(k.max_tokens_per_minute) : "",
    priority: stringOf(k, "priority"),
    max_budget_tokens: tokenBudgetOf(k) !== undefined ? String(tokenBudgetOf(k)) : "",
    budget_usd: budgetOf(k) !== undefined ? String(budgetOf(k)) : "",
    project: stringOf(k, "project"),
    user: stringOf(k, "user"),
    tenant_id: stringOf(k, "tenant_id"),
    bypass_prompt_injection: boolOf(k, "bypass_prompt_injection"),
    principal_selectors: jsonText(k.principal_selectors ?? k.policy?.principal_selectors),
    inject_tools: jsonText(k.inject_tools ?? k.policy?.inject_tools),
    inject_mcp: jsonObjectText(k.inject_mcp ?? k.policy?.inject_mcp),
    metadata: metadataText(k.metadata ?? k.policy?.metadata),
    tags: fromList(k.tags ?? k.policy?.tags),
  });
}

async function submitEdit() {
  if (!editing.value) return;
  editBusy.value = true;
  editError.value = null;
  try {
    const k = editing.value;
    const body = buildPolicy(editForm as any);
    // Emptied fields that the key currently carries are explicit clears:
    // priority clears with "", inject_mcp with JSON null, metadata with {}.
    if (!editForm.priority && stringOf(k, "priority")) body.priority = "";
    if (!editForm.inject_mcp.trim() && (k.inject_mcp ?? k.policy?.inject_mcp)) {
      body.inject_mcp = null;
    }
    if (!editForm.metadata.trim() && metadataText(k.metadata ?? k.policy?.metadata)) {
      body.metadata = {};
    }
    await api.patchKey(keyId(k), body);
    editing.value = null;
    keysReq.run();
  } catch (e) {
    editError.value = e instanceof ApiError ? e : new ApiError(0, String(e));
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
      <button class="sb-btn sb-btn--primary" @click="showCreate = true">Create key</button>
    </template>
  </PageHeader>

  <p class="notice" v-if="actionError">{{ actionError }}</p>

  <ErrorState v-if="keysReq.error.value" :error="keysReq.error.value" @retry="keysReq.run" />
  <EmptyState v-else-if="!keys.length" message="No keys yet.">
    <button class="sb-btn sb-btn--primary" @click="showCreate = true">Create the first key</button>
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
            <button class="sb-btn sb-btn--sm" @click="openEdit(k)">Edit</button>
            <button
              class="sb-btn sb-btn--sm"
              :disabled="rowBusy === keyId(k) + 'rotate'"
              @click="doAction(k, 'rotate')"
            >
              Rotate
            </button>
            <button
              v-if="!k.blocked"
              class="sb-btn sb-btn--sm"
              :disabled="rowBusy === keyId(k) + 'block'"
              @click="doAction(k, 'block')"
            >
              Block
            </button>
            <button
              v-else
              class="sb-btn sb-btn--sm"
              :disabled="rowBusy === keyId(k) + 'unblock'"
              @click="doAction(k, 'unblock')"
            >
              Unblock
            </button>
            <button
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
      <div class="sb-field">
        <label class="sb-label">Name</label>
        <input class="sb-input" v-model="createForm.name" placeholder="team-frontend" />
      </div>
      <div class="two">
        <div class="sb-field">
          <label class="sb-label">Allowed models</label>
          <input class="sb-input" v-model="createForm.allowed_models" placeholder="comma separated" />
        </div>
        <div class="sb-field">
          <label class="sb-label">Blocked models</label>
          <input class="sb-input" v-model="createForm.blocked_models" placeholder="comma separated" />
        </div>
      </div>
      <div class="two">
        <div class="sb-field">
          <label class="sb-label">Allowed providers</label>
          <input class="sb-input" v-model="createForm.allowed_providers" placeholder="openai, anthropic" />
        </div>
        <div class="sb-field">
          <label class="sb-label">Blocked providers</label>
          <input class="sb-input" v-model="createForm.blocked_providers" placeholder="comma separated" />
        </div>
      </div>
      <div class="two">
        <div class="sb-field">
          <label class="sb-label">Budget (USD)</label>
          <input class="sb-input" v-model="createForm.budget_usd" inputmode="decimal" placeholder="100" />
        </div>
        <div class="sb-field">
          <label class="sb-label">Budget tokens</label>
          <input class="sb-input" v-model="createForm.max_budget_tokens" inputmode="numeric" placeholder="1000000" />
        </div>
      </div>
      <div class="two">
        <div class="sb-field">
          <label class="sb-label">Requests per minute</label>
          <input class="sb-input" v-model="createForm.max_requests_per_minute" inputmode="numeric" placeholder="60" />
        </div>
        <div class="sb-field">
          <label class="sb-label">Tokens per minute</label>
          <input class="sb-input" v-model="createForm.max_tokens_per_minute" inputmode="numeric" placeholder="100000" />
        </div>
      </div>
      <div class="two">
        <div class="sb-field">
          <label class="sb-label">Priority lane</label>
          <select class="sb-input" v-model="createForm.priority">
            <option value="">standard (default)</option>
            <option v-for="p in PRIORITY_LANES" :key="p" :value="p">{{ p }}</option>
          </select>
        </div>
        <div class="sb-field">
          <label class="sb-label">Route to model</label>
          <input class="sb-input" v-model="createForm.route_to_model" placeholder="qwen2.5-coder:1.5b" />
        </div>
      </div>
      <div class="two">
        <div class="sb-field">
          <label class="sb-label">Expires at (ISO 8601)</label>
          <input class="sb-input" v-model="createForm.expires_at" placeholder="2026-12-31T00:00:00Z" />
        </div>
        <div class="sb-field">
          <label class="sb-label">Require PII redaction</label>
          <input class="sb-input" v-model="createForm.require_pii_redaction" placeholder="email, credit_card" />
        </div>
      </div>
      <div class="two">
        <div class="sb-field">
          <label class="sb-label">Project</label>
          <input class="sb-input" v-model="createForm.project" placeholder="frontend" />
        </div>
        <div class="sb-field">
          <label class="sb-label">User</label>
          <input class="sb-input" v-model="createForm.user" placeholder="team or service" />
        </div>
      </div>
      <div class="two">
        <div class="sb-field">
          <label class="sb-label">Tenant</label>
          <input class="sb-input" v-model="createForm.tenant_id" placeholder="default" />
        </div>
        <div class="sb-field checkbox-field">
          <label class="sb-label">Prompt-injection scan</label>
          <label class="checkline">
            <input type="checkbox" v-model="createForm.bypass_prompt_injection" />
            <span>Bypass for this trusted key</span>
          </label>
        </div>
      </div>
      <div class="sb-field">
        <label class="sb-label">Tags</label>
        <input class="sb-input" v-model="createForm.tags" placeholder="comma separated" />
      </div>
      <div class="sb-field">
        <label class="sb-label">Principal selectors (JSON array)</label>
        <textarea class="sb-input textarea" v-model="createForm.principal_selectors" placeholder='[{"project":"frontend"}]'></textarea>
      </div>
      <div class="sb-field">
        <label class="sb-label">Inject tools (JSON array)</label>
        <textarea class="sb-input textarea" v-model="createForm.inject_tools" placeholder='[{"type":"function","function":{"name":"search"}}]'></textarea>
      </div>
      <div class="sb-field">
        <label class="sb-label">Inject MCP gateway (JSON object)</label>
        <textarea class="sb-input textarea" v-model="createForm.inject_mcp" placeholder='{"ref": "toolhub"}'></textarea>
      </div>
      <div class="sb-field">
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
    <p class="sb-faint" style="margin-top: 12px" v-if="createdMeta?.id">
      Key id: <span class="sb-mono">{{ createdMeta.id }}</span>
    </p>
    <template #footer>
      <button class="sb-btn sb-btn--primary" @click="createdToken = null">Done</button>
    </template>
  </ModalDialog>

  <!-- Edit modal -->
  <ModalDialog v-if="editing" title="Edit policy" @close="editing = null">
    <p class="sb-faint" style="margin-bottom: 12px">
      Editing <span class="sb-mono">{{ shortId(keyId(editing)) }}</span>. Leave a field empty to clear it.
    </p>
    <ErrorState v-if="editError" :error="editError" title="Update failed" @retry="submitEdit" />
    <div class="two">
      <div class="sb-field">
        <label class="sb-label">Allowed models</label>
        <input class="sb-input" v-model="editForm.allowed_models" />
      </div>
      <div class="sb-field">
        <label class="sb-label">Blocked models</label>
        <input class="sb-input" v-model="editForm.blocked_models" />
      </div>
    </div>
    <div class="two">
      <div class="sb-field">
        <label class="sb-label">Allowed providers</label>
        <input class="sb-input" v-model="editForm.allowed_providers" />
      </div>
      <div class="sb-field">
        <label class="sb-label">Blocked providers</label>
        <input class="sb-input" v-model="editForm.blocked_providers" />
      </div>
    </div>
    <div class="two">
      <div class="sb-field">
        <label class="sb-label">Budget (USD)</label>
        <input class="sb-input" v-model="editForm.budget_usd" inputmode="decimal" />
      </div>
      <div class="sb-field">
        <label class="sb-label">Budget tokens</label>
        <input class="sb-input" v-model="editForm.max_budget_tokens" inputmode="numeric" />
      </div>
    </div>
    <div class="two">
      <div class="sb-field">
        <label class="sb-label">Requests per minute</label>
        <input class="sb-input" v-model="editForm.max_requests_per_minute" inputmode="numeric" />
      </div>
      <div class="sb-field">
        <label class="sb-label">Tokens per minute</label>
        <input class="sb-input" v-model="editForm.max_tokens_per_minute" inputmode="numeric" />
      </div>
    </div>
    <div class="two">
      <div class="sb-field">
        <label class="sb-label">Priority lane</label>
        <select class="sb-input" v-model="editForm.priority">
          <option value="">standard (default)</option>
          <option v-for="p in PRIORITY_LANES" :key="p" :value="p">{{ p }}</option>
        </select>
      </div>
      <div class="sb-field">
        <label class="sb-label">Route to model</label>
        <input class="sb-input" v-model="editForm.route_to_model" />
      </div>
    </div>
    <div class="two">
      <div class="sb-field">
        <label class="sb-label">Require PII redaction</label>
        <input class="sb-input" v-model="editForm.require_pii_redaction" />
      </div>
      <div class="sb-field">
        <label class="sb-label">Tags</label>
        <input class="sb-input" v-model="editForm.tags" />
      </div>
    </div>
    <div class="two">
      <div class="sb-field">
        <label class="sb-label">Project</label>
        <input class="sb-input" v-model="editForm.project" />
      </div>
      <div class="sb-field">
        <label class="sb-label">User</label>
        <input class="sb-input" v-model="editForm.user" />
      </div>
    </div>
    <div class="two">
      <div class="sb-field">
        <label class="sb-label">Tenant</label>
        <input class="sb-input" v-model="editForm.tenant_id" />
      </div>
      <div class="sb-field checkbox-field">
        <label class="sb-label">Prompt-injection scan</label>
        <label class="checkline">
          <input type="checkbox" v-model="editForm.bypass_prompt_injection" />
          <span>Bypass for this trusted key</span>
        </label>
      </div>
    </div>
    <div class="sb-field">
      <label class="sb-label">Principal selectors (JSON array)</label>
      <textarea class="sb-input textarea" v-model="editForm.principal_selectors"></textarea>
    </div>
    <div class="sb-field">
      <label class="sb-label">Inject tools (JSON array)</label>
      <textarea class="sb-input textarea" v-model="editForm.inject_tools"></textarea>
    </div>
    <div class="sb-field">
      <label class="sb-label">Inject MCP gateway (JSON object)</label>
      <textarea class="sb-input textarea" v-model="editForm.inject_mcp" placeholder='{"ref": "toolhub"}'></textarea>
    </div>
    <div class="sb-field">
      <label class="sb-label">Metadata (key = value per line)</label>
      <textarea class="sb-input textarea" v-model="editForm.metadata"></textarea>
    </div>
    <template #footer>
      <button class="sb-btn" @click="editing = null">Cancel</button>
      <button class="sb-btn sb-btn--primary" :disabled="editBusy" @click="submitEdit">
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
}
.warn-line {
  background: var(--sb-warn-bg);
  border: 1px solid rgba(180, 83, 9, 0.3);
  border-radius: var(--sb-radius-sm);
  padding: 10px 12px;
  color: var(--sb-warn-fg);
  font-size: 0.85rem;
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
