<script setup lang="ts">
import { computed, onMounted, reactive, ref } from "vue";
import { api, asList, ApiError, type Credential } from "../api";
import { useAsync } from "../composables/useAsync";
import { formatTime, shortId } from "../lib/format";
import PageHeader from "../components/PageHeader.vue";
import StatusBadge from "../components/StatusBadge.vue";
import ErrorState from "../components/ErrorState.vue";
import EmptyState from "../components/EmptyState.vue";
import ModalDialog from "../components/ModalDialog.vue";

const req = useAsync(() => api.credentials());
const creds = computed<Credential[]>(() =>
  asList<Credential>(req.data.value, "credentials", "items", "data"),
);
onMounted(req.run);

function credId(c: Credential): string {
  return String(c.id ?? c.name ?? "");
}

// ---- create ----
const showCreate = ref(false);
const form = reactive({ name: "", provider: "", kind: "", secret: "", tags: "" });
const busy = ref(false);
const createError = ref<ApiError | null>(null);

function reset() {
  Object.assign(form, { name: "", provider: "", kind: "", secret: "", tags: "" });
  createError.value = null;
}

async function submit() {
  busy.value = true;
  createError.value = null;
  try {
    const body: Record<string, unknown> = {};
    if (form.name) body.name = form.name;
    if (form.provider) body.provider = form.provider;
    if (form.kind) body.kind = form.kind;
    if (form.secret) body.secret = form.secret;
    if (form.tags) body.tags = form.tags.split(/[,\n]/).map((s) => s.trim()).filter(Boolean);
    await api.createCredential(body);
    showCreate.value = false;
    reset();
    req.run();
  } catch (e) {
    createError.value = e instanceof ApiError ? e : new ApiError(0, String(e));
  } finally {
    busy.value = false;
  }
}

// ---- actions ----
const rowBusy = ref<string | null>(null);
const actionError = ref<string | null>(null);

async function doAction(c: Credential, action: "revoke" | "block" | "unblock" | "rotate") {
  const id = credId(c);
  if (action === "revoke" && !confirm(`Revoke credential ${id}?`)) return;
  rowBusy.value = id + action;
  actionError.value = null;
  try {
    await api.credentialAction(id, action);
    req.run();
  } catch (e) {
    actionError.value = e instanceof ApiError ? `${action}: ${e.hint}` : String(e);
  } finally {
    rowBusy.value = null;
  }
}

async function doDelete(c: Credential) {
  const id = credId(c);
  if (!confirm(`Delete credential ${id}?`)) return;
  rowBusy.value = id + "delete";
  actionError.value = null;
  try {
    await api.deleteCredential(id);
    req.run();
  } catch (e) {
    actionError.value = e instanceof ApiError ? `delete: ${e.hint}` : String(e);
  } finally {
    rowBusy.value = null;
  }
}

function statusOf(c: Credential): string {
  return String(c.status ?? "active");
}
</script>

<template>
  <PageHeader
    title="Credentials"
    subtitle="Upstream provider secrets. Values are write-only: they are never returned or displayed here, only their metadata."
  >
    <template #actions>
      <button class="sb-btn" @click="req.run">Refresh</button>
      <button class="sb-btn sb-btn--primary" @click="showCreate = true">Add credential</button>
    </template>
  </PageHeader>

  <p class="notice" v-if="actionError">{{ actionError }}</p>

  <ErrorState v-if="req.error.value" :error="req.error.value" @retry="req.run" />
  <EmptyState v-else-if="!creds.length" message="No credentials configured.">
    <button class="sb-btn sb-btn--primary" @click="showCreate = true">Add the first credential</button>
  </EmptyState>

  <div class="table-wrap" v-else>
    <table class="sb-table">
      <thead>
        <tr>
          <th>Name</th>
          <th>Provider</th>
          <th>Status</th>
          <th>Created</th>
          <th>Expires</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="(c, i) in creds" :key="i">
          <td>
            <div style="font-weight: 600">{{ c.name ?? "(unnamed)" }}</div>
            <div class="sb-id">{{ shortId(credId(c)) }}</div>
            <div class="tags" v-if="c.tags?.length">
              <span class="tag" v-for="t in c.tags" :key="t">{{ t }}</span>
            </div>
          </td>
          <td class="sb-mono">{{ c.provider ?? c.kind ?? "n/a" }}</td>
          <td>
            <StatusBadge :label="statusOf(c)" />
            <div v-if="c.rotation_pending" style="margin-top: 4px">
              <StatusBadge label="rotation pending" tone="warn" />
            </div>
          </td>
          <td>{{ c.created_at ? formatTime(c.created_at) : "n/a" }}</td>
          <td>{{ c.expires_at ? formatTime(c.expires_at) : "never" }}</td>
          <td class="actions">
            <button
              class="sb-btn sb-btn--sm"
              :disabled="rowBusy === credId(c) + 'rotate'"
              @click="doAction(c, 'rotate')"
            >
              Rotate
            </button>
            <button
              v-if="c.status !== 'blocked'"
              class="sb-btn sb-btn--sm"
              :disabled="rowBusy === credId(c) + 'block'"
              @click="doAction(c, 'block')"
            >
              Block
            </button>
            <button
              v-else
              class="sb-btn sb-btn--sm"
              :disabled="rowBusy === credId(c) + 'unblock'"
              @click="doAction(c, 'unblock')"
            >
              Unblock
            </button>
            <button
              class="sb-btn sb-btn--sm sb-btn--danger"
              :disabled="rowBusy === credId(c) + 'revoke'"
              @click="doAction(c, 'revoke')"
            >
              Revoke
            </button>
            <button
              class="sb-btn sb-btn--sm sb-btn--danger"
              :disabled="rowBusy === credId(c) + 'delete'"
              @click="doDelete(c)"
            >
              Delete
            </button>
          </td>
        </tr>
      </tbody>
    </table>
  </div>

  <ModalDialog v-if="showCreate" title="Add credential" @close="showCreate = false">
    <ErrorState v-if="createError" :error="createError" title="Create failed" @retry="submit" />
    <p class="sb-faint" style="margin-bottom: 12px">
      The secret is sent once to the server and stored there. It is never shown back in this UI.
    </p>
    <div class="sb-field">
      <label class="sb-label">Name</label>
      <input class="sb-input" v-model="form.name" placeholder="openai-prod" />
    </div>
    <div class="two">
      <div class="sb-field">
        <label class="sb-label">Provider</label>
        <input class="sb-input" v-model="form.provider" placeholder="openai" />
      </div>
      <div class="sb-field">
        <label class="sb-label">Kind (optional)</label>
        <input class="sb-input" v-model="form.kind" placeholder="api_key" />
      </div>
    </div>
    <div class="sb-field">
      <label class="sb-label">Secret value</label>
      <input class="sb-input" v-model="form.secret" type="password" autocomplete="off" placeholder="write-only" />
    </div>
    <div class="sb-field">
      <label class="sb-label">Tags</label>
      <input class="sb-input" v-model="form.tags" placeholder="comma separated" />
    </div>
    <template #footer>
      <button class="sb-btn" @click="showCreate = false">Cancel</button>
      <button class="sb-btn sb-btn--primary" :disabled="busy" @click="submit">
        {{ busy ? "Saving..." : "Save credential" }}
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
.actions {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
  justify-content: flex-end;
  min-width: 180px;
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
.notice {
  background: var(--sb-err-bg);
  border: 1px solid rgba(180, 34, 63, 0.3);
  border-radius: var(--sb-radius-sm);
  padding: 8px 12px;
  color: var(--sb-err);
  font-size: 0.85rem;
}
</style>
