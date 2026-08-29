<script setup lang="ts">
import { computed, onMounted, reactive, ref } from "vue";
import { api, asList, ApiError, type Credential } from "../api";
import { useAsync } from "../composables/useAsync";
import { useCapabilities } from "../composables/useCapabilities";
import { toast } from "../composables/useToasts";
import { formatTime, shortId } from "../lib/format";
import PageHeader from "../components/PageHeader.vue";
import StatusBadge from "../components/StatusBadge.vue";
import ErrorState from "../components/ErrorState.vue";
import EmptyState from "../components/EmptyState.vue";
import ModalDialog from "../components/ModalDialog.vue";
import ReadOnlyNotice from "../components/ReadOnlyNotice.vue";

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
const form = reactive({ name: "", provider: "", kind: "", secret: "", tags: "", header: "", scheme: "" });
const busy = ref(false);
const createError = ref<ApiError | null>(null);

function reset() {
  Object.assign(form, { name: "", provider: "", kind: "", secret: "", tags: "", header: "", scheme: "" });
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
    // Presentation belongs to the credential: how the upstream expects
    // this secret sent, not how the caller sent theirs. Blank means the
    // server default (authorization: Bearer ...).
    if (form.header) body.header = form.header.trim();
    if (form.scheme !== "") body.scheme = form.scheme;
    if (form.tags) body.tags = form.tags.split(/[,\n]/).map((s) => s.trim()).filter(Boolean);
    await api.createCredential(body);
    showCreate.value = false;
    reset();
    toast.success("Credential added");
    req.run();
  } catch (e) {
    createError.value = e instanceof ApiError ? e : new ApiError(0, String(e));
  } finally {
    busy.value = false;
  }
}

// ---- actions ----
const rowBusy = ref<string | null>(null);

const ACTION_DONE: Record<string, string> = {
  revoke: "Credential revoked",
  block: "Credential blocked",
  unblock: "Credential unblocked",
  rotate: "Credential rotated",
};

async function doAction(c: Credential, action: "revoke" | "block" | "unblock" | "rotate") {
  const id = credId(c);
  if (action === "revoke" && !confirm(`Revoke credential ${id}?`)) return;
  rowBusy.value = id + action;
  try {
    await api.credentialAction(id, action);
    toast.success(ACTION_DONE[action], shortId(id));
    req.run();
  } catch (e) {
    toast.error(e, `${action[0].toUpperCase()}${action.slice(1)} credential`);
  } finally {
    rowBusy.value = null;
  }
}

async function doDelete(c: Credential) {
  const id = credId(c);
  if (!confirm(`Delete credential ${id}?`)) return;
  rowBusy.value = id + "delete";
  try {
    await api.deleteCredential(id);
    toast.success("Credential deleted", shortId(id));
    req.run();
  } catch (e) {
    toast.error(e, "Delete credential");
  } finally {
    rowBusy.value = null;
  }
}

function statusOf(c: Credential): string {
  return String(c.status ?? "active");
}

// WOR-2576: every state-changing control on this page is refused for a
// read_only operator by the admin server, so the console disables it and
// says why rather than offering a button that answers 403.
const { canMutate, whyNot } = useCapabilities();
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

  <ReadOnlyNotice action="Adding, blocking, revoking and deleting credentials" />

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
          <th>Upstream header</th>
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
          <td class="sb-mono">{{ c.header ?? "authorization" }}</td>
          <td>
            <StatusBadge :label="statusOf(c)" />
            <div v-if="c.rotation_pending" style="margin-top: 4px">
              <StatusBadge label="rotation pending" tone="warn" />
            </div>
          </td>
          <td>{{ c.created_at ? formatTime(c.created_at) : "n/a" }}</td>
          <td>{{ c.expires_at ? formatTime(c.expires_at) : "never" }}</td>
          <td class="actions">
            <!--
              WOR-2347: no Rotate button here. `credential_subroute` in
              admin_keys.rs implements revoke, block, and unblock only, so
              every click returned "unknown credential action".

              It is absent rather than implemented because rotation is not
              sbproxy's to perform. A key is minted here, so the proxy can
              issue a replacement; a credential holds a secret the operator
              obtained from an upstream provider. Rotate it at the provider
              and PATCH the new value (or point the credential at a
              `vault://` reference and let the resolver pick it up).
            -->
            <button
            :title="canMutate ? undefined : whyNot('mutate')"
              v-if="c.status !== 'blocked'"
              class="sb-btn sb-btn--sm"
              :disabled="rowBusy === credId(c) + 'block' || !canMutate"
              @click="doAction(c, 'block')"
            >
              Block
            </button>
            <button
            :title="canMutate ? undefined : whyNot('mutate')"
              v-else
              class="sb-btn sb-btn--sm"
              :disabled="rowBusy === credId(c) + 'unblock' || !canMutate"
              @click="doAction(c, 'unblock')"
            >
              Unblock
            </button>
            <button
            :title="canMutate ? undefined : whyNot('mutate')"
              class="sb-btn sb-btn--sm sb-btn--danger"
              :disabled="rowBusy === credId(c) + 'revoke' || !canMutate"
              @click="doAction(c, 'revoke')"
            >
              Revoke
            </button>
            <button
            :title="canMutate ? undefined : whyNot('mutate')"
              class="sb-btn sb-btn--sm sb-btn--danger"
              :disabled="rowBusy === credId(c) + 'delete' || !canMutate"
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
    <div class="two">
      <div class="sb-field">
        <label class="sb-label">Upstream header</label>
        <input class="sb-input" v-model="form.header" placeholder="authorization" />
        <p class="sb-faint">
          Where the upstream expects this secret. Blank means
          <code>authorization</code>. Anthropic wants <code>x-api-key</code>.
        </p>
      </div>
      <div class="sb-field">
        <label class="sb-label">Scheme prefix</label>
        <input class="sb-input" v-model="form.scheme" placeholder="Bearer " />
        <p class="sb-faint">
          Prefix on the header value. Blank means <code>Bearer&nbsp;</code>. Type
          a single space to send the raw secret with no prefix.
        </p>
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
      <button
            :title="canMutate ? undefined : whyNot('mutate')" class="sb-btn sb-btn--primary" :disabled="busy || !canMutate" @click="submit">
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
