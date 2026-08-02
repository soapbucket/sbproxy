<script setup lang="ts">
import { computed, onMounted, reactive, ref } from "vue";
import { api, asList, ApiError, type PromptEntry } from "../api";
import { useAsync } from "../composables/useAsync";
import { toast } from "../composables/useToasts";
import PageHeader from "../components/PageHeader.vue";
import StatusBadge from "../components/StatusBadge.vue";
import ErrorState from "../components/ErrorState.vue";
import EmptyState from "../components/EmptyState.vue";
import ModalDialog from "../components/ModalDialog.vue";

const req = useAsync(() => api.prompts());
onMounted(req.run);

const prompts = computed<PromptEntry[]>(() =>
  asList<PromptEntry>(req.data.value, "prompts", "overlays", "items", "data"),
);

function versionsOf(p: PromptEntry): string[] {
  if (!Array.isArray(p.versions)) return [];
  return p.versions.map((v) => (typeof v === "string" ? v : String(v?.version ?? ""))).filter(Boolean);
}
function pinnedOf(p: PromptEntry): string {
  return String(p.pinned ?? p.pinned_version ?? p.active ?? "");
}

// ---- add version ----
const showAdd = ref(false);
const addTarget = ref<PromptEntry | null>(null);
const addForm = reactive({ version: "", content: "" });
const addBusy = ref(false);
const addError = ref<ApiError | null>(null);

function openAdd(p: PromptEntry) {
  addTarget.value = p;
  addForm.version = "";
  addForm.content = "";
  addError.value = null;
  showAdd.value = true;
}

async function submitAdd() {
  if (!addTarget.value) return;
  addBusy.value = true;
  addError.value = null;
  try {
    const body: Record<string, unknown> = {};
    if (addForm.version) body.version = addForm.version;
    if (addForm.content) body.content = addForm.content;
    await api.addPromptVersion(
      String(addTarget.value.host ?? ""),
      String(addTarget.value.name ?? ""),
      body,
    );
    showAdd.value = false;
    toast.success("Prompt version added");
    req.run();
  } catch (e) {
    addError.value = e instanceof ApiError ? e : new ApiError(0, String(e));
  } finally {
    addBusy.value = false;
  }
}

// ---- pin ----
const showPin = ref(false);
const pinTarget = ref<PromptEntry | null>(null);
const pinVersion = ref("");
const pinBusy = ref(false);
const pinError = ref<ApiError | null>(null);

function openPin(p: PromptEntry) {
  pinTarget.value = p;
  pinVersion.value = pinnedOf(p) || versionsOf(p)[0] || "";
  pinError.value = null;
  showPin.value = true;
}

async function submitPin() {
  if (!pinTarget.value) return;
  pinBusy.value = true;
  pinError.value = null;
  try {
    await api.pinPrompt(
      String(pinTarget.value.host ?? ""),
      String(pinTarget.value.name ?? ""),
      { version: pinVersion.value },
    );
    showPin.value = false;
    toast.success(`Pinned ${pinVersion.value}`);
    req.run();
  } catch (e) {
    pinError.value = e instanceof ApiError ? e : new ApiError(0, String(e));
  } finally {
    pinBusy.value = false;
  }
}
</script>

<template>
  <PageHeader
    title="Prompts"
    subtitle="The prompt overlay snapshot: managed prompt versions per host and name, and which version is pinned."
  >
    <template #actions>
      <button class="sb-btn sb-btn--primary" @click="req.run">Refresh</button>
    </template>
  </PageHeader>

  <ErrorState v-if="req.error.value" :error="req.error.value" @retry="req.run" />
  <EmptyState v-else-if="!prompts.length" message="No prompt overlays configured." />

  <div class="cards" v-else>
    <div class="sb-card prompt" v-for="(p, i) in prompts" :key="i">
      <div class="prompt__head">
        <div>
          <div class="prompt__name">{{ p.name ?? "(unnamed)" }}</div>
          <div class="sb-id">{{ p.host ?? "any host" }}</div>
        </div>
        <StatusBadge v-if="pinnedOf(p)" :label="`pinned ${pinnedOf(p)}`" tone="ok" />
      </div>

      <div class="versions">
        <span class="sb-eyebrow">Versions</span>
        <div class="tags" v-if="versionsOf(p).length">
          <span
            class="tag sb-mono"
            :class="{ 'tag--pinned': v === pinnedOf(p) }"
            v-for="v in versionsOf(p)"
            :key="v"
          >
            {{ v }}
          </span>
        </div>
        <span class="sb-faint" v-else>none recorded</span>
      </div>

      <div class="prompt__actions">
        <button class="sb-btn sb-btn--sm" @click="openAdd(p)">Add version</button>
        <button class="sb-btn sb-btn--sm" @click="openPin(p)">Pin version</button>
      </div>
    </div>
  </div>

  <!-- Add version -->
  <ModalDialog v-if="showAdd && addTarget" title="Add prompt version" wide @close="showAdd = false">
    <p class="sb-faint" style="margin-bottom: 12px">
      For <span class="sb-mono">{{ addTarget.host ?? "any" }} / {{ addTarget.name }}</span>.
    </p>
    <ErrorState v-if="addError" :error="addError" title="Add failed" @retry="submitAdd" />
    <div class="sb-field">
      <label class="sb-label">Version label (optional)</label>
      <input class="sb-input" v-model="addForm.version" placeholder="e.g. 2026-07-05 or v3" />
    </div>
    <div class="sb-field">
      <label class="sb-label">Prompt content</label>
      <textarea class="sb-textarea" v-model="addForm.content" placeholder="Prompt text or template"></textarea>
    </div>
    <template #footer>
      <button class="sb-btn" @click="showAdd = false">Cancel</button>
      <button class="sb-btn sb-btn--primary" :disabled="addBusy" @click="submitAdd">
        {{ addBusy ? "Adding..." : "Add version" }}
      </button>
    </template>
  </ModalDialog>

  <!-- Pin -->
  <ModalDialog v-if="showPin && pinTarget" title="Pin prompt version" @close="showPin = false">
    <p class="sb-faint" style="margin-bottom: 12px">
      For <span class="sb-mono">{{ pinTarget.host ?? "any" }} / {{ pinTarget.name }}</span>.
    </p>
    <ErrorState v-if="pinError" :error="pinError" title="Pin failed" @retry="submitPin" />
    <div class="sb-field">
      <label class="sb-label">Version</label>
      <select class="sb-select" v-model="pinVersion" v-if="versionsOf(pinTarget).length">
        <option v-for="v in versionsOf(pinTarget)" :key="v" :value="v">{{ v }}</option>
      </select>
      <input class="sb-input" v-model="pinVersion" v-else placeholder="version label" />
    </div>
    <template #footer>
      <button class="sb-btn" @click="showPin = false">Cancel</button>
      <button class="sb-btn sb-btn--primary" :disabled="pinBusy || !pinVersion" @click="submitPin">
        {{ pinBusy ? "Pinning..." : "Pin version" }}
      </button>
    </template>
  </ModalDialog>
</template>

<style scoped>
.cards {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
  gap: var(--sb-space-4);
}
.prompt {
  display: flex;
  flex-direction: column;
  gap: var(--sb-space-4);
}
.prompt__head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: var(--sb-space-3);
}
.prompt__name {
  font-weight: 600;
  font-size: 1.02rem;
}
.versions {
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.tags {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}
.tag {
  font-size: 0.76rem;
  padding: 2px 10px;
  background: var(--sb-surface-2);
  color: var(--sb-text-muted);
  border: 1px solid var(--sb-border);
}
.tag--pinned {
  color: var(--sb-accent);
  border-color: var(--sb-border-accent);
  background: var(--sb-accent-tint);
}
.prompt__actions {
  display: flex;
  gap: var(--sb-space-3);
  margin-top: auto;
}
</style>
