<script setup lang="ts">
import { computed, onMounted, reactive, ref } from "vue";
import { api, flattenPromptOverlay, ApiError, type PromptEntry } from "../api";
import { useAsync } from "../composables/useAsync";
import { useCapabilities } from "../composables/useCapabilities";
import { toast } from "../composables/useToasts";
import PageHeader from "../components/PageHeader.vue";
import StatusBadge from "../components/StatusBadge.vue";
import ErrorState from "../components/ErrorState.vue";
import EmptyState from "../components/EmptyState.vue";
import ModalDialog from "../components/ModalDialog.vue";
import ReadOnlyNotice from "../components/ReadOnlyNotice.vue";

const req = useAsync(() => api.prompts());
onMounted(req.run);

const prompts = computed<PromptEntry[]>(() =>
  flattenPromptOverlay(req.data.value),
);

function versionsOf(p: PromptEntry): string[] {
  if (!Array.isArray(p.versions)) return [];
  return p.versions.map((v) => (typeof v === "string" ? v : String(v?.version ?? ""))).filter(Boolean);
}
function pinnedOf(p: PromptEntry): string {
  return String(p.pinned ?? p.pinned_version ?? p.active ?? "");
}

// ---- labels (WOR-2582) ----
//
// A label is a movable pointer at a version. The point of it is that a
// caller writes `support-bot@production` once and never changes, while
// the operator repoints which version that renders. So the card shows
// the pointer and where it points, and repointing is one control.
//
// A pin (`default_version`) is a different thing and both are shown: a
// pin is one pointer per prompt, serving callers who name no version at
// all, and it cannot express staging and production sitting on
// different versions at the same time.
function labelsOf(p: PromptEntry): { label: string; version: string }[] {
  const labels = p.labels ?? {};
  return Object.entries(labels)
    .map(([label, version]) => ({ label, version: String(version) }))
    .sort((a, b) => a.label.localeCompare(b.label));
}

const showLabel = ref(false);
const labelTarget = ref<PromptEntry | null>(null);
const labelForm = reactive({ label: "", version: "" });
const labelBusy = ref(false);
const labelError = ref<ApiError | null>(null);

function openLabel(p: PromptEntry, existing?: { label: string; version: string }) {
  labelTarget.value = p;
  labelForm.label = existing?.label ?? "";
  labelForm.version = existing?.version ?? "";
  labelError.value = null;
  showLabel.value = true;
}

async function submitLabel() {
  const target = labelTarget.value;
  if (!target || !labelForm.label || !labelForm.version) return;
  labelBusy.value = true;
  labelError.value = null;
  try {
    await api.setPromptLabel(
      String(target.host ?? ""),
      String(target.name ?? ""),
      labelForm.label,
      labelForm.version,
    );
    toast.success(
      `Label @${labelForm.label} now points at version ${labelForm.version}`,
      "Callers referencing this label render the new version with no change on their side.",
    );
    showLabel.value = false;
    req.run();
  } catch (e) {
    // A 409 here is the server refusing a collision: a label named after
    // an existing version would never resolve, because an exact version
    // always wins. The operator needs to read that rather than retry.
    labelError.value = e instanceof ApiError ? e : new ApiError(0, String(e));
  } finally {
    labelBusy.value = false;
  }
}

async function removeLabel(p: PromptEntry, label: string) {
  try {
    await api.removePromptLabel(String(p.host ?? ""), String(p.name ?? ""), label);
    toast.warn(
      `Label @${label} removed`,
      "A caller still referencing it now gets an unknown-version error rather than a different prompt.",
    );
    req.run();
  } catch (e) {
    toast.error(e, "Remove prompt label");
  }
}

// ---- add version ----
const showAdd = ref(false);
const addTarget = ref<PromptEntry | null>(null);
const addForm = reactive({ host: "", name: "", version: "", template: "", isNew: false });
const addBusy = ref(false);
const addError = ref<ApiError | null>(null);

function openAdd(p: PromptEntry) {
  addTarget.value = p;
  addForm.host = String(p.host ?? "");
  addForm.name = String(p.name ?? "");
  addForm.version = "";
  addForm.template = "";
  addForm.isNew = false;
  addError.value = null;
  showAdd.value = true;
}

function openNewPrompt() {
  addTarget.value = { host: "default", name: "my-prompt" };
  addForm.host = "";
  addForm.name = "";
  addForm.version = "";
  addForm.template = "";
  addForm.isNew = true;
  addError.value = null;
  showAdd.value = true;
}

async function submitAdd() {
  if (!addForm.host || !addForm.name) return;
  addBusy.value = true;
  addError.value = null;
  try {
    // Both fields are required by the endpoint (serde rejects a missing
    // one with an opaque 400), so the submit button stays disabled until
    // both are non-empty and the body always carries both.
    const body = { version: addForm.version, template: addForm.template };
    await api.addPromptVersion(
      addForm.host,
      addForm.name,
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

// WOR-2576: every state-changing control on this page is refused for a
// read_only operator by the admin server, so the console disables it and
// says why rather than offering a button that answers 403.
const { canMutate, whyNot } = useCapabilities();
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

  <ReadOnlyNotice action="Adding and pinning prompt versions" />

  <ErrorState v-if="req.error.value" :error="req.error.value" @retry="req.run" />
  <EmptyState v-else-if="!prompts.length" message="No prompt overlays configured.">
    <div style="margin-top: 16px;">
      <button
            :title="canMutate ? undefined : whyNot('mutate')"
            :disabled="!canMutate" class="sb-btn sb-btn--primary" @click="openNewPrompt">Create first prompt</button>
    </div>
  </EmptyState>

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

      <div class="versions">
        <span class="sb-eyebrow">Labels</span>
        <div class="tags" v-if="labelsOf(p).length">
          <span class="label-tag sb-mono" v-for="l in labelsOf(p)" :key="l.label">
            <span class="label-tag__name">@{{ l.label }}</span>
            <span class="label-tag__arrow">-&gt;</span>
            <span class="label-tag__version">{{ l.version }}</span>
            <button
              class="label-tag__edit"
              :disabled="!canMutate"
              :title="canMutate ? 'Repoint this label' : whyNot('mutate')"
              @click="openLabel(p, l)"
            >
              move
            </button>
            <button
              class="label-tag__edit"
              :disabled="!canMutate"
              :title="canMutate ? 'Remove this label' : whyNot('mutate')"
              @click="removeLabel(p, l.label)"
            >
              remove
            </button>
          </span>
        </div>
        <span class="sb-faint" v-else>
          none. A label lets a caller reference "{{ p.name }}@production" while you
          move which version that serves.
        </span>
      </div>

      <div class="prompt__actions">
        <button
            :title="canMutate ? undefined : whyNot('mutate')"
            :disabled="!canMutate" class="sb-btn sb-btn--sm" @click="openAdd(p)">Add version</button>
        <button
            :title="canMutate ? undefined : whyNot('mutate')"
            :disabled="!canMutate" class="sb-btn sb-btn--sm" @click="openPin(p)">Pin version</button>
        <button
            :title="canMutate ? undefined : whyNot('mutate')"
            :disabled="!canMutate" class="sb-btn sb-btn--sm" @click="openLabel(p)">Add label</button>
      </div>
    </div>
  </div>

  <!-- Point a label at a version (WOR-2582) -->
  <ModalDialog v-if="showLabel" title="Point a label at a version" @close="showLabel = false">
    <p class="sb-faint">
      A label is a movable pointer. A caller referencing
      <code class="sb-mono">{{ labelTarget?.name }}@{{ labelForm.label || "label" }}</code>
      keeps that string forever; moving the label changes which version it renders.
    </p>
    <label class="field">
      <span class="sb-eyebrow">Label</span>
      <input v-model="labelForm.label" class="sb-input sb-mono" placeholder="production" />
    </label>
    <label class="field">
      <span class="sb-eyebrow">Version</span>
      <select v-model="labelForm.version" class="sb-input sb-mono">
        <option value="">select a version</option>
        <option v-for="v in versionsOf(labelTarget ?? {})" :key="v" :value="v">{{ v }}</option>
      </select>
    </label>
    <ErrorState v-if="labelError" :error="labelError" />
    <template #actions>
      <button class="sb-btn" @click="showLabel = false">Cancel</button>
      <button
        class="sb-btn sb-btn--primary"
        :disabled="labelBusy || !canMutate || !labelForm.label || !labelForm.version"
        :title="canMutate ? undefined : whyNot('mutate')"
        @click="submitLabel"
      >
        {{ labelBusy ? "Saving..." : "Point label" }}
      </button>
    </template>
  </ModalDialog>

  <!-- Add version -->
  <ModalDialog v-if="showAdd" :title="addForm.isNew ? 'New prompt overlay' : 'Add prompt version'" wide @close="showAdd = false">
    <p v-if="!addForm.isNew" class="sb-faint" style="margin-bottom: 12px">
      For <span class="sb-mono">{{ addForm.host || "any" }} / {{ addForm.name }}</span>.
    </p>
    <ErrorState v-if="addError" :error="addError" title="Add failed" @retry="submitAdd" />
    
    <div class="sb-field" v-if="addForm.isNew">
      <label class="sb-label">Host</label>
      <input class="sb-input" v-model="addForm.host" placeholder="e.g. openai" />
    </div>
    <div class="sb-field" v-if="addForm.isNew">
      <label class="sb-label">Name</label>
      <input class="sb-input" v-model="addForm.name" placeholder="e.g. default-system" />
    </div>

    <div class="sb-field">
      <label class="sb-label">Version label (optional)</label>
      <input class="sb-input" v-model="addForm.version" placeholder="e.g. 2026-07-05 or v3" />
    </div>
    <div class="sb-field">
      <label class="sb-label">Prompt content</label>
      <textarea class="sb-textarea" v-model="addForm.template" placeholder="Prompt text or template"></textarea>
    </div>
    <template #footer>
      <button class="sb-btn" @click="showAdd = false">Cancel</button>
      <button
            :title="canMutate ? undefined : whyNot('mutate')"
        class="sb-btn sb-btn--primary"
        :disabled="addBusy || !addForm.host || !addForm.name || !addForm.version || !addForm.template || !canMutate"
        @click="submitAdd"
      >
        {{ addBusy ? "Adding..." : (addForm.isNew ? "Create prompt" : "Add version") }}
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
      <button
            :title="canMutate ? undefined : whyNot('mutate')" class="sb-btn sb-btn--primary" :disabled="pinBusy || !pinVersion || !canMutate" @click="submitPin">
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

.label-tag {
  display: inline-flex;
  align-items: center;
  gap: var(--sb-space-2);
  border: 1px solid var(--sb-border-strong);
  border-radius: var(--sb-radius);
  padding: 2px var(--sb-space-2);
}
.label-tag__name {
  font-weight: 600;
}
.label-tag__arrow,
.label-tag__edit {
  color: var(--sb-text-muted);
}
.label-tag__edit {
  background: none;
  border: none;
  cursor: pointer;
  font: inherit;
  text-decoration: underline;
}
.label-tag__edit:disabled {
  cursor: not-allowed;
  opacity: 0.5;
}
</style>
