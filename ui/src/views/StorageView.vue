<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { api, ApiError, type GcReport } from "../api";
import CopyText from "../components/CopyText.vue";
import EmptyState from "../components/EmptyState.vue";
import ErrorState from "../components/ErrorState.vue";
import ModalDialog from "../components/ModalDialog.vue";
import ModelFilesTable from "../components/ModelFilesTable.vue";
import PageHeader from "../components/PageHeader.vue";
import { useAsync } from "../composables/useAsync";
import { formatBytes } from "../lib/format";
import {
  deleteRefusalReason,
  gcBudgetAbsentReason,
  gcSummary,
  gcUnavailableReason,
  storageRows,
  type StorageArtifactRow,
} from "../lib/storage";

const filesReq = useAsync(() => api.modelHostFiles());
onMounted(() => {
  void filesReq.run();
});

const files = computed(() => filesReq.data.value);
const rows = computed(() => storageRows(files.value));
const cacheConfigured = computed(() => Boolean(files.value?.cache_root));

const banner = ref<{ tone: "ok" | "err"; text: string } | null>(null);

function failureText(error: unknown): string {
  if (error instanceof ApiError) return error.hint;
  return error instanceof Error ? error.message : "The operation failed.";
}

// ---- per-artifact delete ----

// Fail-closed refusal reasons keyed by digest, rendered inline on the
// row so the reason stays readable after the dialog closes.
const refusals = ref<Record<string, string>>({});
const pendingDelete = ref<StorageArtifactRow | null>(null);
const deleteBusy = ref("");

function requestDelete(row: StorageArtifactRow) {
  banner.value = null;
  pendingDelete.value = row;
}

function closeDelete() {
  if (deleteBusy.value) return;
  pendingDelete.value = null;
}

async function confirmDelete() {
  const row = pendingDelete.value;
  if (!row || deleteBusy.value) return;
  deleteBusy.value = row.digest;
  banner.value = null;
  const cleared = { ...refusals.value };
  delete cleared[row.digest];
  refusals.value = cleared;
  try {
    const report = await api.deleteModelHostArtifact(row.digest);
    pendingDelete.value = null;
    banner.value = report.removed
      ? {
          tone: "ok",
          text: `Deleted ${row.model} (${row.variant}) and reclaimed ${formatBytes(report.reclaimed_bytes)}.`,
        }
      : {
          tone: "err",
          text: `The server accepted the request but did not remove ${row.digestShort}.`,
        };
  } catch (error) {
    pendingDelete.value = null;
    if (error instanceof ApiError && error.status === 409) {
      refusals.value = {
        ...refusals.value,
        [row.digest]: deleteRefusalReason(error.body),
      };
    } else {
      banner.value = { tone: "err", text: failureText(error) };
    }
  } finally {
    deleteBusy.value = "";
  }
  await filesReq.run();
}

// ---- cache GC ----

const gcBusy = ref(false);
const gcResult = ref<GcReport | null>(null);
const gcServerRefusal = ref<string | null>(null);

// GC is disabled with an explanation when the server reports that no
// cache budget is configured, either proactively on the files report or
// through a refusal from the GC route itself.
const gcDisabledReason = computed(
  () => gcBudgetAbsentReason(files.value) ?? gcServerRefusal.value,
);

const gcSkipped = computed(() =>
  gcResult.value ? Object.entries(gcResult.value.skipped_artifacts) : [],
);

async function runGc() {
  if (gcBusy.value || gcDisabledReason.value) return;
  gcBusy.value = true;
  banner.value = null;
  try {
    gcResult.value = await api.modelHostGc();
  } catch (error) {
    gcResult.value = null;
    if (error instanceof ApiError) {
      const unavailable = gcUnavailableReason(error.body);
      if (unavailable) {
        gcServerRefusal.value = unavailable;
      } else {
        banner.value = { tone: "err", text: failureText(error) };
      }
    } else {
      banner.value = { tone: "err", text: failureText(error) };
    }
  } finally {
    gcBusy.value = false;
  }
  await filesReq.run();
}

function refresh() {
  banner.value = null;
  void filesReq.run();
}
</script>

<template>
  <PageHeader
    title="Storage"
    subtitle="Verified model weights in the artifact cache: what is on disk, what is resident, and what can be reclaimed."
  >
    <template #actions>
      <button
        class="sb-btn"
        :disabled="gcBusy || Boolean(gcDisabledReason) || !cacheConfigured"
        :title="gcDisabledReason ?? undefined"
        @click="runGc"
      >
        {{ gcBusy ? "Collecting..." : "Run GC" }}
      </button>
      <button class="sb-btn sb-btn--sm" :disabled="filesReq.loading.value" @click="refresh">
        {{ filesReq.loading.value ? "Refreshing..." : "Refresh" }}
      </button>
    </template>
  </PageHeader>

  <ErrorState v-if="filesReq.error.value" :error="filesReq.error.value" @retry="refresh" />
  <template v-else>
    <p v-if="banner" class="banner" :class="`banner--${banner.tone}`">{{ banner.text }}</p>

    <p v-if="files" class="storage-summary">
      <strong>{{ formatBytes(files.total_bytes) }}</strong>
      across {{ rows.length }} {{ rows.length === 1 ? "artifact" : "artifacts" }}
      <template v-if="files.cache_root">
        in <span class="sb-mono cache-root">{{ files.cache_root }}</span>
      </template>
    </p>

    <p v-if="gcDisabledReason" class="sb-faint gc-disabled-reason">
      {{ gcDisabledReason }}
    </p>

    <div v-if="gcResult" class="sb-card gc-result" aria-live="polite">
      <h3>Cache GC result</h3>
      <p class="gc-summary">{{ gcSummary(gcResult) }}</p>
      <p class="sb-faint">
        {{ gcResult.deleted_artifacts.length }}
        {{ gcResult.deleted_artifacts.length === 1 ? "artifact" : "artifacts" }} deleted.
      </p>
      <template v-if="gcSkipped.length">
        <p class="sb-faint">Protected artifacts skipped:</p>
        <ul class="gc-skipped">
          <li v-for="[digest, reason] in gcSkipped" :key="digest">
            <span class="sb-mono gc-digest">{{ digest }}</span>
            <span class="sb-faint">{{ reason }}</span>
          </li>
        </ul>
      </template>
      <p v-if="gcResult.budget_unsatisfied_bytes > 0" class="gc-unsatisfied">
        Still {{ formatBytes(gcResult.budget_unsatisfied_bytes) }} above budget because the
        remaining artifacts are protected.
      </p>
    </div>

    <EmptyState
      v-if="files && !cacheConfigured"
      message="No model host is configured, so no artifact cache is open."
    />
    <ModelFilesTable
      v-else-if="files"
      :rows="rows"
      :delete-busy-digest="deleteBusy"
      :refusals="refusals"
      @delete="requestDelete"
    />
  </template>

  <ModalDialog v-if="pendingDelete" title="Delete cached artifact" @close="closeDelete">
    <p>
      Delete the cached weights for
      <strong class="sb-mono">{{ pendingDelete.model }}</strong>
      ({{ pendingDelete.variant }})? This frees
      {{ formatBytes(pendingDelete.sizeBytes) }} on disk. A deployment that needs this
      artifact later will download and verify it again.
    </p>
    <CopyText :value="pendingDelete.digest" mono />
    <template #footer>
      <button class="sb-btn" :disabled="Boolean(deleteBusy)" @click="closeDelete">
        Cancel
      </button>
      <button
        class="sb-btn sb-btn--danger"
        :disabled="Boolean(deleteBusy)"
        @click="confirmDelete"
      >
        {{ deleteBusy ? "Deleting..." : "Delete artifact" }}
      </button>
    </template>
  </ModalDialog>
</template>

<style scoped>
.banner {
  padding: var(--sb-space-3) var(--sb-space-4);
  border-radius: var(--sb-radius-sm);
  margin-bottom: var(--sb-space-4);
  font-size: 0.9rem;
}
.banner--ok {
  background: var(--sb-accent-tint);
  color: var(--sb-accent);
}
.banner--err {
  background: var(--sb-err-bg);
  color: var(--sb-err);
}
.storage-summary {
  margin-bottom: var(--sb-space-3);
  color: var(--sb-text-muted);
}
.cache-root {
  font-size: 0.82rem;
  overflow-wrap: anywhere;
}
.gc-disabled-reason {
  margin-bottom: var(--sb-space-3);
  max-width: 72ch;
}
.gc-result {
  margin-bottom: var(--sb-space-4);
}
.gc-result h3 {
  margin-bottom: var(--sb-space-3);
}
.gc-summary {
  font-weight: 600;
}
.gc-skipped {
  margin: 0 0 var(--sb-space-3);
  padding-left: var(--sb-space-5);
}
.gc-skipped li {
  min-width: 0;
  overflow-wrap: anywhere;
}
.gc-digest {
  display: block;
  font-size: 0.78rem;
}
.gc-unsatisfied {
  margin: 0;
  color: var(--sb-warn-fg);
}
</style>
