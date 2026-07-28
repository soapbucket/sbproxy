<script setup lang="ts">
import { computed, ref } from "vue";
import { api, type OperationJob } from "../api";
import type { DeploymentFormValue } from "../lib/model-management";
import { useAsync } from "../composables/useAsync";
import { useModelManagement } from "../composables/useModelManagement";
import { deployableCatalogVariants } from "../lib/model-management";
import PageHeader from "../components/PageHeader.vue";
import StatusBadge from "../components/StatusBadge.vue";
import ErrorState from "../components/ErrorState.vue";
import EmptyState from "../components/EmptyState.vue";
import ModelDeploymentModal from "../components/ModelDeploymentModal.vue";

// Reuses the exact same fetch/mutate/lifecycle machinery the Models view
// runs on (`useModelManagement`), rather than a second implementation of
// deployment creation. This view only adds a "deploy this catalog
// variant now" affordance on top of it.
const {
  catalogReq,
  catalog,
  catalogModels,
  canonicalDesiredDeployments,
  canMutate,
  conflict,
  conflictRetryAllowed,
  editor,
  mutationBusy,
  mutationError,
  banner,
  persistentGuidance,
  openAddDeployment,
  saveDeployment,
  runLifecycle,
  reloadConflict,
  closeEditor,
} = useModelManagement();

// Preselects the modal's model/variant fields; the operator can still
// change either before saving. Cleared implicitly the next time the
// modal opens for a different variant.
const pendingModel = ref<string | null>(null);
const pendingVariant = ref<string | null>(null);

function openFor(modelId: string, variantId: string) {
  pendingModel.value = modelId;
  pendingVariant.value = variantId;
  openAddDeployment();
}

// Durable jobs let this page show a just-created deployment coming up
// without leaving it. Polled lazily: nothing to track until a
// deployment has actually been saved.
const jobsReq = useAsync(() => api.modelHostJobs(), { pollMs: 4_000 });
const pendingDeploymentId = ref<string | null>(null);
const pendingJob = computed<OperationJob | null>(() => {
  if (!pendingDeploymentId.value) return null;
  const matches = (jobsReq.data.value?.jobs ?? []).filter(
    (job) => job.subject === pendingDeploymentId.value,
  );
  if (!matches.length) return null;
  return matches.reduce((latest, job) =>
    job.created_at_ms > latest.created_at_ms ? job : latest,
  );
});

function jobTone(state: OperationJob["state"]): "ok" | "warn" | "err" | "info" | "neutral" {
  if (state === "ready") return "ok";
  if (state === "failed") return "err";
  if (state === "deleted") return "neutral";
  return "info"; // queued, downloading, verifying, deleting
}

// Saving adds the deployment to desired state; loading it is a separate
// lifecycle action (`runLifecycle`, the same one the Models view's "Load"
// button calls). Chaining them here is this view's one opinion: an
// onboarding card that says "Deploy" should end with the model coming
// up, not just registered.
async function onSaveDeployment(value: DeploymentFormValue) {
  const deploymentId = value.deploymentId;
  await saveDeployment(value);
  // `useModelManagement` clears `editor` and leaves `mutationError` null
  // only once the save actually succeeded.
  if (editor.value || mutationError.value) return;
  pendingDeploymentId.value = deploymentId;
  await runLifecycle("load", deploymentId);
  await jobsReq.run();
}
</script>

<template>
  <PageHeader
    title="Get started"
    subtitle="Deploy a model from the catalog to start serving requests locally."
  >
    <template #actions>
      <button class="sb-btn sb-btn--sm" :disabled="catalogReq.loading.value" @click="catalogReq.run">
        Refresh catalog
      </button>
    </template>
  </PageHeader>

  <ErrorState v-if="catalogReq.error.value" :error="catalogReq.error.value" @retry="catalogReq.run" />
  <EmptyState
    v-else-if="catalogReq.succeeded.value && !catalogModels.length"
    message="No deployable catalog models are available. Check the model host catalog configuration."
  />
  <template v-else>
    <p v-if="banner" class="sb-card banner" :class="`banner--${banner.tone}`">
      {{ banner.text }}
    </p>

    <div v-if="pendingJob" class="sb-card pending-job">
      <div class="pending-job__head">
        <span class="sb-eyebrow">Deploying</span>
        <StatusBadge :label="pendingJob.state" :tone="jobTone(pendingJob.state)" />
      </div>
      <p class="sb-mono">{{ pendingDeploymentId }}</p>
      <p v-if="pendingJob.error" class="sb-faint error-text">{{ pendingJob.error }}</p>
      <RouterLink class="sb-btn sb-btn--sm" to="/jobs">View jobs</RouterLink>
    </div>

    <div class="catalog-grid">
      <div v-for="entry in catalogModels" :key="entry.id" class="sb-card model-card">
        <div class="model-card__head">
          <h3 class="sb-mono">{{ entry.id }}</h3>
          <span class="sb-faint">{{ entry.entry.params }} · {{ entry.entry.family }}</span>
        </div>
        <table class="sb-table">
          <thead>
            <tr>
              <th>Variant</th>
              <th>Format</th>
              <th>Support</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="variant in deployableCatalogVariants(entry.entry)" :key="variant.id">
              <td class="sb-mono">{{ variant.id }}</td>
              <td>{{ variant.format }}</td>
              <td><StatusBadge :label="variant.stability" /></td>
              <td class="deploy-cell">
                <button
                  class="sb-btn sb-btn--sm"
                  :disabled="!canMutate"
                  :title="!canMutate ? persistentGuidance ?? undefined : undefined"
                  @click="openFor(entry.id, variant.id)"
                >
                  Deploy
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </template>

  <ModelDeploymentModal
    v-if="editor && catalog"
    :catalog="catalog"
    :existing-deployment-ids="Object.keys(canonicalDesiredDeployments ?? {})"
    :initial-deployment-id="editor.originalDeploymentId"
    :initial-deployment="editor.initialDeployment"
    :preselect-model="pendingModel"
    :preselect-variant="pendingVariant"
    :saving="mutationBusy"
    :can-save="canMutate && (!conflict || conflictRetryAllowed)"
    :submit-error="mutationError"
    :conflict="conflict"
    :mode="editor.openingMode"
    @close="closeEditor"
    @save="onSaveDeployment"
    @reload-conflict="reloadConflict"
  />
</template>

<style scoped>
.banner {
  margin-bottom: var(--sb-space-4);
  padding: var(--sb-space-3) var(--sb-space-4);
}
.banner--ok {
  border-left: 3px solid var(--sb-ok);
}
.banner--warn {
  border-left: 3px solid var(--sb-warn);
}
.banner--err {
  border-left: 3px solid var(--sb-err);
}
.pending-job {
  margin-bottom: var(--sb-space-5);
}
.pending-job__head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--sb-space-3);
  margin-bottom: var(--sb-space-2);
}
.pending-job__head .sb-eyebrow {
  margin: 0;
}
.error-text {
  color: var(--sb-err);
}
.catalog-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(340px, 1fr));
  gap: var(--sb-space-4);
}
.model-card__head {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: var(--sb-space-3);
  margin-bottom: var(--sb-space-3);
}
.model-card__head h3 {
  margin: 0;
  font-size: 0.95rem;
}
.deploy-cell {
  text-align: right;
}
</style>
