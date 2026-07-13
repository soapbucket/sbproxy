<script setup lang="ts">
import EmptyState from "../components/EmptyState.vue";
import ModelDeploymentModal from "../components/ModelDeploymentModal.vue";
import ModelDeploymentTable from "../components/ModelDeploymentTable.vue";
import ModelDeviceTable from "../components/ModelDeviceTable.vue";
import ModelManagementNotices from "../components/ModelManagementNotices.vue";
import ModelManagementOverview from "../components/ModelManagementOverview.vue";
import PageHeader from "../components/PageHeader.vue";
import { useModelManagement } from "../composables/useModelManagement";
import type { ModelDeploymentRow } from "../lib/model-management";

const {
  statusReq,
  catalogReq,
  deploymentsReq,
  clusterStatusReq,
  clusterBundleReq,
  banner,
  lifecycleBusy,
  mutationBusy,
  mutationError,
  conflict,
  editor,
  status,
  catalog,
  deploymentDocument,
  coherentClusterBundle,
  canonicalDesiredDeployments,
  effectiveDesiredRevision,
  effectiveDesiredContentDigest,
  clusterAuthority,
  runtimeDeployments,
  runtimeStatusCurrent,
  rows,
  readyDeployments,
  reservedMemory,
  blockers,
  catalogModels,
  previewOnlyCatalog,
  throughputByModel,
  initialClusterBundleAbsent,
  canMutate,
  conflictRetryAllowed,
  persistentGuidance,
  authorityDescription,
  refreshing,
  refresh,
  openAddDeployment,
  openEditDeployment,
  saveDeployment,
  removeDeployment,
  retryConflict,
  reloadConflict,
  dismissConflict,
  runLifecycle,
  closeEditor,
} = useModelManagement();

function confirmRemove(row: ModelDeploymentRow) {
  if (window.confirm(`Remove deployment ${row.deploymentId} from desired state?`)) {
    removeDeployment(row);
  }
}
</script>

<template>
  <PageHeader
    title="Model host"
    subtitle="Desired model deployments and local runtime residency, controlled from one operational view."
  >
    <template #actions>
      <button
        class="sb-btn sb-btn--primary"
        :disabled="!canMutate"
        :title="!canMutate ? persistentGuidance ?? undefined : undefined"
        @click="openAddDeployment"
      >
        Add deployment
      </button>
      <button class="sb-btn sb-btn--sm" :disabled="refreshing" @click="refresh">
        {{ refreshing ? "Refreshing..." : "Refresh" }}
      </button>
    </template>
  </PageHeader>

  <ModelManagementOverview
    :document="deploymentDocument ?? null"
    :desired-deployments="canonicalDesiredDeployments"
    :desired-revision="effectiveDesiredRevision"
    :desired-content-digest="effectiveDesiredContentDigest"
    :status="status ?? null"
    :catalog-revision="catalog?.catalog_revision ?? null"
    :cluster-authority="clusterAuthority"
    :cluster-bundle="coherentClusterBundle"
    :can-mutate="canMutate"
    :guidance="persistentGuidance"
    :authority-description="authorityDescription"
    :runtime-count="runtimeDeployments.length"
    :ready-count="readyDeployments"
    :reserved-memory="reservedMemory"
  />

  <ModelManagementNotices
    :banner="banner ?? null"
    :status-error="statusReq.error.value ?? null"
    :has-status="Boolean(status)"
    :desired-error="deploymentsReq.error.value ?? null"
    :catalog-error="catalogReq.error.value ?? null"
    :cluster-authority-error="clusterStatusReq.error.value ?? null"
    :cluster-bundle-error="clusterBundleReq.error.value ?? null"
    :cluster-authority-mode="deploymentDocument?.authority === 'cluster_authority'"
    :initial-cluster-bundle-absent="initialClusterBundleAbsent"
    :catalog-loaded="catalogReq.succeeded.value"
    :catalog-model-count="catalogModels.length"
    :preview-only-catalog="previewOnlyCatalog"
    :blockers="blockers"
    :blocker-recommendation="status?.local_serving?.recommendation"
    :conflict="conflict"
    :editor-open="Boolean(editor)"
    :mutation-error="mutationError"
    :mutation-busy="mutationBusy"
    :conflict-retry-allowed="conflictRetryAllowed"
    @retry-status="statusReq.run()"
    @retry-desired="deploymentsReq.run()"
    @retry-catalog="catalogReq.run()"
    @retry-authority="clusterStatusReq.run()"
    @retry-bundle="clusterBundleReq.run()"
    @retry-conflict="retryConflict"
    @reload-conflict="reloadConflict"
    @dismiss-conflict="dismissConflict"
  />

  <section class="deployment-section" aria-labelledby="deployments-heading">
    <div class="section-heading">
      <div>
        <p class="sb-eyebrow">Desired / runtime</p>
        <h2 id="deployments-heading">Deployment ledger</h2>
      </div>
      <p>
        Configured deployments remain listed when stopped. Runtime-only rows remain visible when management metadata fails.
      </p>
    </div>
    <ModelDeploymentTable
      :rows="rows"
      :can-mutate="canMutate"
      :runtime-status-current="runtimeStatusCurrent"
      :persistent-read-only-reason="persistentGuidance"
      :lifecycle-busy="lifecycleBusy"
      :mutation-busy="mutationBusy"
      :throughput-by-model="throughputByModel"
      @edit="openEditDeployment"
      @remove="confirmRemove"
      @load="runLifecycle('load', $event)"
      @stop="runLifecycle('stop', $event)"
      @reset="runLifecycle('reset', $event)"
    />
  </section>

  <ModelDeviceTable
    v-if="status?.vram?.devices?.length"
    :devices="status.vram.devices"
  />

  <EmptyState
    v-if="!refreshing && !status && !deploymentDocument && !statusReq.error.value && !deploymentsReq.error.value"
    message="No model host deployment state is available."
  />

  <ModelDeploymentModal
    v-if="editor && catalog"
    :catalog="catalog"
    :existing-deployment-ids="Object.keys(canonicalDesiredDeployments ?? {})"
    :initial-deployment-id="editor.originalDeploymentId"
    :initial-deployment="editor.initialDeployment"
    :saving="mutationBusy"
    :can-save="canMutate && (!conflict || conflictRetryAllowed)"
    :submit-error="mutationError"
    :conflict="conflict"
    :mode="editor.openingMode"
    @close="closeEditor"
    @save="saveDeployment"
    @reload-conflict="reloadConflict"
  />
</template>

<style scoped>
.deployment-section {
  margin-bottom: var(--sb-space-6);
}

.section-heading {
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  gap: var(--sb-space-4);
  margin-bottom: var(--sb-space-4);
}

.section-heading .sb-eyebrow {
  margin: 0 0 var(--sb-space-1);
}

.section-heading > p {
  max-width: 62ch;
  margin: 0;
  color: var(--sb-text-faint);
  font-size: 0.76rem;
  text-align: right;
}

@media (max-width: 760px) {
  .section-heading {
    align-items: flex-start;
    flex-direction: column;
  }

  .section-heading > p {
    max-width: none;
    text-align: left;
  }
}
</style>
