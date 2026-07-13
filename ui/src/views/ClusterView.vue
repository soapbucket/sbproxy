<script setup lang="ts">
import { onMounted, ref } from "vue";
import {
  api,
  ApiError,
  type ClusterMetrics,
  type ClusterStatusResponse,
} from "../api";
import ClusterControlPlane from "../components/ClusterControlPlane.vue";
import ClusterDeploymentTable from "../components/ClusterDeploymentTable.vue";
import ClusterHealthRail from "../components/ClusterHealthRail.vue";
import ClusterMetricsPanel from "../components/ClusterMetricsPanel.vue";
import ClusterNodeAlerts from "../components/ClusterNodeAlerts.vue";
import ClusterNodeRoster from "../components/ClusterNodeRoster.vue";
import EmptyState from "../components/EmptyState.vue";
import ErrorState from "../components/ErrorState.vue";
import PageHeader from "../components/PageHeader.vue";
import StatusBadge from "../components/StatusBadge.vue";
import { formatTime } from "../lib/format";

const status = ref<ClusterStatusResponse | null>(null);
const statusLoading = ref(false);
const statusError = ref<ApiError | null>(null);

const clusterMetrics = ref<ClusterMetrics | null>(null);
const metricsLoading = ref(false);
const metricsNotEnabled = ref(false);
const metricsError = ref<ApiError | null>(null);

function asApiError(error: unknown): ApiError {
  return error instanceof ApiError
    ? error
    : new ApiError(0, error instanceof Error ? error.message : String(error));
}

async function loadStatus() {
  statusLoading.value = true;
  statusError.value = null;
  try {
    status.value = await api.clusterStatus();
  } catch (error) {
    statusError.value = asApiError(error);
  } finally {
    statusLoading.value = false;
  }
}

async function loadMetrics() {
  metricsLoading.value = true;
  metricsError.value = null;
  metricsNotEnabled.value = false;
  try {
    clusterMetrics.value = await api.clusterMetrics();
  } catch (error) {
    const apiError = asApiError(error);
    if (apiError.status === 404) {
      metricsNotEnabled.value = true;
      clusterMetrics.value = null;
    } else {
      metricsError.value = apiError;
    }
  } finally {
    metricsLoading.value = false;
  }
}

function refresh() {
  void loadStatus();
  if (!metricsLoading.value) void loadMetrics();
}

onMounted(refresh);
</script>

<template>
  <PageHeader
    title="Cluster"
    subtitle="Membership, model placement, and rollout health across the fleet."
  >
    <template #actions>
      <button class="sb-btn sb-btn--sm" :disabled="statusLoading" @click="refresh">
        {{ statusLoading ? "Refreshing..." : "Refresh" }}
      </button>
    </template>
  </PageHeader>

  <ErrorState
    v-if="statusError && !status"
    :error="statusError"
    title="Could not load cluster status"
    @retry="loadStatus"
  />
  <EmptyState
    v-else-if="!status"
    :message="statusLoading ? 'Loading cluster status...' : 'Cluster status is unavailable.'"
  />

  <template v-else>
    <section
      v-if="statusError"
      class="refresh-warning"
      aria-label="Cluster refresh warning"
    >
      <strong>Showing the last loaded cluster status.</strong>
      <span>
        Snapshot generated {{ formatTime(status.generated_at_unix_ms) }}.
        {{ statusError.hint }}
      </span>
      <button class="sb-btn sb-btn--sm" @click="loadStatus">Retry status</button>
    </section>

    <ClusterHealthRail :nodes="status.nodes" :summary="status.summary" />
    <ClusterNodeAlerts :alerts="status.unhealthy_nodes" :nodes="status.nodes" />

    <section
      v-if="status.summary.deployment_digest_mismatch || status.summary.unplaced_replicas > 0"
      class="fleet-notices"
      aria-label="Fleet deployment warnings"
    >
      <article v-if="status.summary.deployment_digest_mismatch" class="fleet-notice">
        <StatusBadge label="Digest mismatch" tone="err" />
        <div>
          <h3>Nodes disagree on active deployment content</h3>
          <p>Reconcile deployment state before placing or routing more replicas.</p>
        </div>
      </article>
      <article v-if="status.summary.unplaced_replicas > 0" class="fleet-notice">
        <StatusBadge :label="`${status.summary.unplaced_replicas} unplaced`" tone="warn" />
        <div>
          <h3>Desired replicas are not fully placed</h3>
          <p>Review rollout assignments and bounded rejection reasons below.</p>
        </div>
      </article>
    </section>

    <ClusterControlPlane :status="status" />
    <ClusterNodeRoster :nodes="status.nodes" />
    <ClusterDeploymentTable
      :deployments="status.deployments"
      :rollouts-in-progress="status.summary.rollouts_in_progress"
      :unplaced-replicas="status.summary.unplaced_replicas"
    />
    <ClusterMetricsPanel
      :metrics="clusterMetrics"
      :loading="metricsLoading"
      :not-enabled="metricsNotEnabled"
      :error="metricsError"
      @retry="loadMetrics"
    />
  </template>
</template>

<style scoped>
.refresh-warning {
  display: flex;
  align-items: center;
  gap: var(--sb-space-3);
  padding: var(--sb-space-3) var(--sb-space-4);
  margin-bottom: var(--sb-space-5);
  color: var(--sb-warn-fg);
  background: var(--sb-warn-bg);
  border: 1px solid var(--sb-warn);
  border-radius: var(--sb-radius);
  font-size: 0.82rem;
}

.refresh-warning button {
  margin-left: auto;
}

.fleet-notices {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: var(--sb-space-3);
  margin-bottom: var(--sb-space-6);
}

.fleet-notice {
  display: flex;
  align-items: flex-start;
  gap: var(--sb-space-3);
  padding: var(--sb-space-4);
  background: var(--sb-surface);
  border: 1px solid var(--sb-border-strong);
  border-radius: var(--sb-radius);
}

.fleet-notice h3 {
  margin-bottom: var(--sb-space-1);
  font-size: 0.9rem;
}

.fleet-notice p {
  margin: 0;
  color: var(--sb-text-muted);
  font-size: 0.8rem;
}

@media (max-width: 760px) {
  .refresh-warning {
    align-items: flex-start;
    flex-direction: column;
  }

  .refresh-warning button {
    margin-left: 0;
  }
}
</style>
