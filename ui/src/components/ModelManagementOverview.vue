<script setup lang="ts">
import type {
  ClusterDeploymentAuthority,
  ClusterDeploymentDocument,
  DeploymentDocument,
  ModelDeployment,
  ModelHostStatus,
} from "../api";
import { formatBytes, shortId } from "../lib/format";
import { authorityLabel } from "../lib/model-management";
import StatCard from "./StatCard.vue";
import StatusBadge from "./StatusBadge.vue";

defineProps<{
  document: DeploymentDocument | null;
  desiredDeployments: Readonly<Record<string, ModelDeployment>> | null;
  desiredRevision?: number | null;
  desiredContentDigest?: string | null;
  status: ModelHostStatus | null;
  catalogRevision: string | null;
  clusterAuthority: ClusterDeploymentAuthority | null;
  clusterBundle: ClusterDeploymentDocument | null;
  canMutate: boolean;
  guidance: string | null;
  authorityDescription: string;
  runtimeCount: number;
  readyCount: number;
  reservedMemory: number;
}>();
</script>

<template>
  <div class="summary-grid">
    <StatCard
      label="Desired deployments"
      :value="desiredDeployments ? Object.keys(desiredDeployments).length : 'n/a'"
      :sub="document ? authorityLabel(document.authority) : 'Ownership unavailable'"
      tone="accent"
    />
    <StatCard
      label="Runtime observed"
      :value="status ? runtimeCount : 'n/a'"
      :sub="status?.runtime_revision !== undefined ? `Runtime revision ${status.runtime_revision}` : undefined"
    />
    <StatCard label="Ready" :value="status ? readyCount : 'n/a'" sub="Local ready deployments" />
    <StatCard
      label="Memory reserved"
      :value="status ? formatBytes(reservedMemory) : 'n/a'"
      sub="Observed runtime reservations"
    />
  </div>

  <section class="sb-card ownership-panel" aria-labelledby="ownership-heading">
    <div class="ownership-copy">
      <p class="sb-eyebrow">Persistent ownership</p>
      <div class="ownership-title">
        <h2 id="ownership-heading">Desired deployment authority</h2>
        <StatusBadge
          v-if="document"
          :label="authorityLabel(document.authority)"
          :tone="canMutate ? 'ok' : 'info'"
        />
        <StatusBadge v-else label="Unavailable" tone="err" />
      </div>
      <p>{{ authorityDescription }}</p>
      <p v-if="guidance" class="ownership-guidance">{{ guidance }}</p>
    </div>
    <dl class="ownership-facts">
      <div>
        <dt>Desired revision</dt>
        <dd class="sb-mono">
          {{ desiredRevision === undefined ? "Unavailable" : desiredRevision ?? "Initial" }}
        </dd>
      </div>
      <div>
        <dt>Catalog</dt>
        <dd class="sb-mono">{{ catalogRevision ?? "Unavailable" }}</dd>
      </div>
      <div v-if="document?.authority === 'cluster_authority'">
        <dt>Active signed revision</dt>
        <dd class="sb-mono">{{ clusterAuthority?.active_revision ?? "None" }}</dd>
      </div>
      <div v-if="clusterBundle">
        <dt>Bundle signer</dt>
        <dd class="sb-mono">{{ clusterBundle.signer_node_id }}</dd>
      </div>
      <div v-if="desiredContentDigest">
        <dt>Content digest</dt>
        <dd class="sb-mono" :title="desiredContentDigest">
          {{ shortId(desiredContentDigest, 12, 8) }}
        </dd>
      </div>
    </dl>
  </section>
</template>

<style scoped>
.summary-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: var(--sb-space-3);
  margin-bottom: var(--sb-space-5);
}

.ownership-panel {
  display: grid;
  grid-template-columns: minmax(0, 1.25fr) minmax(320px, 0.75fr);
  gap: var(--sb-space-6);
  margin: var(--sb-space-5) 0;
  border-left: 4px solid var(--sb-ink);
}

.ownership-copy,
.ownership-title {
  min-width: 0;
}

.ownership-copy .sb-eyebrow {
  margin: 0 0 var(--sb-space-1);
}

.ownership-title {
  display: flex;
  align-items: center;
  gap: var(--sb-space-3);
  flex-wrap: wrap;
}

.ownership-copy > p:not(.sb-eyebrow) {
  margin: var(--sb-space-2) 0 0;
  color: var(--sb-text-muted);
  font-size: 0.82rem;
  overflow-wrap: anywhere;
}

.ownership-copy .ownership-guidance {
  color: var(--sb-info);
}

.ownership-facts {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: var(--sb-space-3);
  margin: 0;
}

.ownership-facts div {
  min-width: 0;
  padding-bottom: var(--sb-space-2);
  border-bottom: 1px solid var(--sb-border);
}

.ownership-facts dt {
  color: var(--sb-text-faint);
  font-size: 0.68rem;
  text-transform: uppercase;
  letter-spacing: 0.06em;
}

.ownership-facts dd {
  margin: var(--sb-space-1) 0 0;
  font-size: 0.76rem;
  overflow-wrap: anywhere;
}

@media (max-width: 940px) {
  .summary-grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .ownership-panel {
    grid-template-columns: 1fr;
  }
}

@media (max-width: 520px) {
  .summary-grid,
  .ownership-facts {
    grid-template-columns: 1fr;
  }
}
</style>
