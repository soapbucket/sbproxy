<script setup lang="ts">
import { computed } from "vue";
import type { ClusterNode, ClusterSummary } from "../api";
import {
  clusterNodeAnchorId,
  sortClusterNodes,
} from "../lib/cluster-health";

const props = defineProps<{
  nodes: readonly ClusterNode[];
  summary: ClusterSummary;
}>();

const orderedNodes = computed(() => sortClusterNodes(props.nodes));

function healthMark(health: ClusterNode["health"]): string {
  if (health === "healthy") return "OK";
  if (health === "degraded") return "D";
  return "!";
}

function healthLabel(health: ClusterNode["health"]): string {
  return health.charAt(0).toUpperCase() + health.slice(1);
}
</script>

<template>
  <section class="health-rail" aria-labelledby="fleet-health-heading">
    <div class="health-rail__heading">
      <div>
        <p class="sb-eyebrow">Live membership</p>
        <h2 id="fleet-health-heading">Fleet health</h2>
      </div>
      <p class="health-rail__summary" aria-live="polite">
        <span><strong>{{ summary.total_nodes }}</strong> nodes</span>
        <span><strong>{{ summary.healthy_nodes }}</strong> healthy</span>
        <span><strong>{{ summary.degraded_nodes }}</strong> degraded</span>
        <span><strong>{{ summary.unhealthy_nodes }}</strong> unhealthy</span>
      </p>
    </div>

    <div
      class="health-rail__scroller"
      role="region"
      aria-label="Cluster nodes, local node first"
      tabindex="0"
    >
      <div class="health-rail__track">
        <a
          v-for="node in orderedNodes"
          :key="node.node_id"
          class="health-rail__node"
          :class="[
            `health-rail__node--${node.health}`,
            { 'health-rail__node--local': node.local },
          ]"
          :href="`#${clusterNodeAnchorId(node.node_id)}`"
          :aria-label="`${node.node_id}: ${node.health}${node.local ? ', local node' : ''}`"
        >
          <span class="health-rail__marker" aria-hidden="true">
            {{ healthMark(node.health) }}
          </span>
          <span class="health-rail__identity">
            <span class="health-rail__id sb-mono">{{ node.node_id }}</span>
            <span class="health-rail__state">{{ healthLabel(node.health) }}</span>
          </span>
          <span v-if="node.local" class="health-rail__local">Local</span>
        </a>
      </div>
    </div>
  </section>
</template>

<style scoped>
.health-rail {
  margin-bottom: var(--sb-space-5);
  padding: var(--sb-space-5);
  overflow: hidden;
  color: var(--sb-on-ink);
  background: var(--sb-ink);
  border: 1px solid var(--sb-ink-strong);
  border-radius: var(--sb-radius-lg);
}

.health-rail__heading {
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  gap: var(--sb-space-4);
  margin-bottom: var(--sb-space-4);
}

.health-rail :deep(.sb-eyebrow) {
  margin: 0 0 var(--sb-space-1);
  color: var(--sb-accent-tint-strong);
}

.health-rail h2 {
  font-size: 1.25rem;
  color: var(--sb-on-ink);
}

.health-rail__summary {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: var(--sb-space-4);
  margin: 0;
  color: var(--sb-accent-tint-strong);
  font-size: 0.78rem;
  white-space: nowrap;
}

.health-rail__summary strong {
  color: var(--sb-on-ink);
  font-family: var(--sb-font-mono);
  font-weight: 700;
}

.health-rail__scroller {
  overflow-x: auto;
  padding: 3px;
  margin: -3px;
  border-radius: var(--sb-radius-sm);
}

.health-rail__scroller:focus-visible {
  outline: 2px solid var(--sb-on-ink);
  outline-offset: 2px;
}

.health-rail__track {
  position: relative;
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(138px, 1fr));
  gap: var(--sb-space-2);
  min-width: max-content;
}

.health-rail__track::before {
  position: absolute;
  top: 20px;
  right: 18px;
  left: 18px;
  height: 1px;
  content: "";
  background: var(--sb-ink-soft);
}

.health-rail__node {
  position: relative;
  z-index: 1;
  display: grid;
  grid-template-columns: auto minmax(0, 1fr);
  gap: var(--sb-space-2);
  align-items: center;
  min-width: 138px;
  padding: var(--sb-space-2);
  color: var(--sb-on-ink);
  background: var(--sb-ink);
  border: 1px solid var(--sb-ink-soft);
  border-radius: var(--sb-radius-sm);
  text-decoration: none;
}

.health-rail__node:hover {
  color: var(--sb-on-ink);
  background: var(--sb-ink-strong);
  border-color: var(--sb-accent-tint-strong);
  text-decoration: none;
}

.health-rail__node:focus-visible {
  outline: 3px solid var(--sb-accent-tint-strong);
  outline-offset: 2px;
}

.health-rail__marker {
  display: inline-grid;
  place-items: center;
  width: 26px;
  height: 26px;
  color: var(--sb-ink-strong);
  background: var(--sb-ok-bg);
  border: 2px solid var(--sb-ok);
  border-radius: 50%;
  font-family: var(--sb-font-mono);
  font-size: 0.62rem;
  font-weight: 800;
}

.health-rail__node--degraded .health-rail__marker {
  color: var(--sb-warn-fg);
  background: var(--sb-warn-bg);
  border-color: var(--sb-warn);
}

.health-rail__node--unhealthy .health-rail__marker {
  color: var(--sb-err);
  background: var(--sb-err-bg);
  border-color: var(--sb-err);
}

.health-rail__node--local {
  border-color: var(--sb-accent-tint-strong);
  box-shadow: inset 0 -2px 0 var(--sb-accent-tint-strong);
}

.health-rail__identity {
  min-width: 0;
}

.health-rail__id,
.health-rail__state {
  display: block;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.health-rail__id {
  font-size: 0.73rem;
  font-weight: 600;
}

.health-rail__state {
  color: var(--sb-accent-tint-strong);
  font-size: 0.67rem;
}

.health-rail__local {
  grid-column: 1 / -1;
  justify-self: start;
  padding: 1px 6px;
  color: var(--sb-on-ink);
  background: var(--sb-ink-soft);
  border: 1px solid var(--sb-accent-tint-strong);
  border-radius: var(--sb-radius-pill);
  font-size: 0.62rem;
  font-weight: 700;
  letter-spacing: 0.06em;
  line-height: 1.4;
  text-transform: uppercase;
}

@media (max-width: 760px) {
  .health-rail {
    padding: var(--sb-space-4);
  }

  .health-rail__heading {
    display: block;
  }

  .health-rail__summary {
    justify-content: flex-start;
    gap: var(--sb-space-2) var(--sb-space-4);
    margin-top: var(--sb-space-3);
    overflow-x: auto;
  }

  .health-rail__track {
    grid-auto-flow: column;
    grid-auto-columns: 144px;
    grid-template-columns: none;
  }
}
</style>
