<script setup lang="ts">
import { computed } from "vue";
import type { ClusterNodeAlert } from "../api";
import {
  clusterNodeAnchorId,
  formatAgeMs,
  formatReasonCode,
  sortNodeAlerts,
} from "../lib/cluster-health";
import StatusBadge from "./StatusBadge.vue";

const props = defineProps<{
  alerts: readonly ClusterNodeAlert[];
}>();

const orderedAlerts = computed(() => sortNodeAlerts(props.alerts));

function healthTone(
  health: ClusterNodeAlert["health"],
): "ok" | "warn" | "err" {
  if (health === "healthy") return "ok";
  if (health === "degraded") return "warn";
  return "err";
}

function membershipTone(
  membership: ClusterNodeAlert["membership_state"],
): "ok" | "warn" | "err" {
  if (membership === "alive") return "ok";
  if (membership === "suspect") return "warn";
  return "err";
}

function ageAgo(ageMs: number): string {
  const age = formatAgeMs(ageMs);
  return age === "Just now" ? age : `${age} ago`;
}

function rosterHref(nodeId: string): string {
  return `#${clusterNodeAnchorId(nodeId)}`;
}
</script>

<template>
  <section
    v-if="orderedAlerts.length"
    class="alert-section"
    aria-labelledby="unhealthy-heading"
  >
    <div class="section-heading">
      <div>
        <p class="sb-eyebrow">Immediate attention</p>
        <h2 id="unhealthy-heading">Unhealthy nodes</h2>
      </div>
      <span class="section-count sb-mono">{{ orderedAlerts.length }}</span>
    </div>

    <div class="alert-stack">
      <article
        v-for="alert in orderedAlerts"
        :key="alert.node_id"
        class="node-alert"
        :class="`node-alert--${alert.health}`"
      >
        <div class="node-alert__topline">
          <div>
            <p class="node-alert__kicker">Node requires attention</p>
            <h3 class="node-alert__id sb-mono">{{ alert.node_id }}</h3>
          </div>
          <StatusBadge :label="alert.health" :tone="healthTone(alert.health)" />
        </div>

        <ul class="reason-list" aria-label="Unhealthy reasons">
          <li v-for="reason in alert.reasons" :key="reason">
            {{ formatReasonCode(reason) }}
          </li>
          <li v-if="!alert.reasons.length">Reason not reported</li>
        </ul>

        <dl class="node-alert__facts">
          <div>
            <dt>Membership</dt>
            <dd>
              <StatusBadge
                :label="alert.membership_state"
                :tone="membershipTone(alert.membership_state)"
              />
            </dd>
          </div>
          <div>
            <dt>Last acknowledgement</dt>
            <dd>{{ ageAgo(alert.last_ack_age_ms) }}</dd>
          </div>
          <div>
            <dt>Snapshot age</dt>
            <dd>
              {{ alert.snapshot_age_ms === null ? "Unavailable" : ageAgo(alert.snapshot_age_ms) }}
            </dd>
          </div>
          <div class="node-alert__endpoint">
            <dt>Model endpoint</dt>
            <dd class="sb-mono">{{ alert.model_endpoint ?? "Not advertised" }}</dd>
          </div>
        </dl>

        <a class="node-alert__roster-link" :href="rosterHref(alert.node_id)">
          View {{ alert.node_id }} in the full roster
        </a>
      </article>
    </div>
  </section>
</template>

<style scoped>
.alert-section {
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

.section-count {
  display: inline-grid;
  place-items: center;
  min-width: 30px;
  height: 30px;
  color: var(--sb-on-navy);
  background: var(--sb-err);
  border-radius: 50%;
  font-size: 0.78rem;
  font-weight: 700;
}

.alert-stack {
  display: grid;
  gap: var(--sb-space-3);
}

.node-alert {
  padding: var(--sb-space-5);
  background: var(--sb-err-bg);
  border: 1px solid var(--sb-err);
  border-left-width: 5px;
  border-radius: var(--sb-radius);
}

.node-alert--degraded {
  background: var(--sb-warn-bg);
  border-color: var(--sb-warn);
}

.node-alert__topline {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: var(--sb-space-4);
}

.node-alert__kicker {
  margin: 0 0 var(--sb-space-1);
  color: var(--sb-err);
  font-size: 0.7rem;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}

.node-alert--degraded .node-alert__kicker {
  color: var(--sb-warn-fg);
}

.node-alert__id {
  font-size: 1.02rem;
  overflow-wrap: anywhere;
}

.reason-list {
  display: flex;
  flex-wrap: wrap;
  gap: var(--sb-space-2);
  padding: 0;
  margin: var(--sb-space-4) 0;
  list-style: none;
}

.reason-list li {
  padding: 4px 9px;
  color: var(--sb-err);
  background: var(--sb-surface);
  border: 1px solid var(--sb-border-strong);
  border-radius: var(--sb-radius-pill);
  font-size: 0.76rem;
  font-weight: 600;
}

.node-alert--degraded .reason-list li {
  color: var(--sb-warn-fg);
}

.node-alert__facts {
  display: grid;
  grid-template-columns: repeat(3, minmax(130px, 1fr)) minmax(220px, 2fr);
  gap: var(--sb-space-4);
  padding-top: var(--sb-space-4);
  margin: 0;
  border-top: 1px solid var(--sb-border-strong);
}

.node-alert__facts div {
  min-width: 0;
}

.node-alert__facts dt {
  margin-bottom: var(--sb-space-1);
  color: var(--sb-text-faint);
  font-size: 0.68rem;
  font-weight: 700;
  letter-spacing: 0.06em;
  text-transform: uppercase;
}

.node-alert__facts dd {
  margin: 0;
  font-size: 0.82rem;
  overflow-wrap: anywhere;
}

.node-alert__roster-link {
  display: inline-block;
  margin-top: var(--sb-space-4);
  font-size: 0.8rem;
  font-weight: 600;
}

@media (max-width: 760px) {
  .section-heading {
    display: block;
  }

  .section-count {
    margin-top: var(--sb-space-2);
  }

  .node-alert {
    padding: var(--sb-space-4);
  }

  .node-alert__facts {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .node-alert__endpoint {
    grid-column: 1 / -1;
  }
}

@media (max-width: 480px) {
  .node-alert__topline {
    align-items: flex-start;
    flex-direction: column;
  }

  .node-alert__facts {
    grid-template-columns: 1fr;
  }

  .node-alert__endpoint {
    grid-column: auto;
  }
}
</style>
