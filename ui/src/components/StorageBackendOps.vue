<script setup lang="ts">
/*
 * Storage backend operations panel.
 *
 * The Storage page already answers "what model weights are on disk". This
 * answers the other storage question an operator has during an incident:
 * whether the backend the gateway reads and writes through is answering,
 * and how fast. Both come off the /metrics scrape the console already
 * consumes; see ../lib/storage-ops.ts for why absent and zero are
 * different readings here.
 */
import { computed } from "vue";
import type { ApiError } from "../api";
import { formatNumber } from "../lib/format";
import { storageOps } from "../lib/storage-ops";
import type { MetricFamily } from "../lib/metrics";
import ErrorState from "./ErrorState.vue";
import EmptyState from "./EmptyState.vue";
import MiniBars from "./MiniBars.vue";
import StatCard from "./StatCard.vue";

const props = defineProps<{
  families: MetricFamily[];
  loading: boolean;
  error: ApiError | null;
}>();

defineEmits<{ (event: "retry"): void }>();

const report = computed(() => storageOps(props.families));

function formatSeconds(value: number): string {
  if (value < 1) return `${(value * 1000).toFixed(1)} ms`;
  return `${value.toFixed(2)} s`;
}

const p95Text = computed(() => {
  const seconds = report.value?.p95Seconds;
  return seconds === undefined ? "not reported" : formatSeconds(seconds);
});

const backendsText = computed(() => {
  const backends = report.value?.backends ?? [];
  return backends.length
    ? `through ${backends.join(", ")}`
    : "the scrape carries no backend label";
});
</script>

<template>
  <section class="panel" aria-labelledby="storage-backend-ops-heading">
    <h2 id="storage-backend-ops-heading">Storage backend operations</h2>

    <ErrorState
      v-if="error"
      :error="error"
      title="Could not read the metrics endpoint"
      @retry="$emit('retry')"
    />
    <EmptyState
      v-else-if="loading && !report"
      message="Reading storage operation metrics..."
    />
    <EmptyState
      v-else-if="!report"
      message="No storage backend has run an operation on this node, so nothing is reported yet. Counters appear once a configured backend, such as the Redis store behind mesh persistence, serves its first read or write."
    />

    <template v-else>
      <p class="hint">
        Every backend call since this process started, measured where the
        gateway makes it. Values are cumulative.
      </p>

      <div class="tiles">
        <StatCard
          label="Backend operations"
          :value="formatNumber(report.operations)"
          :sub="backendsText"
        />
        <!-- Any failure at all takes the accent, not a rate threshold. These
             are lifetime counters, so a backend that went down ten minutes
             ago on a node up for a week sits far below any percentage worth
             alerting on and would otherwise render identically to one that
             has never failed. -->
        <StatCard
          label="Failed operations"
          :value="formatNumber(report.errors)"
          :sub="`${(report.errorRate * 100).toFixed(2)}% of all operations`"
          :tone="report.errors > 0 ? 'accent' : 'default'"
        />
        <StatCard
          label="Slowest 5% of calls"
          :value="p95Text"
          sub="p95 across every backend and operation"
        />
      </div>

      <div class="subgrid">
        <div>
          <h3 class="sb-eyebrow">Slowest backend and operation (p95)</h3>
          <MiniBars
            v-if="report.slowest.length"
            :items="report.slowest"
            :format="formatSeconds"
          />
          <!-- Not "no call has happened yet": the error counter alone can
               carry the panel, and saying nothing has run beside a nonzero
               failure count contradicts the tile above. -->
          <p v-else class="sb-faint note">
            Latency is not reported. The duration histogram is absent from this
            scrape, so there is no p95 to draw.
          </p>
        </div>
        <div>
          <h3 class="sb-eyebrow">Failures by error kind</h3>
          <MiniBars
            v-if="report.errorsByKind.length"
            :items="report.errorsByKind"
            color="var(--sb-chart-4)"
          />
          <p v-else class="sb-faint note">
            No backend call has returned an error. This counter is a true
            zero, not a missing reading.
          </p>
        </div>
      </div>
    </template>
  </section>
</template>

<style scoped>
.panel {
  margin-bottom: var(--sb-space-5);
}
.panel h2 {
  font-size: 13px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: var(--sb-text-muted);
  margin: 0 0 var(--sb-space-2);
}
.tiles {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: var(--sb-space-3);
  margin-bottom: var(--sb-space-4);
}
.subgrid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
  gap: var(--sb-space-2) var(--sb-space-5);
}
.subgrid h3 {
  margin-bottom: var(--sb-space-2);
}
.hint {
  font-size: 13px;
  color: var(--sb-text-muted);
  margin: 0 0 var(--sb-space-3);
  max-width: 72ch;
}
.note {
  font-size: 0.8rem;
  max-width: 60ch;
}
</style>
