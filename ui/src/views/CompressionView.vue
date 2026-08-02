<script setup lang="ts">
import { computed, onMounted } from "vue";
import EmptyState from "../components/EmptyState.vue";
import ErrorState from "../components/ErrorState.vue";
import PageHeader from "../components/PageHeader.vue";
import StatCard from "../components/StatCard.vue";
import { api, type CompressionRecord } from "../api";
import { useAsync } from "../composables/useAsync";

// Records expire on their own, so a stale list would show sessions that no
// longer exist. Poll at half the shortest interval anything else here uses.
const req = useAsync(() => api.compressionSessions(200), {
  pollMs: 20_000,
  refreshLabel: "Compression sessions",
});
onMounted(req.run);

const records = computed<CompressionRecord[]>(() => req.data.value?.records ?? []);

/** Total tokens the summaries stand in for, minus what they cost. */
const savedTokens = computed(() =>
  records.value.reduce(
    (acc, r) => acc + Math.max(0, r.covered_input_tokens - r.summary_tokens),
    0,
  ),
);

const conflicts = computed(() => records.value.filter((r) => r.conflict_detected).length);

function fmt(n: number): string {
  return n.toLocaleString();
}

function when(ms: number): string {
  if (!ms) return "n/a";
  return new Date(ms).toLocaleString();
}

/** Compression ratio for one record, or null when nothing is covered yet. */
function ratio(r: CompressionRecord): string {
  if (!r.covered_input_tokens || !r.summary_tokens) return "n/a";
  return `${(r.covered_input_tokens / r.summary_tokens).toFixed(1)}x`;
}
</script>

<template>
  <PageHeader
    title="Compression"
    subtitle="Externalized conversation context. Summary text is never listed here."
  />

  <ErrorState
    v-if="req.error.value && !records.length"
    :error="req.error.value"
    title="Could not load compression sessions"
    @retry="req.run"
  />

  <template v-else>
    <div class="cards">
      <StatCard label="Records" :value="fmt(records.length)" />
      <StatCard label="Tokens saved" :value="fmt(savedTokens)" />
      <StatCard
        label="Write conflicts"
        :value="fmt(conflicts)"
        :tone="conflicts > 0 ? 'accent' : undefined"
      />
    </div>

    <EmptyState
      v-if="!records.length && !req.loading.value"
      message="No compression records. Records appear once a route with a compression profile handles a conversation."
    />

    <div v-else class="sb-card table-wrap">
      <table class="sb-table">
        <thead>
          <tr>
            <th>Origin</th>
            <th>Tenant</th>
            <th>Kind</th>
            <th>Covered</th>
            <th>Summary</th>
            <th>Ratio</th>
            <th>Summarizer</th>
            <th>Backend</th>
            <th>Updated</th>
            <th>Expires</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="r in records" :key="r.id">
            <td class="sb-mono">{{ r.origin }}</td>
            <td class="sb-mono">{{ r.tenant_id || "n/a" }}</td>
            <td>{{ r.kind }}</td>
            <td class="num">{{ fmt(r.covered_input_tokens) }}</td>
            <td class="num">{{ fmt(r.summary_tokens) }}</td>
            <td class="num">{{ ratio(r) }}</td>
            <td class="sb-mono">{{ r.summarizer_model || "n/a" }}</td>
            <td>
              {{ r.backend }}
              <span v-if="r.conflict_detected" class="warn" title="Concurrent write detected">
                conflict
              </span>
            </td>
            <td>{{ when(r.updated_at_unix_ms) }}</td>
            <td>{{ when(r.expires_at_unix_ms) }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </template>
</template>

<style scoped>
.cards {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  margin-bottom: 16px;
}
.table-wrap {
  overflow-x: auto;
}
.num {
  text-align: right;
  font-variant-numeric: tabular-nums;
}
.warn {
  margin-left: 6px;
  font-size: 11px;
  color: var(--sb-warn, #8a5a00);
}
</style>
