<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { api, asList, type RequestLog } from "../api";
import { useAsync } from "../composables/useAsync";
import { formatTime, toDate } from "../lib/format";
import PageHeader from "../components/PageHeader.vue";
import StatusBadge from "../components/StatusBadge.vue";
import ErrorState from "../components/ErrorState.vue";
import EmptyState from "../components/EmptyState.vue";

const req = useAsync(() => api.requests());
onMounted(req.run);

const raw = computed<RequestLog[]>(() =>
  asList<RequestLog>(req.data.value, "requests", "items", "entries", "data"),
);

// ---- filters ----
const fMethod = ref("");
const fStatus = ref("");
const fPath = ref("");

function statusOf(r: RequestLog): number | undefined {
  return r.status ?? r.status_code;
}
function pathOf(r: RequestLog): string {
  return String(r.path ?? r.uri ?? "");
}
function timeOf(r: RequestLog): unknown {
  return r.time ?? r.timestamp ?? r.ts;
}
function durationOf(r: RequestLog): number | undefined {
  return r.duration_ms ?? r.latency_ms;
}

const methods = computed(() => {
  const set = new Set<string>();
  raw.value.forEach((r) => r.method && set.add(String(r.method).toUpperCase()));
  return [...set].sort();
});

const rows = computed<RequestLog[]>(() => {
  let list = [...raw.value];
  // Newest first, by parsed timestamp when available.
  list.sort((a, b) => {
    const da = toDate(timeOf(a))?.getTime() ?? 0;
    const db = toDate(timeOf(b))?.getTime() ?? 0;
    return db - da;
  });
  if (fMethod.value) {
    list = list.filter((r) => String(r.method ?? "").toUpperCase() === fMethod.value);
  }
  if (fStatus.value) {
    // Accept exact code or a class like "2xx".
    const q = fStatus.value.trim();
    list = list.filter((r) => {
      const s = statusOf(r);
      if (s === undefined) return false;
      if (/^\dxx$/i.test(q)) return String(s)[0] === q[0];
      return String(s).startsWith(q);
    });
  }
  if (fPath.value) {
    const q = fPath.value.toLowerCase();
    list = list.filter((r) => pathOf(r).toLowerCase().includes(q));
  }
  return list;
});

function statusTone(s: number | undefined): "ok" | "warn" | "err" | "info" | "neutral" {
  if (s === undefined) return "neutral";
  if (s < 300) return "ok";
  if (s < 400) return "info";
  if (s < 500) return "warn";
  return "err";
}

function clearFilters() {
  fMethod.value = "";
  fStatus.value = "";
  fPath.value = "";
}
</script>

<template>
  <PageHeader
    title="Logs"
    subtitle="Recent requests from the in-memory ring buffer. Live streaming is a planned follow-up; use Refresh to pull the latest snapshot."
  >
    <template #actions>
      <button class="sb-btn sb-btn--primary" @click="req.run">Refresh</button>
    </template>
  </PageHeader>

  <div class="filters">
    <select class="sb-select" v-model="fMethod" aria-label="Filter by method">
      <option value="">All methods</option>
      <option v-for="m in methods" :key="m" :value="m">{{ m }}</option>
    </select>
    <input class="sb-input" v-model="fStatus" placeholder="Status (e.g. 200 or 5xx)" aria-label="Filter by status" />
    <input class="sb-input" v-model="fPath" placeholder="Filter by path" aria-label="Filter by path" />
    <button class="sb-btn" @click="clearFilters">Clear</button>
    <span class="count sb-faint">{{ rows.length }} of {{ raw.length }}</span>
  </div>

  <ErrorState v-if="req.error.value" :error="req.error.value" @retry="req.run" />
  <EmptyState v-else-if="!raw.length" message="No requests recorded yet." />
  <EmptyState v-else-if="!rows.length" message="No requests match the current filters." />
  <div class="table-wrap" v-else>
    <table class="sb-table">
      <thead>
        <tr>
          <th>Time</th>
          <th>Method</th>
          <th>Path</th>
          <th>Status</th>
          <th>Duration</th>
          <th>Upstream</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="(r, i) in rows" :key="i">
          <td class="nowrap sb-muted">{{ formatTime(timeOf(r)) }}</td>
          <td class="sb-mono">{{ r.method ?? "" }}</td>
          <td class="sb-mono path">{{ pathOf(r) || "n/a" }}</td>
          <td><StatusBadge :label="String(statusOf(r) ?? '?')" :tone="statusTone(statusOf(r))" /></td>
          <td class="nowrap">{{ durationOf(r) !== undefined ? `${durationOf(r)} ms` : "n/a" }}</td>
          <td class="sb-mono sb-muted">{{ r.upstream ?? r.target ?? "" }}</td>
        </tr>
      </tbody>
    </table>
  </div>
</template>

<style scoped>
.filters {
  display: flex;
  gap: var(--sb-space-3);
  align-items: center;
  margin-bottom: var(--sb-space-4);
  flex-wrap: wrap;
}
.filters .sb-select {
  width: auto;
}
.filters .sb-input {
  width: auto;
  flex: 1;
  min-width: 160px;
}
.count {
  font-size: 0.8rem;
  margin-left: auto;
}
.table-wrap {
  border: 1px solid var(--sb-border);
  border-radius: var(--sb-radius);
  overflow-x: auto;
}
.nowrap {
  white-space: nowrap;
}
.path {
  max-width: 420px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
</style>
