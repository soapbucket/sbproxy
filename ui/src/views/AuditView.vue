<script setup lang="ts">
import { computed, onMounted, ref, watch } from "vue";
import {
  api,
  type AuditEvent,
  type AuditRow,
} from "../api";
import { useAsync } from "../composables/useAsync";
import { toast } from "../composables/useToasts";
import { formatTime, shortId } from "../lib/format";
import PageHeader from "../components/PageHeader.vue";
import StatusBadge from "../components/StatusBadge.vue";
import ErrorState from "../components/ErrorState.vue";
import EmptyState from "../components/EmptyState.vue";
import WorkspaceBudgets from "../components/WorkspaceBudgets.vue";

const req = useAsync(() => api.auditRecent(100));

// WOR-2094: the unified security + change audit sample.
const channelFilter = ref<"" | "security" | "key" | "config" | "admin" | "policy">("");
const keyFilter = ref("");
const eventsReq = useAsync(() =>
  api.auditEvents({
    limit: 200,
    channel: channelFilter.value || undefined,
    keyId: keyFilter.value || undefined,
  }),
);
const events = computed<AuditEvent[]>(() =>
  Array.isArray(eventsReq.data.value) ? eventsReq.data.value : [],
);
watch([channelFilter, keyFilter], () => eventsReq.run());

function refresh() {
  req.run();
  eventsReq.run();
}
onMounted(refresh);

function channelTone(channel: string): "ok" | "warn" | "err" | "info" | "neutral" {
  switch (channel) {
    case "security":
      return "err";
    case "key":
      return "warn";
    case "config":
      return "info";
    case "admin":
      return "info";
    default:
      return "neutral";
  }
}

const rows = computed<AuditRow[]>(() => (Array.isArray(req.data.value) ? req.data.value : []));

function actionTone(action?: string): "ok" | "warn" | "err" | "neutral" {
  const a = (action ?? "").toLowerCase();
  if (a.includes("suspend") || a.includes("block")) return "err";
  if (a.includes("throttle") || a.includes("escalate")) return "warn";
  if (a.includes("resume") || a.includes("restore")) return "ok";
  return "neutral";
}
</script>

<template>
  <PageHeader
    title="Audit"
    subtitle="Security and change events, plus rate-limit budget actions, from the bounded runtime audit sample."
  >
    <template #actions>
      <button class="sb-btn sb-btn--sm" @click="refresh">Refresh</button>
    </template>
  </PageHeader>


  <!--
    WOR-2353: the budgets table and its Resume control moved into a shared
    component so Overview carries them too. They stay here because the
    budget audit trail below is the record of these actions, but Overview
    is where an operator looks when something needs attention.
  -->
  <WorkspaceBudgets @resumed="req.run()" />

  <!-- WOR-2094: security + change audit timeline -->
  <section class="section">
    <h2>Security and change events</h2>
    <div class="filter-row">
      <select v-model="channelFilter" class="sb-select" aria-label="Filter by channel">
        <option value="">all channels</option>
        <option value="security">security</option>
        <option value="key">key</option>
        <option value="config">config</option>
        <option value="admin">admin</option>
        <option value="policy">policy</option>
      </select>
      <input
        v-model="keyFilter"
        class="sb-input"
        placeholder="Filter by key ID"
        aria-label="Filter by key ID"
      />
    </div>
    <ErrorState
      v-if="eventsReq.error.value"
      :error="eventsReq.error.value"
      @retry="eventsReq.run"
    />
    <EmptyState
      v-else-if="!events.length"
      message="No audit events in the current sample. This is a bounded runtime view; the durable trail is whatever your collector ships the audit tracing targets to."
    />
    <div v-else class="table-wrap">
      <table class="sb-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Channel</th>
            <th>Kind</th>
            <th>Actor</th>
            <th>Key</th>
            <th>Detail</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="(e, i) in events" :key="i">
            <td class="sb-mono">{{ formatTime(e.timestamp) }}</td>
            <td><StatusBadge :label="e.channel" :tone="channelTone(e.channel)" /></td>
            <td class="sb-mono">{{ e.kind }}</td>
            <td class="sb-mono">{{ e.actor ?? "-" }}</td>
            <td class="sb-mono" :title="e.api_key_id">
              {{ e.api_key_id ? shortId(e.api_key_id) : "-" }}
            </td>
            <td>{{ e.detail ?? "-" }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </section>

  <!-- Budget audit trail -->
  <section class="section">
    <h2>Budget audit trail</h2>
    <ErrorState v-if="req.error.value" :error="req.error.value" @retry="req.run" />
    <EmptyState
      v-else-if="!rows.length"
      message="No budget audit events recorded. Rate-limit budget actions appear here; security and change events are in the section above."
    />
    <div v-else class="table-wrap">
      <table class="sb-table">
        <thead>
          <tr><th>Time</th><th>Action</th><th>Target</th><th>Reason</th></tr>
        </thead>
        <tbody>
          <tr v-for="(r, i) in rows" :key="i">
            <td class="sb-mono">{{ r.timestamp ? formatTime(r.timestamp) : "-" }}</td>
            <td><StatusBadge :label="r.action ?? 'unknown'" :tone="actionTone(r.action)" /></td>
            <td class="sb-mono">
              {{ r.target_kind ? `${r.target_kind}:` : "" }}{{ r.target_id ?? "-" }}
            </td>
            <td>{{ r.reason ?? "-" }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </section>
  <p class="sb-faint note">
    Both audit views are bounded runtime samples that clear on restart.
    The durable trail is whatever your log pipeline or OTel collector
    ships the audit tracing targets to.
  </p>
</template>

<style scoped>
.table-wrap {
  overflow-x: auto;
}
.section {
  margin-bottom: var(--sb-space-6);
}
.section h2 {
  margin-bottom: var(--sb-space-4);
}
.note {
  margin-top: var(--sb-space-4);
  font-size: 0.82rem;
}
.filter-row {
  display: flex;
  gap: var(--sb-space-3);
  margin-bottom: var(--sb-space-4);
  flex-wrap: wrap;
}
</style>
