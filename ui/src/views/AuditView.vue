<script setup lang="ts">
import { computed, onMounted } from "vue";
import { api, type AuditRow } from "../api";
import { useAsync } from "../composables/useAsync";
import { formatTime, toDate } from "../lib/format";
import PageHeader from "../components/PageHeader.vue";
import StatusBadge from "../components/StatusBadge.vue";
import ErrorState from "../components/ErrorState.vue";
import EmptyState from "../components/EmptyState.vue";

const req = useAsync(() => api.auditRecent(100));
onMounted(req.run);

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
    subtitle="Rate-limit budget actions (suspend, throttle, resume) with the reason each fired."
  >
    <template #actions>
      <button class="sb-btn sb-btn--sm" @click="req.run">Refresh</button>
    </template>
  </PageHeader>

  <ErrorState v-if="req.error.value" :error="req.error.value" @retry="req.run" />
  <EmptyState
    v-else-if="!rows.length"
    message="No budget audit events recorded. Rate-limit budget actions appear here; broader admin-action audit (logins, config edits) is written to the tracing log under the admin::audit target."
  />
  <div v-else class="table-wrap">
    <table class="sb-table">
      <thead>
        <tr><th>Time</th><th>Action</th><th>Target</th><th>Reason</th></tr>
      </thead>
      <tbody>
        <tr v-for="(r, i) in rows" :key="i">
          <td class="sb-mono">{{ r.timestamp ? formatTime(toDate(r.timestamp)) : "-" }}</td>
          <td><StatusBadge :label="r.action ?? 'unknown'" :tone="actionTone(r.action)" /></td>
          <td class="sb-mono">
            {{ r.target_kind ? `${r.target_kind}:` : "" }}{{ r.target_id ?? "-" }}
          </td>
          <td>{{ r.reason ?? "-" }}</td>
        </tr>
      </tbody>
    </table>
  </div>
  <p class="sb-faint note">
    This trail covers rate-limit budget decisions. Login, config, and key
    changes are audited to the structured log (admin::audit), not this
    in-memory ring.
  </p>
</template>

<style scoped>
.table-wrap {
  overflow-x: auto;
}
.note {
  margin-top: var(--sb-space-4);
  font-size: 0.82rem;
}
</style>
