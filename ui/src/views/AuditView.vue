<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { api, ApiError, type AuditRow, type WorkspaceStatus } from "../api";
import { useAsync } from "../composables/useAsync";
import { toast } from "../composables/useToasts";
import { formatTime, toDate } from "../lib/format";
import PageHeader from "../components/PageHeader.vue";
import StatusBadge from "../components/StatusBadge.vue";
import ErrorState from "../components/ErrorState.vue";
import EmptyState from "../components/EmptyState.vue";

const req = useAsync(() => api.auditRecent(100));
const budgetReq = useAsync(() => api.budgetSnapshot());
function refresh() {
  req.run();
  budgetReq.run();
}
onMounted(refresh);

const rows = computed<AuditRow[]>(() => (Array.isArray(req.data.value) ? req.data.value : []));

// Budget snapshot (WOR-1764). 404 means no rate_limits block; treat as empty.
const budgets = computed<WorkspaceStatus[]>(() =>
  Array.isArray(budgetReq.data.value) ? budgetReq.data.value : [],
);
const budgetConfigured = computed(
  () => !(budgetReq.error.value instanceof ApiError && budgetReq.error.value.status === 404),
);

const busy = ref("");
async function resume(ws: string) {
  if (busy.value) return;
  busy.value = ws;
  try {
    await api.resumeWorkspace(ws);
    toast.success(`Resumed "${ws}"`);
    budgetReq.run();
    req.run();
  } catch (e) {
    toast.error(e, "Resume workspace");
  } finally {
    busy.value = "";
  }
}

function tierTone(tier?: string): "ok" | "warn" | "err" | "neutral" {
  switch (tier) {
    case "auto_suspend":
      return "err";
    case "throttle":
      return "warn";
    case "soft":
      return "warn";
    case "normal":
      return "ok";
    default:
      return "neutral";
  }
}

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
      <button class="sb-btn sb-btn--sm" @click="refresh">Refresh</button>
    </template>
  </PageHeader>


  <!-- Workspace budgets + manual resume (WOR-1764) -->
  <section class="section" v-if="budgetConfigured">
    <h2>Workspace budgets</h2>
    <EmptyState
      v-if="!budgets.length"
      message="No workspaces have tripped the rate-limit budget yet."
    />
    <div v-else class="table-wrap">
      <table class="sb-table">
        <thead>
          <tr><th>Workspace</th><th>Tier</th><th>Cooldown</th><th></th></tr>
        </thead>
        <tbody>
          <tr v-for="b in budgets" :key="b.workspace">
            <td class="sb-mono">{{ b.workspace }}</td>
            <td><StatusBadge :label="b.tier ?? 'unknown'" :tone="tierTone(b.tier)" /></td>
            <td>{{ b.cooldown_secs != null ? `${b.cooldown_secs}s` : "-" }}</td>
            <td>
              <button
                v-if="b.suspended && b.workspace"
                class="sb-btn sb-btn--sm"
                :disabled="busy === b.workspace"
                @click="resume(b.workspace)"
              >
                {{ busy === b.workspace ? "Resuming..." : "Resume" }}
              </button>
            </td>
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
  </section>
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
</style>
