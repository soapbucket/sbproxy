<script setup lang="ts">
import { computed, onMounted } from "vue";
import { api, type RequestLog } from "../api";
import { useAsync } from "../composables/useAsync";
import { formatMs, formatNumber, formatTime, formatUsd } from "../lib/format";
import {
  logGroups,
  rollupRequests,
  type SessionSummary,
} from "../lib/request-observability";
import PageHeader from "../components/PageHeader.vue";
import StatCard from "../components/StatCard.vue";
import StatusBadge from "../components/StatusBadge.vue";
import ErrorState from "../components/ErrorState.vue";
import EmptyState from "../components/EmptyState.vue";

const req = useAsync(() => api.requests());
onMounted(req.run);

const requests = computed<RequestLog[]>(() => req.data.value ?? []);
const sessionRequests = computed(() =>
  requests.value.filter(
    (request) =>
      typeof request.session_id === "string" && request.session_id.length > 0,
  ),
);
const groups = computed(() =>
  logGroups(sessionRequests.value, true).filter(
    (group): group is typeof group & { session: SessionSummary } =>
      group.session !== undefined,
  ),
);
const totals = computed(() => rollupRequests(sessionRequests.value));
const ungroupedCount = computed(
  () => requests.value.length - sessionRequests.value.length,
);

function statusTone(
  status: number | undefined,
): "ok" | "warn" | "err" | "info" | "neutral" {
  if (status === undefined) return "neutral";
  if (status < 300) return "ok";
  if (status < 400) return "info";
  if (status < 500) return "warn";
  return "err";
}
</script>

<template>
  <PageHeader
    title="Sessions"
    subtitle="Recent request sessions reconstructed from the in-memory request ring. Open a session to read its calls in causal order."
  >
    <template #actions>
      <button class="sb-btn sb-btn--primary" @click="req.run">Refresh</button>
    </template>
  </PageHeader>

  <aside class="retention-note">
    <strong>Recent view.</strong>
    Sessions are not durable traces. A restart or ring eviction can remove requests from
    a session, and this page never replays traffic.
    <span v-if="ungroupedCount">{{ ungroupedCount }} current requests have no session ID.</span>
  </aside>

  <p
    v-if="req.loading.value && !req.data.value"
    class="loading-state sb-mono sb-faint"
    role="status"
    aria-live="polite"
  >
    Loading recent sessions...
  </p>
  <ErrorState v-else-if="req.error.value" :error="req.error.value" @retry="req.run" />
  <template v-else-if="sessionRequests.length">
    <section class="session-totals" aria-label="Current ring session totals">
      <StatCard label="Requests" :value="formatNumber(totals.requestCount)" />
      <StatCard label="Tokens" :value="formatNumber(totals.totalTokens)" />
      <StatCard
        label="Cost"
        :value="formatUsd(totals.costUsdMicros / 1_000_000)"
        tone="accent"
      />
      <StatCard label="Wall clock" :value="formatMs(totals.wallClockMs)" />
      <StatCard
        label="Worst status"
        :value="String(totals.worstStatus ?? 'n/a')"
      />
    </section>

    <section class="session-index">
      <div class="section-heading">
        <h2>Session index</h2>
        <span class="sb-faint">{{ groups.length }} sessions in this ring</span>
      </div>
      <div class="table-wrap">
        <table class="sb-table">
          <thead>
            <tr>
              <th>Session</th>
              <th>Started</th>
              <th>Requests</th>
              <th>Tokens</th>
              <th>Cost</th>
              <th>Duration</th>
              <th>Worst</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="group in groups" :key="group.key">
              <td>
                <div
                  class="session-cell"
                  :style="{ paddingLeft: `${group.depth * 20}px` }"
                >
                  <span class="session-rail" aria-hidden="true" />
                  <RouterLink
                    class="sb-mono session-link"
                    :to="{
                      name: 'session-detail',
                      params: { sessionId: group.session.sessionId },
                    }"
                  >
                    {{ group.session.sessionId }}
                  </RouterLink>
                  <StatusBadge
                    v-if="group.kind === 'orphan'"
                    label="parent outside ring"
                    tone="warn"
                  />
                </div>
                <span
                  v-if="group.session.parentSessionId"
                  class="parent-label sb-mono sb-faint"
                >
                  parent {{ group.session.parentSessionId }}
                </span>
              </td>
              <td class="nowrap">{{ formatTime(group.session.startedAt) }}</td>
              <td>{{ formatNumber(group.session.requestCount) }}</td>
              <td>{{ formatNumber(group.session.totalTokens) }}</td>
              <td>{{ formatUsd(group.session.costUsdMicros / 1_000_000) }}</td>
              <td>{{ formatMs(group.session.wallClockMs) }}</td>
              <td>
                <StatusBadge
                  :label="String(group.session.worstStatus ?? '?')"
                  :tone="statusTone(group.session.worstStatus)"
                />
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>
  </template>
  <EmptyState
    v-else-if="!req.loading.value"
    message="No session-linked requests are present in the current ring."
  />
</template>

<style scoped>
.retention-note {
  display: flex;
  align-items: baseline;
  flex-wrap: wrap;
  gap: var(--sb-space-2);
  margin-bottom: var(--sb-space-5);
  padding: var(--sb-space-3) var(--sb-space-4);
  border-left: 3px solid var(--sb-accent);
  background: var(--sb-surface-2);
  color: var(--sb-text-muted);
  font-size: 0.84rem;
}
.loading-state {
  padding: var(--sb-space-5) 0;
  font-size: 0.78rem;
}
.retention-note strong {
  color: var(--sb-text);
}
.session-totals {
  display: grid;
  grid-template-columns: repeat(5, minmax(0, 1fr));
  gap: var(--sb-space-3);
  margin-bottom: var(--sb-space-6);
}
.section-heading {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: var(--sb-space-3);
  margin-bottom: var(--sb-space-3);
}
.section-heading h2 {
  margin: 0;
}
.section-heading span {
  font-size: 0.78rem;
}
.table-wrap {
  border: 1px solid var(--sb-border);
  overflow-x: auto;
}
.session-cell {
  display: flex;
  align-items: center;
  gap: var(--sb-space-2);
  min-width: 270px;
}
.session-rail {
  width: 18px;
  height: 1px;
  background: var(--sb-accent);
  flex: none;
}
.session-link {
  color: var(--sb-text);
  font-weight: 600;
}
.parent-label {
  display: block;
  margin: 4px 0 0 26px;
  font-size: 0.66rem;
}
.nowrap {
  white-space: nowrap;
}
@media (max-width: 900px) {
  .session-totals {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}
@media (max-width: 520px) {
  .session-totals {
    grid-template-columns: 1fr;
  }
}
</style>
