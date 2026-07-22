<script setup lang="ts">
import { computed, onMounted } from "vue";
import { useRoute } from "vue-router";
import { api, type RequestLog } from "../api";
import { useAsync } from "../composables/useAsync";
import { formatMs, formatNumber, formatTime, formatUsd } from "../lib/format";
import {
  buildSessionForest,
  durationOf,
  gatewayBadges,
  pathOf,
  sessionCallChain,
  statusOf,
  timestampOf,
} from "../lib/request-observability";
import PageHeader from "../components/PageHeader.vue";
import StatCard from "../components/StatCard.vue";
import StatusBadge from "../components/StatusBadge.vue";
import ErrorState from "../components/ErrorState.vue";
import EmptyState from "../components/EmptyState.vue";

const route = useRoute();
const req = useAsync(() => api.requests());
onMounted(req.run);

const sessionId = computed(() => {
  const value = route.params.sessionId;
  return Array.isArray(value) ? (value[0] ?? "") : String(value ?? "");
});
const requests = computed<RequestLog[]>(() => req.data.value ?? []);
const forest = computed(() => buildSessionForest(requests.value));
const session = computed(() => forest.value.byId.get(sessionId.value));
const chain = computed(() => sessionCallChain(requests.value, sessionId.value));
const parent = computed(() => {
  const parentId = session.value?.parentSessionId;
  return parentId ? forest.value.byId.get(parentId) : undefined;
});

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
  <nav class="breadcrumb sb-mono" aria-label="Breadcrumb">
    <RouterLink to="/sessions">Sessions</RouterLink>
    <span aria-hidden="true">/</span>
    <span>{{ sessionId }}</span>
  </nav>

  <PageHeader
    title="Session detail"
    subtitle="An oldest-first call chain reconstructed from the requests still present in the in-memory ring."
  >
    <template #actions>
      <RouterLink
        class="sb-btn"
        :to="{ path: '/logs', query: { session_id: sessionId } }"
      >
        Open in Logs
      </RouterLink>
      <button class="sb-btn sb-btn--primary" @click="req.run">Refresh</button>
    </template>
  </PageHeader>

  <ErrorState v-if="req.error.value" :error="req.error.value" @retry="req.run" />
  <template v-else-if="session">
    <section class="identity-panel">
      <span class="identity-panel__eyebrow sb-mono">session</span>
      <strong class="identity-panel__id sb-mono">{{ session.sessionId }}</strong>
      <div class="relations">
        <span v-if="session.parentSessionId">
          Parent:
          <RouterLink
            v-if="parent"
            :to="{
              name: 'session-detail',
              params: { sessionId: parent.sessionId },
            }"
            class="sb-mono"
          >
            {{ parent.sessionId }}
          </RouterLink>
          <span v-else class="sb-mono sb-faint">
            {{ session.parentSessionId }} (outside ring)
          </span>
        </span>
        <span v-if="session.children.length">
          Children:
          <RouterLink
            v-for="child in session.children"
            :key="child.sessionId"
            :to="{
              name: 'session-detail',
              params: { sessionId: child.sessionId },
            }"
            class="sb-mono child-link"
          >
            {{ child.sessionId }}
          </RouterLink>
        </span>
      </div>
    </section>

    <section class="session-totals" aria-label="Session totals">
      <StatCard label="Requests" :value="formatNumber(session.requestCount)" />
      <StatCard label="Tokens" :value="formatNumber(session.totalTokens)" />
      <StatCard
        label="Cost"
        :value="formatUsd(session.costUsdMicros / 1_000_000)"
        tone="accent"
      />
      <StatCard label="Wall clock" :value="formatMs(session.wallClockMs)" />
      <StatCard label="Worst status" :value="String(session.worstStatus ?? 'n/a')" />
    </section>

    <section class="chain-section">
      <div class="chain-heading">
        <div>
          <h2>Call chain</h2>
          <p>Oldest first. Timing is recorded latency, not a span waterfall.</p>
        </div>
        <StatusBadge
          :label="String(session.worstStatus ?? '?')"
          :tone="statusTone(session.worstStatus)"
        />
      </div>

      <ol class="call-chain">
        <li v-for="(request, index) in chain" :key="request.request_id ?? index">
          <span class="call-index sb-mono">{{ String(index + 1).padStart(2, "0") }}</span>
          <article class="call-card">
            <header class="call-head">
              <div class="call-route">
                <span class="sb-mono method">{{ request.method ?? "" }}</span>
                <strong class="sb-mono">{{ pathOf(request) || "n/a" }}</strong>
              </div>
              <div class="call-outcome">
                <StatusBadge
                  :label="String(statusOf(request) ?? '?')"
                  :tone="statusTone(statusOf(request))"
                />
                <span>{{ formatMs(durationOf(request)) }}</span>
              </div>
            </header>

            <div class="signal-rail" aria-label="Gateway decisions">
              <template
                v-for="(badge, badgeIndex) in gatewayBadges(request)"
                :key="`${badge.kind}-${badge.label}`"
              >
                <span v-if="badgeIndex" class="signal-join" aria-hidden="true">›</span>
                <StatusBadge :label="badge.label" :tone="badge.tone" />
              </template>
            </div>

            <dl class="call-fields">
              <div>
                <dt>Time</dt>
                <dd>{{ formatTime(timestampOf(request)) }}</dd>
              </div>
              <div v-if="request.request_id">
                <dt>Request</dt>
                <dd class="sb-mono">{{ request.request_id }}</dd>
              </div>
              <div v-if="request.trace_id">
                <dt>Trace</dt>
                <dd class="sb-mono">{{ request.trace_id }}</dd>
              </div>
              <div v-if="request.provider || request.model">
                <dt>AI route</dt>
                <dd>{{ request.provider ?? "n/a" }} / {{ request.model ?? "n/a" }}</dd>
              </div>
              <div v-if="request.tokens_in !== undefined || request.tokens_out !== undefined">
                <dt>Tokens</dt>
                <dd>
                  {{ formatNumber(request.tokens_in ?? 0) }} in,
                  {{ formatNumber(request.tokens_out ?? 0) }} out
                </dd>
              </div>
              <div v-if="request.cost_usd_micros !== undefined">
                <dt>Cost</dt>
                <dd>{{ formatUsd(request.cost_usd_micros / 1_000_000) }}</dd>
              </div>
            </dl>

            <div v-if="Object.keys(request.properties ?? {}).length" class="properties">
              <span
                v-for="([key, value]) in Object.entries(request.properties ?? {}).sort(([a], [b]) => a.localeCompare(b))"
                :key="key"
                class="property sb-mono"
              >
                {{ key }}={{ value }}
              </span>
            </div>
          </article>
        </li>
      </ol>
    </section>
  </template>
  <EmptyState
    v-else-if="!req.loading.value"
    message="This session is not present in the current request ring. It may have been evicted or recorded before the latest proxy restart."
  />
</template>

<style scoped>
.breadcrumb {
  display: flex;
  gap: var(--sb-space-2);
  margin-bottom: var(--sb-space-4);
  color: var(--sb-text-faint);
  font-size: 0.74rem;
}
.identity-panel {
  margin-bottom: var(--sb-space-4);
  padding: var(--sb-space-4);
  border: 1px solid var(--sb-border-ink);
  background: var(--sb-surface);
}
.identity-panel__eyebrow {
  display: block;
  margin-bottom: var(--sb-space-2);
  color: var(--sb-accent-strong);
  font-size: 0.68rem;
  text-transform: uppercase;
  letter-spacing: 0.12em;
}
.identity-panel__id {
  display: block;
  overflow-wrap: anywhere;
}
.relations {
  display: flex;
  flex-wrap: wrap;
  gap: var(--sb-space-3) var(--sb-space-5);
  margin-top: var(--sb-space-3);
  color: var(--sb-text-muted);
  font-size: 0.78rem;
}
.child-link {
  margin-left: var(--sb-space-2);
}
.session-totals {
  display: grid;
  grid-template-columns: repeat(5, minmax(0, 1fr));
  gap: var(--sb-space-3);
  margin-bottom: var(--sb-space-6);
}
.chain-heading {
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  gap: var(--sb-space-4);
  margin-bottom: var(--sb-space-4);
  padding-bottom: var(--sb-space-3);
  border-bottom: 1px solid var(--sb-border-ink);
}
.chain-heading h2,
.chain-heading p {
  margin: 0;
}
.chain-heading p {
  margin-top: 4px;
  color: var(--sb-text-muted);
  font-size: 0.82rem;
}
.call-chain {
  margin: 0;
  padding: 0;
  list-style: none;
}
.call-chain li {
  display: grid;
  grid-template-columns: 42px minmax(0, 1fr);
  position: relative;
}
.call-chain li:not(:last-child)::before {
  content: "";
  position: absolute;
  left: 16px;
  top: 31px;
  bottom: 0;
  width: 1px;
  background: var(--sb-border-accent);
}
.call-index {
  position: relative;
  z-index: 1;
  align-self: start;
  width: 32px;
  padding: 5px 0;
  border: 1px solid var(--sb-accent);
  background: var(--sb-surface);
  color: var(--sb-accent-strong);
  text-align: center;
  font-size: 0.68rem;
}
.call-card {
  margin-bottom: var(--sb-space-4);
  padding: var(--sb-space-4);
  border: 1px solid var(--sb-border);
  background: var(--sb-surface);
}
.call-head,
.call-route,
.call-outcome,
.signal-rail {
  display: flex;
  align-items: baseline;
  gap: var(--sb-space-2);
}
.call-head {
  justify-content: space-between;
  gap: var(--sb-space-4);
}
.call-route {
  min-width: 0;
}
.call-route strong {
  overflow-wrap: anywhere;
}
.method {
  color: var(--sb-accent-strong);
  font-size: 0.76rem;
}
.call-outcome {
  white-space: nowrap;
}
.signal-rail {
  margin-top: var(--sb-space-3);
  flex-wrap: wrap;
}
.signal-join {
  color: var(--sb-border-strong);
  font-family: var(--sb-font-mono);
}
.call-fields {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: var(--sb-space-3);
  margin: var(--sb-space-4) 0 0;
}
.call-fields div {
  min-width: 0;
}
.call-fields dt {
  margin-bottom: 3px;
  color: var(--sb-text-faint);
  font-family: var(--sb-font-mono);
  font-size: 0.64rem;
  text-transform: uppercase;
  letter-spacing: 0.08em;
}
.call-fields dd {
  margin: 0;
  overflow-wrap: anywhere;
  font-size: 0.8rem;
}
.properties {
  display: flex;
  flex-wrap: wrap;
  gap: var(--sb-space-2);
  margin-top: var(--sb-space-3);
  padding-top: var(--sb-space-3);
  border-top: 1px solid var(--sb-border);
}
.property {
  padding: 3px 6px;
  background: var(--sb-accent-tint);
  color: var(--sb-accent-strong);
  font-size: 0.68rem;
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
  .call-head {
    align-items: flex-start;
    flex-direction: column;
  }
}
</style>
