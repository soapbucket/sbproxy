<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useRoute, useRouter } from "vue-router";
import { api, type RoutingDecision, type RoutingDecisionFilters } from "../api";
import { useAsync } from "../composables/useAsync";
import { filterStateFromQuery, filterStateToQuery } from "../lib/filter-url";
import { formatMs, formatTime, shortId } from "../lib/format";
import PageHeader from "../components/PageHeader.vue";
import StatusBadge from "../components/StatusBadge.vue";
import ErrorState from "../components/ErrorState.vue";
import EmptyState from "../components/EmptyState.vue";

const route = useRoute();
const router = useRouter();

// One ref per filter dimension; empty string means "not filtered".
const fOrigin = ref("");
const fStrategy = ref("");
const fModel = ref("");
const fProvider = ref("");
// Time range as a rolling window; the API takes an RFC 3339 `since`.
const fWindow = ref("");
const WINDOWS: Array<{ value: string; label: string; ms: number }> = [
  { value: "15m", label: "Last 15 minutes", ms: 15 * 60 * 1000 },
  { value: "1h", label: "Last hour", ms: 60 * 60 * 1000 },
  { value: "24h", label: "Last 24 hours", ms: 24 * 60 * 60 * 1000 },
];

// Computed at load time, not cached: a rolling window's `since` must be
// relative to the moment of the fetch, or Refresh resends a stale cut.
function currentFilters(): RoutingDecisionFilters {
  const windowMs = WINDOWS.find((w) => w.value === fWindow.value)?.ms;
  return {
    ...(fOrigin.value ? { origin: fOrigin.value } : {}),
    ...(fStrategy.value ? { strategy: fStrategy.value } : {}),
    ...(fModel.value ? { model: fModel.value } : {}),
    ...(fProvider.value ? { provider: fProvider.value } : {}),
    ...(windowMs
      ? { since: new Date(Date.now() - windowMs).toISOString() }
      : {}),
  };
}

const req = useAsync(() => api.routingDecisions(currentFilters()));
const rows = computed<RoutingDecision[]>(() => req.data.value ?? []);

const FILTER_KEYS = [
  "origin",
  "strategy",
  "model",
  "provider",
  "window",
] as const;

// Same contract as the Reports view: the URL is the saved filter, over
// every dimension the view offers rather than three of the five. A
// link that carries `?provider=anthropic` has to come back filtered to
// anthropic, and applying a filter here has to leave a link worth
// sharing.
function syncStateToUrl() {
  router.replace({
    query: filterStateToQuery({
      origin: fOrigin.value,
      strategy: fStrategy.value,
      model: fModel.value,
      provider: fProvider.value,
      window: fWindow.value,
    }),
  });
}

function applyFilters() {
  syncStateToUrl();
  req.run();
}

onMounted(() => {
  const state = filterStateFromQuery(route.query, FILTER_KEYS);
  fOrigin.value = state.origin;
  fStrategy.value = state.strategy;
  fModel.value = state.model;
  fProvider.value = state.provider;
  // A hand-edited link can name a window this view does not offer;
  // fall back to "no window" rather than sending a `since` of NaN.
  fWindow.value = WINDOWS.some((w) => w.value === state.window)
    ? state.window
    : "";
  req.run();
});

function clearFilters() {
  fOrigin.value = "";
  fStrategy.value = "";
  fModel.value = "";
  fProvider.value = "";
  fWindow.value = "";
  applyFilters();
}

// Option sets derived from the data on screen, like the Logs view.
const origins = computed(() =>
  [...new Set(rows.value.map((d) => d.origin).filter(Boolean))].sort(),
);
const strategies = computed(() =>
  [...new Set(rows.value.map((d) => d.strategy).filter(Boolean))].sort(),
);

const expandedKey = ref<string | null>(null);
function rowKey(decision: RoutingDecision, index: number): string {
  return decision.request_id ?? `${decision.timestamp ?? ""}-${index}`;
}
function toggleExpand(decision: RoutingDecision, index: number) {
  const key = rowKey(decision, index);
  expandedKey.value = expandedKey.value === key ? null : key;
}

function statusTone(status?: number): "ok" | "warn" | "err" | "neutral" {
  if (status === undefined) return "neutral";
  if (status >= 500) return "err";
  if (status >= 400) return "warn";
  return "ok";
}

/** The winner as "provider / model", tolerating either side missing. */
function winnerOf(decision: RoutingDecision): string {
  const provider = decision.selected_provider ?? "";
  const model = decision.selected_model ?? "";
  if (provider && model) return `${provider} / ${model}`;
  return provider || model || "n/a";
}

/** True when the served model differs from the requested one. */
function substituted(decision: RoutingDecision): boolean {
  return Boolean(
    decision.requested_model &&
      decision.selected_model &&
      decision.requested_model !== decision.selected_model,
  );
}

interface DetailField {
  label: string;
  value: string;
}

function detailFields(decision: RoutingDecision): DetailField[] {
  const fields: DetailField[] = [];
  const push = (label: string, value: unknown) => {
    if (value === undefined || value === null || value === "") return;
    fields.push({ label, value: String(value) });
  };
  push("Request", decision.request_id);
  push("Tenant", decision.tenant_id);
  push("Requested model", decision.requested_model);
  push("Selected model", decision.selected_model);
  push("Attempts", decision.attempts);
  if (decision.failover_from || decision.failover_to) {
    push(
      "Failover",
      `${decision.failover_from ?? "?"} -> ${decision.failover_to ?? "?"}`,
    );
  }
  push("Reason", decision.reason);
  return fields;
}

/** The open detail map, rendered as stable key/value rows. Additive
 *  columns from later features appear here without a UI change. */
function extraDetail(decision: RoutingDecision): DetailField[] {
  const detail = decision.detail;
  if (!detail) return [];
  return Object.keys(detail)
    .sort()
    .map((key) => {
      const value = detail[key];
      return {
        label: key,
        value: typeof value === "string" ? value : JSON.stringify(value),
      };
    });
}
</script>

<template>
  <PageHeader
    title="Routing decisions"
    subtitle="Why each request was routed where it was: the strategy or plan that decided, the candidates it weighed, the winner, and the fallback chain it traversed."
  >
    <template #actions>
      <button class="sb-btn sb-btn--primary" @click="req.run">Refresh</button>
    </template>
  </PageHeader>

  <section class="filter-panel" aria-label="Routing decision filters">
    <div class="filters">
      <select
        v-if="origins.length > 1"
        v-model="fOrigin"
        class="sb-select"
        aria-label="Filter by origin"
      >
        <option value="">All origins</option>
        <option v-for="origin in origins" :key="origin" :value="origin">
          {{ origin }}
        </option>
      </select>
      <select
        v-if="strategies.length > 1"
        v-model="fStrategy"
        class="sb-select"
        aria-label="Filter by strategy"
      >
        <option value="">All strategies</option>
        <option v-for="strategy in strategies" :key="strategy" :value="strategy">
          {{ strategy }}
        </option>
      </select>
      <input
        v-model.trim="fModel"
        class="sb-input"
        placeholder="Model (requested or served)"
        aria-label="Filter by model"
        @keydown.enter="req.run"
      />
      <input
        v-model.trim="fProvider"
        class="sb-input"
        placeholder="Provider"
        aria-label="Filter by selected provider"
        @keydown.enter="req.run"
      />
      <select v-model="fWindow" class="sb-select" aria-label="Filter by time range">
        <option value="">All time in ring</option>
        <option v-for="window in WINDOWS" :key="window.value" :value="window.value">
          {{ window.label }}
        </option>
      </select>
    </div>
    <div class="filter-actions">
      <button class="sb-btn sb-btn--sm sb-btn--primary" @click="applyFilters">
        Apply
      </button>
      <button class="sb-btn sb-btn--sm" @click="clearFilters">Clear</button>
      <span class="count sb-faint">{{ rows.length }} decisions</span>
    </div>
  </section>

  <ErrorState v-if="req.error.value" :error="req.error.value" @retry="req.run" />
  <EmptyState
    v-else-if="!req.loading.value && !rows.length"
    message="No routing decisions recorded yet. Decisions appear once routed traffic (AI dispatch or a load-balanced origin) flows through the gateway."
  />
  <div v-else-if="rows.length" class="table-wrap">
    <table class="sb-table decision-ledger">
      <thead>
        <tr>
          <th>Time</th>
          <th>Origin</th>
          <th>Strategy</th>
          <th>Winner</th>
          <th>Chain</th>
          <th>Reason</th>
          <th>Status</th>
          <th>Duration</th>
        </tr>
      </thead>
      <tbody>
        <template v-for="(decision, index) in rows" :key="rowKey(decision, index)">
          <tr
            class="row"
            tabindex="0"
            :aria-expanded="expandedKey === rowKey(decision, index)"
            @click="toggleExpand(decision, index)"
            @keydown.enter="toggleExpand(decision, index)"
            @keydown.space.prevent="toggleExpand(decision, index)"
          >
            <td class="nowrap sb-muted">{{ formatTime(decision.timestamp) }}</td>
            <td class="sb-mono">{{ decision.origin ?? "" }}</td>
            <td>
              <StatusBadge
                :label="decision.strategy ?? '?'"
                :tone="decision.strategy === 'ai_routing_policy' ? 'info' : 'neutral'"
              />
            </td>
            <td class="sb-mono winner">
              {{ winnerOf(decision) }}
              <StatusBadge v-if="substituted(decision)" label="substituted" tone="warn" />
            </td>
            <td>
              <div class="signal-rail" aria-label="Providers attempted">
                <template
                  v-for="(provider, hop) in decision.attempted ?? []"
                  :key="`${provider}-${hop}`"
                >
                  <span v-if="hop" class="signal-join" aria-hidden="true">›</span>
                  <span class="sb-mono">{{ provider }}</span>
                </template>
                <span
                  v-if="!(decision.attempted ?? []).length"
                  class="sb-faint"
                >direct</span>
              </div>
            </td>
            <td class="reason" :title="decision.reason">{{ decision.reason ?? "" }}</td>
            <td>
              <StatusBadge
                :label="String(decision.status ?? '?')"
                :tone="statusTone(decision.status)"
              />
            </td>
            <td class="nowrap">{{ formatMs(decision.latency_ms) }}</td>
          </tr>
          <tr v-if="expandedKey === rowKey(decision, index)" class="detail-row">
            <td colspan="8">
              <div v-if="(decision.candidates ?? []).length" class="candidates">
                <p class="sb-eyebrow">Candidates weighed, in order</p>
                <ol class="candidate-list">
                  <li
                    v-for="(candidate, rank) in decision.candidates"
                    :key="`${candidate.provider}-${rank}`"
                    class="sb-mono"
                  >
                    {{ candidate.provider
                    }}<template v-if="candidate.model"> / {{ candidate.model }}</template>
                    <StatusBadge
                      v-if="candidate.provider === decision.selected_provider"
                      label="selected"
                      tone="ok"
                    />
                  </li>
                </ol>
              </div>
              <div class="detail-grid">
                <div
                  v-for="field in detailFields(decision)"
                  :key="field.label"
                  class="detail-item"
                >
                  <span class="detail-label">{{ field.label }}</span>
                  <span class="sb-mono detail-value">
                    {{ field.label === "Request" ? shortId(field.value) : field.value }}
                  </span>
                </div>
                <div
                  v-for="field in extraDetail(decision)"
                  :key="`detail-${field.label}`"
                  class="detail-item"
                >
                  <span class="detail-label sb-mono">{{ field.label }}</span>
                  <span class="sb-mono detail-value">{{ field.value }}</span>
                </div>
              </div>
            </td>
          </tr>
        </template>
      </tbody>
    </table>
  </div>
</template>

<style scoped>
.filter-panel {
  border-top: 1px solid var(--sb-border-ink);
  border-bottom: 1px solid var(--sb-border);
  padding: var(--sb-space-3) 0;
  margin-bottom: var(--sb-space-4);
}
.filters,
.filter-actions {
  display: flex;
  gap: var(--sb-space-2);
  align-items: center;
  flex-wrap: wrap;
}
.filter-actions {
  margin-top: var(--sb-space-2);
}
.filters .sb-select,
.filters .sb-input {
  width: auto;
  min-width: 135px;
  flex: 1;
}
.count {
  font-size: 0.8rem;
  margin-left: auto;
}
.table-wrap {
  border: 1px solid var(--sb-border);
  overflow-x: auto;
}
.decision-ledger {
  min-width: 960px;
}
.nowrap {
  white-space: nowrap;
}
.row {
  cursor: pointer;
}
.row:focus-visible {
  outline: 2px solid var(--sb-accent);
  outline-offset: -2px;
}
.winner {
  white-space: nowrap;
}
.reason {
  max-width: 280px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.signal-rail {
  display: flex;
  align-items: baseline;
  gap: 5px;
  min-width: max-content;
}
.signal-join {
  color: var(--sb-border-strong);
  font-family: var(--sb-font-mono);
}
.detail-row td {
  background: var(--sb-surface-2);
}
.candidates {
  margin-bottom: var(--sb-space-3);
}
.candidate-list {
  margin: var(--sb-space-2) 0 0;
  padding-left: var(--sb-space-5);
  display: grid;
  gap: 4px;
  font-size: 0.85rem;
}
.detail-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
  gap: var(--sb-space-3);
}
.detail-item {
  display: grid;
  gap: 2px;
}
.detail-label {
  font-size: 0.72rem;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--sb-text-muted);
}
.detail-value {
  font-size: 0.85rem;
  overflow-wrap: anywhere;
}
</style>
