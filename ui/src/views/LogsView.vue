<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from "vue";
import { useRoute } from "vue-router";
import { api, type RequestFilters, type RequestLog } from "../api";
import { useAsync } from "../composables/useAsync";
import { toast } from "../composables/useToasts";
import { formatMs, formatNumber, formatTime, formatUsd } from "../lib/format";
import {
  discoverPropertyKeys,
  durationOf,
  gatewayBadges,
  logGroups,
  pathOf,
  requestMatchesFilters,
  restorePropertyColumns,
  statusOf,
  timestampMillis,
  timestampOf,
} from "../lib/request-observability";
import PageHeader from "../components/PageHeader.vue";
import StatusBadge from "../components/StatusBadge.vue";
import ErrorState from "../components/ErrorState.vue";
import EmptyState from "../components/EmptyState.vue";

const route = useRoute();

// Snapshot and live rows use the same predicate. The server receives every
// bounded filter it supports; origin, status classes, and session stay local.
const fMethod = ref("");
const fOrigin = ref("");
const fStatus = ref("");
const fPath = ref("");
const fGuardrail = ref("");
const fCache = ref("");
const fRetried = ref<"" | "true" | "false">("");
const fPropertyKey = ref("");
const fPropertyValue = ref("");
const fSession = ref("");

const filters = computed<RequestFilters>(() => ({
  ...(fMethod.value ? { method: fMethod.value } : {}),
  ...(fOrigin.value ? { origin: fOrigin.value } : {}),
  ...(fStatus.value ? { status: fStatus.value } : {}),
  ...(fPath.value ? { path: fPath.value } : {}),
  ...(fGuardrail.value ? { guardrailAction: fGuardrail.value } : {}),
  ...(fCache.value ? { cacheStatus: fCache.value } : {}),
  ...(fRetried.value ? { retried: fRetried.value === "true" } : {}),
  ...(fPropertyKey.value ? { propertyKey: fPropertyKey.value } : {}),
  ...(fPropertyKey.value && fPropertyValue.value
    ? { propertyValue: fPropertyValue.value }
    : {}),
  ...(fSession.value ? { sessionId: fSession.value } : {}),
}));

const req = useAsync(() => api.requests(filters.value));
const snapshot = computed<RequestLog[]>(() => req.data.value ?? []);

onMounted(() => {
  const guardrail = route.query.guardrail_action;
  if (typeof guardrail === "string") fGuardrail.value = guardrail;
  const session = route.query.session_id;
  if (typeof session === "string") fSession.value = session;
  req.run();
  loadLogLevel();
  loadUiSettings();
  loadPreferences();
});
onUnmounted(stopStream);

// Live tail over the request ring.
const STREAM_ROW_CAP = 1000;
const live = ref(false);
const paused = ref(false);
const streamState = ref<"idle" | "open" | "reconnecting">("idle");
const streamRows = ref<RequestLog[]>([]);
const pendingRows = ref<RequestLog[]>([]);
let source: EventSource | null = null;

function startStream() {
  stopStream();
  streamRows.value = [...snapshot.value];
  pendingRows.value = [];
  paused.value = false;
  streamState.value = "reconnecting";
  source = new EventSource(api.requestsStreamUrl());
  source.onopen = () => {
    streamState.value = "open";
  };
  source.onerror = () => {
    streamState.value = "reconnecting";
  };
  source.onmessage = (event) => {
    try {
      const request = JSON.parse(event.data) as RequestLog;
      const target = paused.value ? pendingRows.value : streamRows.value;
      target.unshift(request);
      if (target.length > STREAM_ROW_CAP) target.length = STREAM_ROW_CAP;
    } catch {
      // Heartbeats and malformed frames are not request rows.
    }
  };
  live.value = true;
}

function stopStream() {
  source?.close();
  source = null;
  streamState.value = "idle";
  live.value = false;
  paused.value = false;
}

function toggleLive() {
  if (live.value) stopStream();
  else startStream();
}

function togglePause() {
  if (!live.value) return;
  if (paused.value) {
    streamRows.value = [...pendingRows.value, ...streamRows.value].slice(
      0,
      STREAM_ROW_CAP,
    );
    pendingRows.value = [];
  }
  paused.value = !paused.value;
}

const raw = computed<RequestLog[]>(() =>
  live.value ? streamRows.value : snapshot.value,
);

// Trace deep links.
const traceTemplate = ref("");
async function loadUiSettings() {
  try {
    traceTemplate.value = (await api.uiSettings()).trace_url_template ?? "";
  } catch {
    // Older servers render trace ids as plain text.
  }
}
function traceUrl(request: RequestLog): string | null {
  if (!traceTemplate.value || !request.trace_id) return null;
  return traceTemplate.value.replaceAll("{trace_id}", request.trace_id);
}

// Runtime log level.
const logLevel = ref("");
const levelDraft = ref("");
const levelBusy = ref(false);
const LEVEL_PRESETS = ["info", "debug", "trace", "sbproxy_ai=debug"];
async function loadLogLevel() {
  try {
    logLevel.value = (await api.logLevel()).level ?? "";
    levelDraft.value = logLevel.value;
  } catch {
    // Hide the control when an older server lacks the endpoint.
  }
}
async function applyLogLevel(value: string) {
  if (levelBusy.value || !value.trim()) return;
  levelBusy.value = true;
  try {
    logLevel.value = (await api.setLogLevel(value)).level ?? value;
    levelDraft.value = logLevel.value;
    toast.success(`Log level set to ${logLevel.value}`);
  } catch (error) {
    toast.error(error, "Set log level");
  } finally {
    levelBusy.value = false;
  }
}

const methods = computed(() => {
  const values = new Set<string>();
  raw.value.forEach((request) => {
    if (request.method) values.add(request.method.toUpperCase());
  });
  return [...values].sort();
});
const origins = computed(() => {
  const values = new Set<string>();
  raw.value.forEach((request) => {
    if (request.origin) values.add(request.origin);
  });
  return [...values].sort();
});
const propertyKeys = computed(() => discoverPropertyKeys(raw.value));

const rows = computed<RequestLog[]>(() =>
  [...raw.value]
    .sort(
      (a, b) =>
        (timestampMillis(b) ?? Number.NEGATIVE_INFINITY) -
        (timestampMillis(a) ?? Number.NEGATIVE_INFINITY),
    )
    .filter((request) => requestMatchesFilters(request, filters.value)),
);

function applyFilters() {
  if (!live.value) req.run();
}
function clearFilters() {
  fMethod.value = "";
  fOrigin.value = "";
  fStatus.value = "";
  fPath.value = "";
  fGuardrail.value = "";
  fCache.value = "";
  fRetried.value = "";
  fPropertyKey.value = "";
  fPropertyValue.value = "";
  fSession.value = "";
  if (!live.value) req.run();
}

// Operator presentation preferences.
const PROPERTY_COLUMNS_KEY = "sbproxy.logs.property-columns.v1";
const SESSION_GROUP_KEY = "sbproxy.logs.group-session.v1";
const selectedPropertyKeys = ref<string[]>([]);
const propertyColumnsStored = ref<string | null>(null);
const propertyColumnsHydrated = ref(false);
const groupBySession = ref(false);

function loadPreferences() {
  try {
    propertyColumnsStored.value = window.localStorage.getItem(PROPERTY_COLUMNS_KEY);
    groupBySession.value =
      window.localStorage.getItem(SESSION_GROUP_KEY) === "true";
  } catch {
    // Storage can be unavailable in locked-down browsers.
  }
}

watch(propertyKeys, (available) => {
  if (propertyColumnsHydrated.value || !available.length) return;
  selectedPropertyKeys.value = restorePropertyColumns(
    available,
    propertyColumnsStored.value,
  );
  propertyColumnsHydrated.value = true;
});

function togglePropertyColumn(key: string) {
  const selected = new Set(selectedPropertyKeys.value);
  if (selected.has(key)) selected.delete(key);
  else selected.add(key);
  selectedPropertyKeys.value = propertyKeys.value.filter((candidate) =>
    selected.has(candidate),
  );
  try {
    window.localStorage.setItem(
      PROPERTY_COLUMNS_KEY,
      JSON.stringify(selectedPropertyKeys.value),
    );
  } catch {
    // The selection still applies for this page lifetime.
  }
}

function toggleSessionGrouping() {
  groupBySession.value = !groupBySession.value;
  try {
    window.localStorage.setItem(
      SESSION_GROUP_KEY,
      String(groupBySession.value),
    );
  } catch {
    // The selection still applies for this page lifetime.
  }
}

const displayGroups = computed(() => logGroups(rows.value, groupBySession.value));
const tableColumnCount = computed(() => 8 + selectedPropertyKeys.value.length);

function statusTone(
  status: number | undefined,
): "ok" | "warn" | "err" | "info" | "neutral" {
  if (status === undefined) return "neutral";
  if (status < 300) return "ok";
  if (status < 400) return "info";
  if (status < 500) return "warn";
  return "err";
}

// Row expansion shows the complete bounded record.
const expandedKey = ref<string | null>(null);
function rowKey(request: RequestLog, index: number, group: string): string {
  return request.request_id ?? `${String(timestampOf(request))}-${group}-${index}`;
}
function toggleExpand(request: RequestLog, index: number, group: string) {
  const key = rowKey(request, index, group);
  expandedKey.value = expandedKey.value === key ? null : key;
}
interface DetailField {
  label: string;
  value: string;
}
function detailFields(request: RequestLog): DetailField[] {
  const fields: DetailField[] = [];
  const push = (label: string, value: unknown) => {
    if (value !== undefined && value !== null && value !== "") {
      fields.push({ label, value: String(value) });
    }
  };
  push("Request id", request.request_id);
  push("Trace id", request.trace_id);
  push("Session id", request.session_id);
  push("Parent session", request.parent_session_id);
  push("Origin", request.origin);
  push("Client IP", request.client_ip ?? request.client);
  push("Provider", request.provider);
  push("Model", request.model);
  push("Tokens in", request.tokens_in);
  push("Tokens out", request.tokens_out);
  if (request.cost_usd_micros !== undefined) {
    push("Cost", formatUsd(request.cost_usd_micros / 1_000_000));
  }
  push("Cache", request.cache_status);
  push("Retry count", request.retry_count);
  push("Failover engaged", request.failover_engaged);
  push("Failover from", request.failover_from);
  push("Failover to", request.failover_to);
  push("Load balancer", request.load_balancer_strategy);
  push("Selected target", request.load_balancer_target);
  push("Guardrail", request.guardrail_category);
  push("Guardrail action", request.guardrail_action);
  Object.entries(request.properties ?? {})
    .sort(([a], [b]) => a.localeCompare(b))
    .forEach(([key, value]) => push(`Property: ${key}`, value));
  return fields;
}
</script>

<template>
  <PageHeader
    title="Logs"
    subtitle="Recent requests from the in-memory ring. Filter the snapshot or tail it live, then expand any row to inspect the bounded request record."
  >
    <template #actions>
      <button
        class="sb-btn"
        :class="{ 'sb-btn--primary': live }"
        :aria-pressed="live"
        @click="toggleLive"
      >
        {{ live ? "Live: on" : "Live: off" }}
      </button>
      <button v-if="live" class="sb-btn" @click="togglePause">
        {{ paused ? `Resume (${pendingRows.length} new)` : "Pause" }}
      </button>
      <button v-else class="sb-btn sb-btn--primary" @click="req.run">
        Refresh
      </button>
    </template>
  </PageHeader>

  <div v-if="live && streamState === 'reconnecting'" class="sb-card stream-state">
    Stream disconnected; retrying. If this persists after a proxy restart, sign in
    again.
  </div>

  <div v-if="logLevel" class="sb-card loglevel">
    <span class="lbl">Tracing level</span>
    <input
      v-model="levelDraft"
      class="sb-input lvl-input"
      aria-label="Tracing filter directive"
      @keydown.enter="applyLogLevel(levelDraft)"
    />
    <button
      class="sb-btn sb-btn--sm"
      :disabled="levelBusy"
      @click="applyLogLevel(levelDraft)"
    >
      Set
    </button>
    <button
      v-for="preset in LEVEL_PRESETS"
      :key="preset"
      class="sb-btn sb-btn--sm preset"
      :disabled="levelBusy"
      @click="applyLogLevel(preset)"
    >
      {{ preset }}
    </button>
  </div>

  <section class="filter-panel" aria-label="Request filters">
    <div class="filters">
      <select v-model="fMethod" class="sb-select" aria-label="Filter by method">
        <option value="">All methods</option>
        <option v-for="method in methods" :key="method" :value="method">
          {{ method }}
        </option>
      </select>
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
      <input
        v-model="fStatus"
        class="sb-input"
        placeholder="Status: 200 or 5xx"
        aria-label="Filter by status"
      />
      <input
        v-model="fPath"
        class="sb-input"
        placeholder="Path contains"
        aria-label="Filter by path"
      />
      <select v-model="fCache" class="sb-select" aria-label="Filter by cache status">
        <option value="">Any cache</option>
        <option value="disabled">Disabled</option>
        <option value="miss">Miss</option>
        <option value="hit">Hit</option>
        <option value="semantic_hit">Semantic hit</option>
      </select>
      <select v-model="fRetried" class="sb-select" aria-label="Filter by retry">
        <option value="">Any attempt count</option>
        <option value="true">Retried</option>
        <option value="false">Not retried</option>
      </select>
      <select
        v-model="fGuardrail"
        class="sb-select"
        aria-label="Filter by guardrail action"
      >
        <option value="">Any guardrail</option>
        <option value="block">Blocked</option>
      </select>
      <select
        v-model="fPropertyKey"
        class="sb-select"
        aria-label="Filter by property key"
      >
        <option value="">Any property</option>
        <option v-for="key in propertyKeys" :key="key" :value="key">{{ key }}</option>
      </select>
      <input
        v-model="fPropertyValue"
        class="sb-input"
        :disabled="!fPropertyKey"
        placeholder="Exact property value"
        aria-label="Filter by property value"
      />
      <input
        v-model="fSession"
        class="sb-input session-filter"
        placeholder="Exact session ID"
        aria-label="Filter by session ID"
      />
    </div>
    <div class="filter-actions">
      <button class="sb-btn sb-btn--sm" :disabled="live" @click="applyFilters">
        Apply to snapshot
      </button>
      <button class="sb-btn sb-btn--sm" @click="clearFilters">Clear all</button>
      <button
        class="sb-btn sb-btn--sm"
        :class="{ 'sb-btn--primary': groupBySession }"
        :aria-pressed="groupBySession"
        @click="toggleSessionGrouping"
      >
        Group by session
      </button>
      <details class="column-picker">
        <summary class="sb-btn sb-btn--sm">Property columns</summary>
        <div class="column-picker__menu">
          <p v-if="!propertyKeys.length" class="sb-faint">No properties in this ring.</p>
          <label v-for="key in propertyKeys" :key="key" class="column-option">
            <input
              type="checkbox"
              :checked="selectedPropertyKeys.includes(key)"
              @change="togglePropertyColumn(key)"
            />
            <span class="sb-mono">{{ key }}</span>
          </label>
        </div>
      </details>
      <span class="count sb-faint">{{ rows.length }} of {{ raw.length }}</span>
    </div>
  </section>

  <ErrorState v-if="!live && req.error.value" :error="req.error.value" @retry="req.run" />
  <EmptyState v-else-if="!raw.length" message="No requests recorded yet." />
  <EmptyState
    v-else-if="!rows.length"
    message="No requests match the current filters."
  />
  <div v-else class="table-wrap">
    <table class="sb-table request-ledger">
      <thead>
        <tr>
          <th>Time</th>
          <th>Method</th>
          <th>Path</th>
          <th>Status</th>
          <th>Duration</th>
          <th>Gateway</th>
          <th v-for="key in selectedPropertyKeys" :key="key" class="property-head">
            {{ key }}
          </th>
          <th>Trace</th>
          <th>Upstream</th>
        </tr>
      </thead>
      <tbody>
        <template v-for="group in displayGroups" :key="group.key">
          <tr v-if="groupBySession" class="session-row">
            <td :colspan="tableColumnCount">
              <div
                v-if="group.session"
                class="session-summary"
                :style="{ paddingLeft: `${group.depth * 18}px` }"
              >
                <span class="session-rail" aria-hidden="true" />
                <RouterLink
                  class="session-id sb-mono"
                  :to="`/sessions/${encodeURIComponent(group.session.sessionId)}`"
                >
                  {{ group.session.sessionId }}
                </RouterLink>
                <StatusBadge v-if="group.kind === 'orphan'" label="orphan" tone="warn" />
                <span>{{ group.session.requestCount }} requests</span>
                <span>{{ formatNumber(group.session.totalTokens) }} tokens</span>
                <span>{{ formatUsd(group.session.costUsdMicros / 1_000_000) }}</span>
                <span>{{ formatMs(group.session.wallClockMs) }}</span>
                <StatusBadge
                  :label="String(group.session.worstStatus ?? '?')"
                  :tone="statusTone(group.session.worstStatus)"
                />
              </div>
              <div v-else class="session-summary ungrouped-summary">
                <span class="session-rail" aria-hidden="true" />
                <strong>Ungrouped requests</strong>
                <span>{{ group.requests.length }} requests</span>
              </div>
            </td>
          </tr>
          <template
            v-for="(request, index) in group.requests"
            :key="rowKey(request, index, group.key)"
          >
            <tr
              class="row"
              tabindex="0"
              @click="toggleExpand(request, index, group.key)"
              @keydown.enter="toggleExpand(request, index, group.key)"
            >
              <td class="nowrap sb-muted">{{ formatTime(timestampOf(request)) }}</td>
              <td class="sb-mono">{{ request.method ?? "" }}</td>
              <td class="sb-mono path">{{ pathOf(request) || "n/a" }}</td>
              <td>
                <StatusBadge
                  :label="String(statusOf(request) ?? '?')"
                  :tone="statusTone(statusOf(request))"
                />
              </td>
              <td class="nowrap">{{ formatMs(durationOf(request)) }}</td>
              <td>
                <div class="signal-rail" aria-label="Gateway decisions">
                  <template
                    v-for="(badge, badgeIndex) in gatewayBadges(request)"
                    :key="`${badge.kind}-${badge.label}`"
                  >
                    <span v-if="badgeIndex" class="signal-join" aria-hidden="true">›</span>
                    <StatusBadge :label="badge.label" :tone="badge.tone" />
                  </template>
                </div>
              </td>
              <td
                v-for="key in selectedPropertyKeys"
                :key="key"
                class="sb-mono property-value"
              >
                {{ request.properties?.[key] ?? "" }}
              </td>
              <td class="sb-mono trace">
                <a
                  v-if="traceUrl(request)"
                  :href="traceUrl(request)!"
                  target="_blank"
                  rel="noopener noreferrer"
                  @click.stop
                >{{ request.trace_id!.slice(0, 8) }}…</a>
                <span v-else-if="request.trace_id" class="sb-muted">
                  {{ request.trace_id.slice(0, 8) }}…
                </span>
              </td>
              <td class="sb-mono sb-muted">{{ request.upstream ?? request.target ?? "" }}</td>
            </tr>
            <tr
              v-if="expandedKey === rowKey(request, index, group.key)"
              class="detail-row"
            >
              <td :colspan="tableColumnCount">
                <div class="detail-grid">
                  <div
                    v-for="field in detailFields(request)"
                    :key="field.label"
                    class="detail-item"
                  >
                    <span class="detail-label">{{ field.label }}</span>
                    <span class="sb-mono detail-value">{{ field.value }}</span>
                  </div>
                  <p v-if="!detailFields(request).length" class="sb-faint no-detail">
                    No additional fields on this legacy row.
                  </p>
                </div>
              </td>
            </tr>
          </template>
        </template>
      </tbody>
    </table>
  </div>
</template>

<style scoped>
.loglevel {
  display: flex;
  align-items: center;
  gap: var(--sb-space-3);
  flex-wrap: wrap;
  margin-bottom: var(--sb-space-4);
}
.loglevel .lbl {
  font-size: 0.78rem;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--sb-text-muted);
}
.loglevel .lvl-input {
  max-width: 200px;
}
.loglevel .preset {
  font-family: var(--sb-font-mono);
}
.stream-state {
  margin-bottom: var(--sb-space-4);
  color: var(--sb-text-muted);
  font-size: 0.85rem;
}
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
.filters .session-filter {
  min-width: 210px;
}
.count {
  font-size: 0.8rem;
  margin-left: auto;
}
.column-picker {
  position: relative;
}
.column-picker summary {
  list-style: none;
}
.column-picker summary::-webkit-details-marker {
  display: none;
}
.column-picker__menu {
  position: absolute;
  z-index: 4;
  top: calc(100% + 4px);
  left: 0;
  min-width: 220px;
  max-height: 280px;
  overflow: auto;
  padding: var(--sb-space-3);
  background: var(--sb-surface);
  border: 1px solid var(--sb-border-ink);
}
.column-picker__menu p {
  margin: 0;
}
.column-option {
  display: flex;
  align-items: center;
  gap: var(--sb-space-2);
  padding: 5px 0;
  font-size: 0.8rem;
}
.table-wrap {
  border: 1px solid var(--sb-border);
  overflow-x: auto;
}
.request-ledger {
  min-width: 1040px;
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
.path {
  max-width: 330px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.property-head {
  color: var(--sb-accent-strong);
}
.property-value {
  max-width: 180px;
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
.trace a,
.session-id {
  text-decoration: underline;
}
.session-row td {
  background: var(--sb-bg-sunken);
  border-top: 1px solid var(--sb-border-ink);
  padding-top: 7px;
  padding-bottom: 7px;
}
.session-summary {
  display: flex;
  align-items: center;
  gap: var(--sb-space-3);
  color: var(--sb-text-muted);
  font-size: 0.76rem;
}
.session-rail {
  width: 18px;
  height: 1px;
  background: var(--sb-accent);
  flex: none;
}
.session-id {
  color: var(--sb-text);
  font-weight: 600;
}
.ungrouped-summary {
  color: var(--sb-text-faint);
}
.detail-row td {
  background: var(--sb-surface-2);
}
.detail-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
  gap: 8px 20px;
  padding: 8px 4px;
}
.detail-item {
  display: flex;
  flex-direction: column;
  gap: 2px;
}
.detail-label {
  font-size: 0.72rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--sb-text-muted);
}
.detail-value {
  font-size: 0.82rem;
  word-break: break-all;
}
.no-detail {
  margin: 4px 0;
}
@media (max-width: 720px) {
  .column-picker__menu {
    right: 0;
    left: auto;
  }
  .count {
    width: 100%;
    margin-left: 0;
  }
}
</style>
