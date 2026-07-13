<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from "vue";
import { useRoute } from "vue-router";
import { api, asList, type RequestLog } from "../api";
import { useAsync } from "../composables/useAsync";
import { formatMs, formatTime, toDate } from "../lib/format";
import PageHeader from "../components/PageHeader.vue";
import StatusBadge from "../components/StatusBadge.vue";
import ErrorState from "../components/ErrorState.vue";
import EmptyState from "../components/EmptyState.vue";

const route = useRoute();
const req = useAsync(() => api.requests());
onMounted(() => {
  req.run();
  loadLogLevel();
  loadUiSettings();
  // WOR-1874: the Guardrails view deep-links here with a filter query.
  const ga = route.query.guardrail_action;
  if (typeof ga === "string" && ga) fGuardrail.value = ga;
});
onUnmounted(stopStream);

const snapshot = computed<RequestLog[]>(() =>
  asList<RequestLog>(req.data.value, "requests", "items", "entries", "data"),
);

// ---- live tail over the ring's SSE stream (WOR-1870) ----
const STREAM_ROW_CAP = 1000;
const live = ref(false);
const paused = ref(false);
const streamState = ref<"idle" | "open" | "reconnecting">("idle");
const streamRows = ref<RequestLog[]>([]);
const pendingRows = ref<RequestLog[]>([]);
let source: EventSource | null = null;

function startStream() {
  stopStream();
  // Seed with the snapshot so toggling live keeps history visible.
  streamRows.value = [...snapshot.value];
  pendingRows.value = [];
  paused.value = false;
  streamState.value = "reconnecting";
  // EventSource sends the admin session cookie same-origin; the server
  // enforces auth on connect and auto-reconnect re-runs the login
  // gate after a proxy restart (sessions are per-process).
  source = new EventSource(api.requestsStreamUrl());
  source.onopen = () => {
    streamState.value = "open";
  };
  source.onerror = () => {
    // EventSource retries on its own; surface the state instead of a
    // silently dead view. A dead session keeps this in "reconnecting"
    // until the operator logs in again.
    streamState.value = "reconnecting";
  };
  source.onmessage = (ev) => {
    try {
      const row = JSON.parse(ev.data) as RequestLog;
      const target = paused.value ? pendingRows.value : streamRows.value;
      target.unshift(row);
      if (target.length > STREAM_ROW_CAP) target.length = STREAM_ROW_CAP;
    } catch {
      // A malformed frame (heartbeat/comment) is not a row.
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
    // Flush what arrived while reading.
    streamRows.value = [...pendingRows.value, ...streamRows.value].slice(0, STREAM_ROW_CAP);
    pendingRows.value = [];
  }
  paused.value = !paused.value;
}

const raw = computed<RequestLog[]>(() => (live.value ? streamRows.value : snapshot.value));

// ---- trace deep links (WOR-1870) ----
const traceTemplate = ref<string>("");
async function loadUiSettings() {
  try {
    traceTemplate.value = (await api.uiSettings()).trace_url_template ?? "";
  } catch {
    // Older server: plain-text trace ids.
  }
}
function traceUrl(r: RequestLog): string | null {
  if (!traceTemplate.value || !r.trace_id) return null;
  return traceTemplate.value.replaceAll("{trace_id}", r.trace_id);
}

// ---- runtime log level (WOR-1759) ----
const logLevel = ref("");
const levelDraft = ref("");
const levelBusy = ref(false);
const levelMsg = ref("");
async function loadLogLevel() {
  try {
    logLevel.value = (await api.logLevel()).level ?? "";
    levelDraft.value = logLevel.value;
  } catch {
    // admin may be older; hide the control by leaving logLevel empty.
  }
}
async function applyLogLevel(value: string) {
  if (levelBusy.value || !value.trim()) return;
  levelBusy.value = true;
  levelMsg.value = "";
  try {
    logLevel.value = (await api.setLogLevel(value)).level ?? value;
    levelDraft.value = logLevel.value;
    levelMsg.value = `Log level set to ${logLevel.value}`;
  } catch (e) {
    levelMsg.value = e instanceof Error ? e.message : "Failed to set level";
  } finally {
    levelBusy.value = false;
  }
}
const LEVEL_PRESETS = ["info", "debug", "trace", "sbproxy_ai=debug"];

// ---- filters ----
const fMethod = ref("");
const fStatus = ref("");
const fPath = ref("");
const fGuardrail = ref("");

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
  if (fGuardrail.value) {
    list = list.filter((r) => r.guardrail_action === fGuardrail.value);
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
  fGuardrail.value = "";
}

// ---- row expansion (WOR-1870): the full ring record ----
const expandedKey = ref<string | null>(null);
function rowKey(r: RequestLog, i: number): string {
  return r.request_id ?? `${String(timeOf(r))}-${i}`;
}
function toggleExpand(r: RequestLog, i: number) {
  const key = rowKey(r, i);
  expandedKey.value = expandedKey.value === key ? null : key;
}
interface DetailField {
  label: string;
  value: string;
}
function detailFields(r: RequestLog): DetailField[] {
  const fields: DetailField[] = [];
  const push = (label: string, v: unknown) => {
    if (v !== undefined && v !== null && v !== "") fields.push({ label, value: String(v) });
  };
  push("Request id", r.request_id);
  push("Trace id", r.trace_id);
  push("Origin", r.origin);
  push("Client IP", r.client_ip ?? r.client);
  push("Provider", r.provider);
  push("Model", r.model);
  push("Tokens in", r.tokens_in);
  push("Tokens out", r.tokens_out);
  if (r.cost_usd_micros !== undefined && r.cost_usd_micros !== null) {
    push("Cost (USD)", (Number(r.cost_usd_micros) / 1_000_000).toFixed(6));
  }
  push("Guardrail", r.guardrail_category);
  push("Guardrail action", r.guardrail_action);
  return fields;
}
</script>

<template>
  <PageHeader
    title="Logs"
    subtitle="Recent requests from the in-memory ring buffer. Live tail streams new rows as they complete; expand a row for the full record."
  >
    <template #actions>
      <button
        class="sb-btn"
        :class="{ 'sb-btn--primary': live }"
        @click="toggleLive"
        :aria-pressed="live"
      >
        {{ live ? "Live: on" : "Live: off" }}
      </button>
      <button v-if="live" class="sb-btn" @click="togglePause">
        {{ paused ? `Resume (${pendingRows.length} new)` : "Pause" }}
      </button>
      <button v-if="!live" class="sb-btn sb-btn--primary" @click="req.run">Refresh</button>
    </template>
  </PageHeader>

  <div class="sb-card stream-state" v-if="live && streamState === 'reconnecting'">
    Stream disconnected; retrying. A proxy restart ends the admin session, so if this
    persists, log in again.
  </div>

  <div class="sb-card loglevel" v-if="logLevel">
    <span class="lbl">Tracing level</span>
    <input
      v-model="levelDraft"
      class="sb-input lvl-input"
      @keydown.enter="applyLogLevel(levelDraft)"
      aria-label="Tracing filter directive"
    />
    <button class="sb-btn sb-btn--sm" :disabled="levelBusy" @click="applyLogLevel(levelDraft)">
      Set
    </button>
    <button
      v-for="p in LEVEL_PRESETS"
      :key="p"
      class="sb-btn sb-btn--sm preset"
      :disabled="levelBusy"
      @click="applyLogLevel(p)"
    >
      {{ p }}
    </button>
    <span class="sb-faint msg" v-if="levelMsg">{{ levelMsg }}</span>
  </div>

  <div class="filters">
    <select class="sb-select" v-model="fMethod" aria-label="Filter by method">
      <option value="">All methods</option>
      <option v-for="m in methods" :key="m" :value="m">{{ m }}</option>
    </select>
    <input class="sb-input" v-model="fStatus" placeholder="Status (e.g. 200 or 5xx)" aria-label="Filter by status" />
    <input class="sb-input" v-model="fPath" placeholder="Filter by path" aria-label="Filter by path" />
    <select class="sb-select" v-model="fGuardrail" aria-label="Filter by guardrail action">
      <option value="">Any guardrail</option>
      <option value="block">Blocked</option>
    </select>
    <button class="sb-btn" @click="clearFilters">Clear</button>
    <span class="count sb-faint">{{ rows.length }} of {{ raw.length }}</span>
  </div>

  <ErrorState v-if="!live && req.error.value" :error="req.error.value" @retry="req.run" />
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
          <th>Trace</th>
          <th>Upstream</th>
        </tr>
      </thead>
      <tbody>
        <template v-for="(r, i) in rows" :key="rowKey(r, i)">
          <tr class="row" @click="toggleExpand(r, i)">
            <td class="nowrap sb-muted">{{ formatTime(timeOf(r)) }}</td>
            <td class="sb-mono">{{ r.method ?? "" }}</td>
            <td class="sb-mono path">
              {{ pathOf(r) || "n/a" }}
              <StatusBadge
                v-if="r.guardrail_action"
                :label="`guardrail: ${r.guardrail_category ?? r.guardrail_action}`"
                tone="warn"
              />
            </td>
            <td><StatusBadge :label="String(statusOf(r) ?? '?')" :tone="statusTone(statusOf(r))" /></td>
            <td class="nowrap">{{ formatMs(durationOf(r)) }}</td>
            <td class="sb-mono trace">
              <a
                v-if="traceUrl(r)"
                :href="traceUrl(r)!"
                target="_blank"
                rel="noopener noreferrer"
                @click.stop
              >{{ r.trace_id!.slice(0, 8) }}…</a>
              <span v-else-if="r.trace_id" class="sb-muted">{{ r.trace_id.slice(0, 8) }}…</span>
            </td>
            <td class="sb-mono sb-muted">{{ r.upstream ?? r.target ?? "" }}</td>
          </tr>
          <tr v-if="expandedKey === rowKey(r, i)" class="detail-row">
            <td colspan="7">
              <div class="detail-grid">
                <div v-for="f in detailFields(r)" :key="f.label" class="detail-item">
                  <span class="detail-label">{{ f.label }}</span>
                  <span class="sb-mono detail-value">{{ f.value }}</span>
                </div>
                <p v-if="!detailFields(r).length" class="sb-faint no-detail">
                  No additional fields on this row (older server or non-AI traffic).
                </p>
              </div>
            </td>
          </tr>
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
.loglevel .msg {
  margin-left: auto;
}
.stream-state {
  margin-bottom: var(--sb-space-4);
  color: var(--sb-text-muted);
  font-size: 0.85rem;
}
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
.row {
  cursor: pointer;
}
.path {
  max-width: 420px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.trace a {
  text-decoration: underline;
}
.detail-row td {
  background: var(--sb-bg-subtle, rgba(127, 127, 127, 0.06));
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
</style>
