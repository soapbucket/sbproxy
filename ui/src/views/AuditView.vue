<script setup lang="ts">
import { computed, onMounted, ref, watch } from "vue";
import {
  api,
  type AuditChainChannel,
  type AuditChainEntry,
  type AuditChainFilters,
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

// WOR-2579: the durable, tamper-evident chain viewer. Reads the chained
// files themselves through GET /api/audit/chain, which re-verifies every
// link as it reads, so a broken chain shows up here as a finding rather
// than staying a CLI-only fact.
const CHAIN_CHANNELS = ["security", "config", "key", "admin"] as const;
const chainChannel = ref<"" | (typeof CHAIN_CHANNELS)[number]>("");
const chainActor = ref("");
const chainSince = ref("");
const chainUntil = ref("");
const beforeSeq = ref<number | undefined>(undefined);
// Cursors behind the current page, so "Newer" can walk back out.
const cursorTrail = ref<(number | undefined)[]>([]);

function chainFilters(): AuditChainFilters {
  return {
    ...(chainChannel.value ? { channel: chainChannel.value } : {}),
    ...(chainActor.value ? { actor: chainActor.value } : {}),
    ...(chainSince.value
      ? { since: new Date(chainSince.value).toISOString() }
      : {}),
    ...(chainUntil.value
      ? { until: new Date(chainUntil.value).toISOString() }
      : {}),
    ...(beforeSeq.value !== undefined ? { beforeSeq: beforeSeq.value } : {}),
  };
}
const chainReq = useAsync(() => api.auditChain(chainFilters()));
const chainEntries = computed<AuditChainEntry[]>(
  () => chainReq.data.value?.entries ?? [],
);

// Verification statuses stick per channel: a channel-filtered page only
// walks its own chain, so the other three cards keep their last walked
// status instead of blanking.
const chainStatuses = ref<Record<string, AuditChainChannel>>({});
watch(chainReq.data, (data) => {
  if (!data) return;
  const next = { ...chainStatuses.value };
  for (const c of data.channels) {
    if (!c.enabled || c.ok !== undefined || c.error) next[c.channel] = c;
    else next[c.channel] = { ...(next[c.channel] ?? c), enabled: true };
  }
  chainStatuses.value = next;
});
const statusCards = computed<AuditChainChannel[]>(() =>
  CHAIN_CHANNELS.map(
    (name) => chainStatuses.value[name] ?? { channel: name, enabled: false },
  ),
);
const brokenChannels = computed(() =>
  statusCards.value.filter((c) => c.enabled && (c.ok === false || c.error)),
);

const selectedStatus = computed(() =>
  chainChannel.value ? chainStatuses.value[chainChannel.value] : undefined,
);
const canOlder = computed(() =>
  Boolean(chainChannel.value && selectedStatus.value?.next_before_seq != null),
);
function olderPage() {
  const next = selectedStatus.value?.next_before_seq;
  if (next == null) return;
  cursorTrail.value = [...cursorTrail.value, beforeSeq.value];
  beforeSeq.value = next;
  chainReq.run();
}
function newerPage() {
  if (!cursorTrail.value.length) return;
  const trail = [...cursorTrail.value];
  beforeSeq.value = trail.pop();
  cursorTrail.value = trail;
  chainReq.run();
}
watch([chainChannel, chainActor, chainSince, chainUntil], () => {
  beforeSeq.value = undefined;
  cursorTrail.value = [];
  chainReq.run();
});

function chainCardLabel(card: AuditChainChannel): string {
  if (!card.enabled) return "off";
  if (card.error) return "unreadable";
  if (card.ok === false) return "broken";
  if (card.ok === true) return "verified";
  return "enabled";
}
function chainCardTone(
  card: AuditChainChannel,
): "ok" | "warn" | "err" | "info" | "neutral" {
  if (!card.enabled) return "neutral";
  if (card.error || card.ok === false) return "err";
  if (card.ok === true) return "ok";
  return "info";
}

function asText(value: unknown): string {
  return typeof value === "string" ? value : "";
}
function eventSummary(entry: AuditChainEntry): string {
  const ev = entry.event;
  const kind =
    asText(ev.event_type) ||
    asText(ev.op) ||
    asText(ev.action) ||
    asText(ev.source);
  const detail =
    asText(ev.reason) || asText(ev.detail) || asText(ev.id) || "";
  return [kind, detail].filter(Boolean).join(": ") || "(structured entry)";
}
function eventJson(entry: AuditChainEntry): string {
  return JSON.stringify(entry.event, null, 2);
}

function refresh() {
  req.run();
  eventsReq.run();
  chainReq.run();
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

  <!-- WOR-2579: the durable, tamper-evident chain viewer -->
  <section class="section">
    <h2>Tamper-evident chain</h2>
    <div class="chain-cards">
      <div v-for="card in statusCards" :key="card.channel" class="chain-card">
        <div class="chain-card-head">
          <span class="chain-card-name">{{ card.channel }}</span>
          <StatusBadge :label="chainCardLabel(card)" :tone="chainCardTone(card)" />
        </div>
        <span v-if="card.error" class="sb-faint chain-card-detail">{{ card.error }}</span>
        <span v-else-if="card.ok === false" class="sb-faint chain-card-detail">
          broken at #{{ card.broken_seq }}: {{ card.reason }}
        </span>
        <span v-else-if="card.enabled" class="sb-faint chain-card-detail">
          {{ card.chain_entries ?? 0 }} entries
          <template v-if="card.key_id"> &middot; signed as {{ card.key_id }}</template>
        </span>
        <span v-else class="sb-faint chain-card-detail">
          not configured; see the audit-log doc
        </span>
      </div>
    </div>
    <div v-if="brokenChannels.length" class="chain-alert" role="alert">
      Chain verification FAILED:
      <template v-for="(c, i) in brokenChannels" :key="c.channel">
        <template v-if="i > 0">; </template>
        <strong>{{ c.channel }}</strong>
        <template v-if="c.error"> is unreadable ({{ c.error }})</template>
        <template v-else>
          broke at sequence {{ c.broken_seq }} ({{ c.reason }})</template>
      </template>.
      Entries after a break are not served because they can no longer be
      trusted. Verify from a copy with
      <code>sbproxy audit verify</code> and treat the file as evidence.
    </div>
    <div class="filter-row">
      <select v-model="chainChannel" class="sb-select" aria-label="Filter chain by channel">
        <option value="">all channels</option>
        <option v-for="name in CHAIN_CHANNELS" :key="name" :value="name">{{ name }}</option>
      </select>
      <input
        v-model.lazy="chainActor"
        class="sb-input"
        placeholder="Filter by actor"
        aria-label="Filter chain by actor"
      />
      <input
        v-model.lazy="chainSince"
        type="datetime-local"
        class="sb-input"
        aria-label="Chain entries recorded at or after"
      />
      <input
        v-model.lazy="chainUntil"
        type="datetime-local"
        class="sb-input"
        aria-label="Chain entries recorded at or before"
      />
      <button
        class="sb-btn sb-btn--sm"
        :disabled="!cursorTrail.length"
        @click="newerPage"
      >
        Newer
      </button>
      <button class="sb-btn sb-btn--sm" :disabled="!canOlder" @click="olderPage">
        Older
      </button>
    </div>
    <ErrorState
      v-if="chainReq.error.value"
      :error="chainReq.error.value"
      @retry="chainReq.run"
    />
    <EmptyState
      v-else-if="!chainEntries.length"
      message="No chained audit entries match. Chains are opt-in per channel: audit.sink: chain, audit.config_path, audit.key_path, and audit.admin_path each turn one on."
    />
    <div v-else class="table-wrap">
      <table class="sb-table">
        <thead>
          <tr>
            <th>Recorded</th>
            <th>Channel</th>
            <th>Seq</th>
            <th>Actor</th>
            <th>Entry</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="e in chainEntries" :key="`${e.channel}:${e.seq}`">
            <td class="sb-mono">{{ formatTime(e.recorded_at) }}</td>
            <td><StatusBadge :label="e.channel" :tone="channelTone(e.channel)" /></td>
            <td class="sb-mono">{{ e.seq }}</td>
            <td class="sb-mono">{{ e.actor ?? "-" }}</td>
            <td>
              <details class="chain-entry">
                <summary>{{ eventSummary(e) }}</summary>
                <pre class="chain-entry-json">{{ eventJson(e) }}</pre>
              </details>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <p class="sb-faint note">
      Every page read re-verifies the chain from its first record: the
      hash links, then each entry's Ed25519 signature. What renders here
      has been proved unmodified since the proxy wrote it.
    </p>
  </section>

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
    The two sections above are bounded runtime samples that clear on
    restart. The tamper-evident chain at the top is the durable record:
    entries land there when a channel's chain file is configured, and
    they stay verifiable after the process is gone.
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
.chain-cards {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: var(--sb-space-3);
  margin-bottom: var(--sb-space-4);
}
.chain-card {
  border: 1px solid var(--sb-border);
  border-radius: var(--sb-radius);
  padding: var(--sb-space-3);
  display: flex;
  flex-direction: column;
  gap: var(--sb-space-2);
}
.chain-card-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--sb-space-2);
}
.chain-card-name {
  font-weight: 600;
  text-transform: capitalize;
}
.chain-card-detail {
  font-size: 0.82rem;
  overflow-wrap: anywhere;
}
.chain-alert {
  border: 1px solid var(--sb-err);
  border-left-width: 4px;
  border-radius: var(--sb-radius);
  background: var(--sb-err-bg);
  padding: var(--sb-space-3);
  margin-bottom: var(--sb-space-4);
}
.chain-entry summary {
  cursor: pointer;
}
.chain-entry-json {
  margin: var(--sb-space-2) 0 0;
  font-size: 0.78rem;
  max-height: 16rem;
  overflow: auto;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}
</style>
