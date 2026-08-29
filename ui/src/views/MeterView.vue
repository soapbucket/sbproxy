<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import EmptyState from "../components/EmptyState.vue";
import ErrorState from "../components/ErrorState.vue";
import PageHeader from "../components/PageHeader.vue";
import StatCard from "../components/StatCard.vue";
import StatusBadge from "../components/StatusBadge.vue";
import { api, type MeterReceipt, type MeterVerifyResult } from "../api";
import { useAsync } from "../composables/useAsync";
import { useCapabilities } from "../composables/useCapabilities";
import { toast } from "../composables/useToasts";
import { formatTime, relativeTime, shortId } from "../lib/format";
import {
  coverageHeadline,
  coverageIsPartial,
  degradedGapCount,
  gapCount,
  gapExplanation,
  groupedTotals,
  meterEmptyState,
  nodeHead,
  nodeTone,
  verifyHeadline,
  verifyTone,
} from "../lib/meter";
import Tooltip from "../components/Tooltip.vue";
import ReadOnlyNotice from "../components/ReadOnlyNotice.vue";

const groupBy = ref("tenant");
const tenantFilter = ref("");
const sinceSeq = ref(0);
const selected = ref<MeterReceipt | null>(null);
const verifyResult = ref<MeterVerifyResult | null>(null);
const verifying = ref(false);

// The coverage block describes the moment somebody asked, so the gather
// runs per request rather than off a background timer. Poll slowly: a
// chain head moves with traffic, not with the clock.
const summary = useAsync(
  () => api.meterSummary(groupBy.value, tenantFilter.value.trim() || undefined),
  { pollMs: 30_000, refreshLabel: "Meter summary" },
);
const receipts = useAsync(
  () => api.meterReceipts(sinceSeq.value, tenantFilter.value.trim() || undefined),
  { refreshLabel: "Receipts" },
);
onMounted(() => {
  void summary.run();
  void receipts.run();
});

const totals = computed(() => groupedTotals(summary.data.value?.totals ?? []));
const empty = computed(() => meterEmptyState(summary.data.value));
const coverage = computed(() => summary.data.value?.coverage ?? null);
const partial = computed(() => coverageIsPartial(coverage.value));
const uncovered = computed(() => coverage.value?.uncovered ?? []);
const nodes = computed(() => summary.data.value?.nodes ?? []);
const gaps = computed(() => summary.data.value?.gaps.by_tenant ?? []);
const gapTotal = computed(() => gapCount(gaps.value));
const degradedGaps = computed(() => degradedGapCount(gaps.value));
const divergence = computed(() => summary.data.value?.gaps.divergence_total ?? 0);
const chain = computed(() => summary.data.value?.chain ?? null);
const attestation = computed(() => summary.data.value?.attestation ?? null);
const rows = computed(() => receipts.data.value?.receipts ?? []);

function reload(): void {
  void summary.run();
  void receipts.run();
}

function applyGroup(value: string): void {
  groupBy.value = value;
  void summary.run();
}

function applyTenant(): void {
  sinceSeq.value = 0;
  selected.value = null;
  reload();
}

function page(next: number | null): void {
  sinceSeq.value = next ?? 0;
  selected.value = null;
  void receipts.run();
}

function open(receipt: MeterReceipt): void {
  selected.value = selected.value?.seq === receipt.seq ? null : receipt;
}

function receiptTenant(receipt: MeterReceipt): string {
  const subject = receipt.claims.subject as { tenant?: string } | undefined;
  return subject?.tenant ?? "unknown";
}

function receiptField(receipt: MeterReceipt, field: string): string {
  const value = receipt.claims[field];
  return typeof value === "string" ? value : "n/a";
}

function receiptDocument(receipt: MeterReceipt): string {
  return JSON.stringify(receipt.claims, null, 2);
}

async function verify(): Promise<void> {
  verifying.value = true;
  try {
    verifyResult.value = await api.meterVerify();
  } catch (error) {
    // A failed request is not a failed verification, and conflating them
    // would tell an operator their chain is broken when their session
    // lapsed. Clear the verdict and say what actually happened.
    verifyResult.value = null;
    toast.error(error, "Verifying the chain");
  } finally {
    verifying.value = false;
  }
}

function fmt(n: number | undefined | null): string {
  return typeof n === "number" ? n.toLocaleString() : "n/a";
}

// WOR-2576: every state-changing control on this page is refused for a
// read_only operator by the admin server, so the console disables it and
// says why rather than offering a button that answers 403.
const { canMutate, whyNot } = useCapabilities();
</script>

<template>
  <PageHeader
    title="Meter"
    subtitle="What this deployment metered, what the total covers, and whether the chain still verifies."
  >
    <template #actions>
      <button class="sb-btn sb-btn--sm" @click="reload">Refresh</button>
    </template>
  </PageHeader>

  <ReadOnlyNotice action="Verifying the receipt chain" />

  <ErrorState
    v-if="summary.error.value && !summary.data.value"
    :error="summary.error.value"
    title="Could not load the meter"
    @retry="summary.run"
  />

  <template v-else>
    <!-- Coverage banner. Rendered only when the fan-out was partial: a
         banner that is always on screen stops being read. -->
    <div v-if="partial" class="banner" role="status">
      <div class="banner__head">
        <span class="banner__tag sb-mono">partial total</span>
        <strong>{{ coverageHeadline(coverage) }}</strong>
      </div>
      <p class="banner__body">
        These figures were assembled from the nodes that answered. Every node below is
        still metering on its own disk, so the shortfall is unreported rather than
        unmetered.
      </p>
      <ul class="banner__list">
        <li v-for="node in uncovered" :key="node.node_id" class="sb-mono">
          {{ node.node_id }} {{ gapExplanation(node.gap) }};
          <template v-if="node.last_known_seq !== null">
            last known sequence {{ fmt(node.last_known_seq) }}
            <span v-if="node.last_seen_at">({{ relativeTime(node.last_seen_at) }})</span>
          </template>
          <template v-else>never seen at any sequence</template>
        </li>
      </ul>
    </div>

    <div class="controls">
      <label class="control">
        <span class="control__label sb-mono">group by</span>
        <select
          class="sb-select"
          :value="groupBy"
          @change="applyGroup(($event.target as HTMLSelectElement).value)"
        >
          <option value="tenant">Tenant</option>
          <option value="unit">Unit</option>
          <option value="source">Provenance</option>
          <option value="total">Total</option>
        </select>
      </label>
      <label class="control">
        <span class="control__label sb-mono">tenant</span>
        <input
          v-model="tenantFilter"
          class="sb-input"
          placeholder="all tenants"
          @keyup.enter="applyTenant"
        />
      </label>
      <button class="sb-btn sb-btn--sm" @click="applyTenant">Apply</button>
    </div>

    <div class="cards">
      <StatCard
        label="Meter state"
        :value="summary.data.value?.state ?? 'unknown'"
        :sub="attestation?.role ? `role: ${attestation.role}` : undefined"
        :tone="summary.data.value?.state === 'reporting' ? undefined : 'accent'"
      />
      <StatCard label="Chain entries" :value="fmt(chain?.entries)" :sub="chain?.node_id" />
      <StatCard label="Distinct claims" :value="fmt(summary.data.value?.claims)" />
      <!-- The gap counter is the number that means lost revenue, so it is a
           tile of its own rather than a column in a table. -->
      <StatCard
        label="Unwritten records"
        :value="fmt(gapTotal)"
        :tone="gapTotal > 0 ? 'accent' : undefined"
        :sub="gapTotal > 0 ? `${fmt(degradedGaps)} degraded` : 'none owed'"
      >
        <template #label-append>
          <Tooltip text="Metered consumptions (e.g., Pay Per Crawl/x402) not durably settled to the chain." />
        </template>
      </StatCard>
    </div>

    <div v-if="gapTotal > 0" class="gaps" role="alert">
      <h2 class="gaps__title">
        {{ fmt(gapTotal) }} records were owed and not written
      </h2>
      <p class="gaps__body">
        Each one is consumption that was served and never made it onto the chain.
        <strong>degraded</strong> means the request went through and the guarantee was
        marked as not made.
      </p>
      <table class="sb-table">
        <thead>
          <tr>
            <th>Tenant</th>
            <th>Failure mode</th>
            <th class="num">Records</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="row in gaps" :key="`${row.tenant}/${row.failure_mode}`">
            <td class="sb-mono">{{ row.tenant }}</td>
            <td><StatusBadge :label="row.failure_mode" /></td>
            <td class="num">{{ fmt(row.count) }}</td>
          </tr>
        </tbody>
      </table>
      <p v-if="divergence > 0" class="gaps__body">
        {{ fmt(divergence) }} units were counted by the meter and did not reach the
        chain. Reconcile against the chain, not against the counters.
      </p>
    </div>

    <EmptyState v-if="empty" :message="empty?.title">
      <p class="empty__detail">{{ empty?.detail }}</p>
      <p v-if="attestation?.ledger_path" class="empty__detail sb-mono">
        {{ attestation?.ledger_path }}
      </p>
    </EmptyState>

    <template v-else>
      <h2 class="section">Units</h2>
      <div class="sb-card table-wrap">
        <table class="sb-table">
          <thead>
            <tr>
              <th>{{ summary.data.value?.group_by ?? "group" }}</th>
              <th>Tenant</th>
              <th>Unit</th>
              <th>Provenance</th>
              <th class="num">Count</th>
            </tr>
          </thead>
          <tbody>
            <template v-for="group in totals" :key="group.group">
              <tr class="group-row">
                <td class="sb-mono" :colspan="4">{{ group.group }}</td>
                <td class="num">{{ fmt(group.count) }}</td>
              </tr>
              <tr v-for="row in group.rows" :key="`${row.tenant}/${row.unit}/${row.source}`">
                <td></td>
                <td class="sb-mono">{{ row.tenant }}</td>
                <td class="sb-mono">{{ row.unit }}</td>
                <!-- Provenance stays on screen next to every count. A
                     dispute about a number nobody can take apart is a long
                     conversation. -->
                <td><StatusBadge :label="row.source" tone="info" /></td>
                <td class="num">{{ fmt(row.count) }}</td>
              </tr>
            </template>
          </tbody>
        </table>
      </div>
    </template>

    <h2 class="section">Chain heads</h2>
    <div class="sb-card table-wrap">
      <table class="sb-table">
        <thead>
          <tr>
            <th>Node</th>
            <th>State</th>
            <th class="num">Head</th>
            <th class="num">Claims</th>
            <th>Digest</th>
            <th>Observed</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="node in nodes" :key="node.node_id" :class="`row--${nodeTone(node)}`">
            <td class="sb-mono">
              {{ node.node_id }}
              <span v-if="node.local" class="tag sb-mono">local</span>
            </td>
            <td>
              <StatusBadge
                v-if="node.covered"
                :label="(node.head_seq ?? 0) === 0 ? 'no entries' : 'counted'"
              />
              <StatusBadge v-else :label="node.gap ?? 'uncovered'" tone="err" />
            </td>
            <td class="num">{{ fmt(nodeHead(node)) }}</td>
            <td class="num">{{ fmt(node.claims) }}</td>
            <td class="sb-mono">{{ shortId(node.head_hash, 12, 4) || "n/a" }}</td>
            <td>{{ formatTime(node.observed_at ?? node.last_seen_at) }}</td>
          </tr>
        </tbody>
      </table>
    </div>

    <h2 class="section">Receipts</h2>
    <div class="verify">
      <button
            :title="canMutate ? undefined : whyNot('mutate')" class="sb-btn sb-btn--sm" :disabled="verifying || !canMutate" @click="verify">
        {{ verifying ? "Verifying…" : "Verify chain" }}
      </button>
      <span v-if="verifyResult" :class="`verify__line verify__line--${verifyTone(verifyResult)}`">
        {{ verifyHeadline(verifyResult) }}
      </span>
    </div>
    <p v-if="chain?.damage_reason" class="damage sb-mono">
      Chain unreadable from sequence {{ fmt(chain?.damaged_at_seq) }}:
      {{ chain?.damage_reason }}
    </p>

    <ErrorState
      v-if="receipts.error.value && !receipts.data.value"
      :error="receipts.error.value"
      title="Could not load receipts"
      @retry="receipts.run"
    />
    <EmptyState
      v-else-if="!rows.length"
      :message="
        receipts.data.value?.state === 'reporting'
          ? 'No receipts in this page for the selected tenant.'
          : 'No receipts on this node yet.'
      "
    />
    <div v-else class="sb-card table-wrap">
      <table class="sb-table">
        <thead>
          <tr>
            <th class="num">Seq</th>
            <th>Recorded</th>
            <th>Tenant</th>
            <th>Route</th>
            <th>Outcome</th>
            <th>Entry digest</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          <template v-for="receipt in rows" :key="receipt.seq">
            <tr>
              <td class="num">{{ receipt.seq }}</td>
              <td>{{ formatTime(receipt.recorded_at) }}</td>
              <td class="sb-mono">{{ receiptTenant(receipt) }}</td>
              <td class="sb-mono">{{ receiptField(receipt, "route") }}</td>
              <td><StatusBadge :label="receiptField(receipt, 'outcome')" /></td>
              <td class="sb-mono">{{ shortId(receipt.entry_hash, 12, 4) }}</td>
              <td>
                <button class="sb-btn sb-btn--sm" @click="open(receipt)">
                  {{ selected?.seq === receipt.seq ? "Hide" : "Inspect" }}
                </button>
              </td>
            </tr>
            <tr v-if="selected?.seq === receipt.seq" class="drill">
              <td :colspan="7">
                <dl class="drill__meta sb-mono">
                  <dt>previous</dt>
                  <dd>{{ receipt.prev_hash }}</dd>
                  <dt>entry</dt>
                  <dd>{{ receipt.entry_hash }}</dd>
                  <dt>signature</dt>
                  <dd>{{ receipt.signature ?? "unsigned chain link" }}</dd>
                </dl>
                <pre class="drill__doc sb-mono">{{ receiptDocument(receipt) }}</pre>
                <button
            :title="canMutate ? undefined : whyNot('mutate')" class="sb-btn sb-btn--sm" :disabled="verifying || !canMutate" @click="verify">
                  Verify the chain this receipt is on
                </button>
              </td>
            </tr>
          </template>
        </tbody>
      </table>
    </div>
    <div class="pager">
      <button class="sb-btn sb-btn--sm" :disabled="sinceSeq === 0" @click="page(0)">
        First page
      </button>
      <button
        class="sb-btn sb-btn--sm"
        :disabled="!receipts.data.value?.next_since_seq"
        @click="page(receipts.data.value?.next_since_seq ?? null)"
      >
        Next page
      </button>
    </div>
  </template>
</template>

<style scoped>
/* The partial-coverage banner is the one surface on this page that has to
   look different from everything around it, so it takes the accent rule
   and the warn wash rather than the ordinary card treatment. */
.banner {
  border: 1px solid var(--sb-warn);
  border-left-width: 4px;
  background: var(--sb-warn-bg);
  padding: var(--sb-space-4);
  margin-bottom: var(--sb-space-5);
}
.banner__head {
  display: flex;
  align-items: baseline;
  gap: var(--sb-space-3);
}
.banner__tag {
  text-transform: uppercase;
  letter-spacing: 0.11em;
  font-size: 0.66rem;
  color: var(--sb-warn-fg);
}
.banner__body {
  margin: 6px 0 8px;
  color: var(--sb-text-muted);
  max-width: 72ch;
}
.banner__list {
  margin: 0;
  padding-left: 1.1rem;
  font-size: 0.82rem;
}
.controls {
  display: flex;
  flex-wrap: wrap;
  gap: var(--sb-space-3);
  align-items: flex-end;
  margin-bottom: var(--sb-space-4);
}
.control {
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.control__label {
  font-size: 0.66rem;
  text-transform: uppercase;
  letter-spacing: 0.11em;
  color: var(--sb-text-faint);
}
.cards {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  margin-bottom: var(--sb-space-5);
}
.cards > * {
  flex: 1 1 180px;
}
/* Gap markers are the number that means lost revenue, so they get their
   own block with an alert role rather than a column somebody scrolls past. */
.gaps {
  border: 1px solid var(--sb-err);
  border-left-width: 4px;
  background: var(--sb-err-bg);
  padding: var(--sb-space-4);
  margin-bottom: var(--sb-space-5);
}
.gaps__title {
  margin: 0 0 6px;
  font-size: 1rem;
}
.gaps__body {
  margin: 0 0 10px;
  color: var(--sb-text-muted);
  max-width: 72ch;
}
.section {
  font-size: 0.9rem;
  text-transform: uppercase;
  letter-spacing: 0.11em;
  color: var(--sb-text-faint);
  margin: var(--sb-space-5) 0 var(--sb-space-3);
}
.table-wrap {
  overflow-x: auto;
}
.num {
  text-align: right;
  font-variant-numeric: tabular-nums;
}
.group-row td {
  background: var(--sb-surface-2);
  font-weight: 600;
}
.row--err td {
  background: var(--sb-err-bg);
}
.row--warn td {
  background: var(--sb-warn-bg);
}
.tag {
  margin-left: 6px;
  font-size: 0.66rem;
  color: var(--sb-text-faint);
  text-transform: uppercase;
  letter-spacing: 0.08em;
}
.verify {
  display: flex;
  align-items: center;
  gap: var(--sb-space-3);
  margin-bottom: var(--sb-space-3);
  flex-wrap: wrap;
}
.verify__line {
  font-size: 0.84rem;
}
.verify__line--ok {
  color: var(--sb-ok);
}
.verify__line--warn {
  color: var(--sb-warn);
}
.verify__line--err {
  color: var(--sb-err);
  font-weight: 600;
}
.verify__line--neutral {
  color: var(--sb-text-muted);
}
.damage {
  color: var(--sb-err);
  font-size: 0.82rem;
  margin: 0 0 var(--sb-space-3);
}
.drill td {
  background: var(--sb-bg-sunken);
}
.drill__meta {
  display: grid;
  grid-template-columns: 8rem 1fr;
  gap: 2px var(--sb-space-3);
  font-size: 0.76rem;
  margin: 0 0 var(--sb-space-3);
  word-break: break-all;
}
.drill__meta dt {
  color: var(--sb-text-faint);
  text-transform: uppercase;
  letter-spacing: 0.08em;
}
.drill__meta dd {
  margin: 0;
}
.drill__doc {
  background: var(--sb-code-bg);
  color: var(--sb-code-fg);
  padding: var(--sb-space-3);
  font-size: 0.74rem;
  max-height: 320px;
  overflow: auto;
  margin: 0 0 var(--sb-space-3);
}
.empty__detail {
  margin: 0 0 6px;
  font-size: 0.84rem;
}
.pager {
  display: flex;
  gap: var(--sb-space-3);
  margin-top: var(--sb-space-3);
}
</style>
