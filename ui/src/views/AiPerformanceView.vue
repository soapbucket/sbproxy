<script setup lang="ts">
import { computed, onMounted } from "vue";
import { api } from "../api";
import { useAsync } from "../composables/useAsync";
import {
  parsePrometheus,
  findFamily,
  groupByLabel,
  groupByLabels,
  sumSamples,
  histogramAvgByLabel,
  histogramQuantile,
  histogramQuantileByLabels,
  type MetricFamily,
} from "../lib/metrics";
import { formatNumber, formatUsd } from "../lib/format";
import { AI_ADMISSION_FAMILY, admissionSummary } from "../lib/ai-admission";
import PageHeader from "../components/PageHeader.vue";
import StatCard from "../components/StatCard.vue";
import StatusBadge from "../components/StatusBadge.vue";
import MiniBars from "../components/MiniBars.vue";
import ErrorState from "../components/ErrorState.vue";
import EmptyState from "../components/EmptyState.vue";

const req = useAsync(() => api.metrics());
onMounted(req.run);

const families = computed<MetricFamily[]>(() => {
  const text = req.data.value;
  return text ? parsePrometheus(text) : [];
});

function fam(name: string) {
  return findFamily(families.value, name);
}

function formatSecs(v: number): string {
  if (v < 1) return `${(v * 1000).toFixed(0)} ms`;
  return `${v.toFixed(2)} s`;
}
function formatTps(v: number): string {
  return `${v.toFixed(1)} tok/s`;
}

// --- AI performance (WOR-1871) ---
const ttft = computed(() => fam("sbproxy_ai_ttft_seconds"));
const tpot = computed(() => fam("sbproxy_ai_inter_token_latency_seconds"));
const throughput = computed(() =>
  fam("sbproxy_ai_output_throughput_tokens_per_second"),
);
const attrLatency = computed(() =>
  fam("sbproxy_ai_request_duration_attributed_seconds"),
);

const ttftP50 = computed(() => histogramQuantile(ttft.value, 0.5));
const ttftP95 = computed(() => histogramQuantile(ttft.value, 0.95));
const tpotP95 = computed(() => histogramQuantile(tpot.value, 0.95));

const ttftByModel = computed(() =>
  histogramQuantileByLabels(ttft.value, 0.95, ["provider", "model"]),
);
const tpotByModel = computed(() =>
  histogramQuantileByLabels(tpot.value, 0.95, ["provider", "model"]),
);
const tpsByModel = computed(() => histogramAvgByLabel(throughput.value, "model"));
const latencyBySurface = computed(() =>
  histogramQuantileByLabels(attrLatency.value, 0.95, ["surface"]),
);

const hasStreaming = computed(() => ttftByModel.value.length > 0);

// --- Provider health (WOR-1871) ---
const providerErrors = computed(() => fam("sbproxy_ai_provider_errors_total"));
const attributedRequests = computed(() =>
  fam("sbproxy_ai_requests_attributed_total"),
);
const gatewayDecisions = computed(() => fam("sbproxy_ai_gateway_decisions_total"));
const failovers = computed(() => fam("sbproxy_ai_failovers_total"));
const attempts = computed(() => fam("sbproxy_ai_provider_attempts_total"));
const cascade = computed(() => fam("sbproxy_ai_cascade_tier_outcomes_total"));
const lbDecisions = computed(() => fam("sbproxy_ai_lb_decisions_total"));

interface ProviderHealthRow {
  provider: string;
  requests: number;
  errors: number;
  errorRate: number;
}
const providerHealth = computed<ProviderHealthRow[]>(() => {
  const requestsByProvider = new Map(
    groupByLabel(attributedRequests.value, "provider").map((r) => [r.key, r.value]),
  );
  const errorsByProvider = new Map(
    groupByLabel(providerErrors.value, "provider").map((r) => [r.key, r.value]),
  );
  const providers = new Set([...requestsByProvider.keys(), ...errorsByProvider.keys()]);
  providers.delete("(none)");
  return [...providers]
    .map((provider) => {
      const requests = requestsByProvider.get(provider) ?? 0;
      const errors = errorsByProvider.get(provider) ?? 0;
      // Attempts can exceed attributed requests (retries), so clamp the
      // displayed rate at 100%.
      const errorRate = requests > 0 ? Math.min(errors / requests, 1) : errors > 0 ? 1 : 0;
      return { provider, requests, errors, errorRate };
    })
    .sort((a, b) => b.errorRate - a.errorRate);
});

const failoverRows = computed(() =>
  groupByLabels(failovers.value, ["from_provider", "to_provider", "reason"]),
);
const attemptRows = computed(() => groupByLabels(attempts.value, ["provider", "outcome"]));
const cascadeRows = computed(() => groupByLabels(cascade.value, ["tier", "outcome"]));
const lbRows = computed(() => groupByLabels(lbDecisions.value, ["strategy", "provider"]));
const outcomeSplit = computed(() => groupByLabel(attributedRequests.value, "outcome"));
const gatewayDecisionRows = computed(() =>
  groupByLabels(gatewayDecisions.value, ["decision", "reason"]),
);
const gatewayDecisionTotal = computed(() => sumSamples(gatewayDecisions.value));
const gatewayRejections = computed(() =>
  sumSamples(gatewayDecisions.value, { decision: "rejected" }),
);
const gatewayRejectionRate = computed(() =>
  gatewayDecisionTotal.value > 0
    ? gatewayRejections.value / gatewayDecisionTotal.value
    : 0,
);

// --- Pre-provider admission refusals (WOR-2595) ---
// A refusal at the inbound native-format shim or the stored-prompt
// resolver happens before a provider is chosen, so it leaves no trace
// on attempts, errors, or latency above. This is the only place the
// console can see it.
//
// `admission` is `undefined` when the family is absent from the scrape,
// which is not the same as zero: the counter registers on its first
// increment, so a proxy that has never refused a request before
// dispatch publishes nothing. The tile says "not reported" for that
// case rather than drawing a reassuring zero.
const admission = computed(() =>
  admissionSummary(fam(AI_ADMISSION_FAMILY)),
);
const admissionDenials = computed(() => admission.value?.denials);

const hasAiTraffic = computed(
  () =>
    sumSamples(attributedRequests.value) > 0 ||
    gatewayDecisionTotal.value > 0 ||
    providerHealth.value.length > 0 ||
    // A deployment whose only AI activity so far is refusals still has
    // something to show, and it is the thing an operator came to find.
    (admissionDenials.value ?? 0) > 0,
);

function rateTone(rate: number): "ok" | "warn" | "err" {
  if (rate >= 0.5) return "err";
  if (rate >= 0.05) return "warn";
  return "ok";
}

// --- Context compression ---
// The compression policies report lever activity and savings; the
// section renders only after at least one compression request ran.
const compressionRequests = computed(() =>
  fam("sbproxy_ai_compression_requests_total"),
);
const compressionTotalRequests = computed(() => sumSamples(compressionRequests.value));
const compressionTokensSaved = computed(() =>
  sumSamples(fam("sbproxy_ai_compression_tokens_saved_total")),
);
const compressionCostSaved = computed(
  () => sumSamples(fam("sbproxy_ai_compression_value_cost_saved_micros_total")) / 1e6,
);
const compressionByOutcome = computed(() =>
  groupByLabel(compressionRequests.value, "outcome").slice(0, 6),
);
const compressionSavedByLever = computed(() =>
  groupByLabel(fam("sbproxy_ai_compression_tokens_saved_total"), "lever").slice(0, 8),
);
const compressionRatioByLever = computed(() =>
  histogramAvgByLabel(fam("sbproxy_ai_compression_ratio"), "lever")
    .map((r) => ({ key: r.key, value: Math.round(r.value * 100) / 100 }))
    .slice(0, 8),
);
const hasCompression = computed(() => compressionTotalRequests.value > 0);
</script>

<template>
  <PageHeader
    title="AI performance"
    subtitle="Requests refused before dispatch, serving latency (TTFT, TPOT, throughput), and provider health from the live counters. Values accumulate since process start."
  />

  <ErrorState v-if="req.error.value" :error="req.error.value" @retry="req.run" />

  <EmptyState
    v-else-if="!req.loading.value && !hasAiTraffic"
    message="No AI traffic recorded since the proxy started, and no request refused before dispatch. Panels light up after the first request flows through an ai_proxy origin; streaming latency panels need at least one streamed completion."
  />

  <template v-else-if="hasAiTraffic">
    <div class="tiles">
      <StatCard
        label="TTFT p50"
        :value="ttftP50 !== undefined ? formatSecs(ttftP50) : 'n/a'"
        sub="time to first token"
      />
      <StatCard
        label="TTFT p95"
        :value="ttftP95 !== undefined ? formatSecs(ttftP95) : 'n/a'"
        tone="accent"
      />
      <StatCard
        label="TPOT p95"
        :value="tpotP95 !== undefined ? formatSecs(tpotP95) : 'n/a'"
        sub="inter-token latency"
      />
      <StatCard
        label="AI requests"
        :value="formatNumber(sumSamples(attributedRequests))"
        sub="since start"
      />
      <StatCard
        label="Gateway rejection rate"
        :value="`${(gatewayRejectionRate * 100).toFixed(1)}%`"
        :sub="`${formatNumber(gatewayRejections)} rejected before provider dispatch`"
        :tone="gatewayRejectionRate >= 0.05 ? 'accent' : 'default'"
      />
      <StatCard
        label="Refused before dispatch"
        :value="admissionDenials !== undefined ? formatNumber(admissionDenials) : 'not reported'"
        :sub="
          admissionDenials !== undefined
            ? 'refused at the inbound surface, no provider called'
            : 'counted from the first refusal at an inbound AI surface'
        "
        :tone="(admissionDenials ?? 0) > 0 ? 'accent' : 'default'"
      />
    </div>

    <section class="panel">
      <h2>Refused before dispatch</h2>
      <p class="hint">
        Requests the gateway refused at the inbound AI surface, before it chose a
        provider. No provider was called, so nothing in provider health below and
        nothing in a provider's own dashboard records them. Coverage is the two
        native-format shims and the shared stored-prompt resolver; a refusal by a
        model gate, guardrail, budget, or policy records under that plane instead.
      </p>
      <template v-if="admission">
        <table v-if="admission.rows.length" class="detail">
          <thead>
            <tr>
              <th>Inbound surface</th>
              <th>Why it was refused</th>
              <th>Outcome</th>
              <th>Requests</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="row in admission.rows" :key="row.key">
              <td>
                {{ row.surfaceLabel }}
                <div class="code sb-mono sb-faint">{{ row.surface }}</div>
              </td>
              <td>
                {{ row.reasonLabel }}
                <div class="code sb-mono sb-faint">{{ row.reason }}</div>
              </td>
              <td>
                <StatusBadge
                  :label="row.outcomeLabel"
                  :tone="row.outcome === 'deny' ? 'err' : 'ok'"
                />
              </td>
              <td>{{ formatNumber(row.count) }}</td>
            </tr>
          </tbody>
        </table>
        <p v-else class="hint">
          The counter is being scraped and has recorded no refusal.
        </p>
        <div class="subgrid" v-if="admission.bySurface.length > 1">
          <div>
            <h3>Refusals by inbound surface</h3>
            <MiniBars :items="admission.bySurface" :format="formatNumber" />
          </div>
        </div>
      </template>
      <p v-else class="hint">
        Not reported. The counter
        <span class="sb-mono">sbproxy_ai_admission_decisions_total</span> is
        published on its first increment, so it is absent until one request is
        refused at an inbound AI surface. This is not a zero.
      </p>
    </section>

    <section class="panel">
      <h2>Provider health</h2>
      <p v-if="!providerHealth.length" class="hint">
        No provider traffic yet.
      </p>
      <table v-else class="detail">
        <thead>
          <tr>
            <th>Provider</th>
            <th>Requests</th>
            <th>Errors</th>
            <th>Error rate</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="r in providerHealth" :key="r.provider">
            <td class="sb-mono">{{ r.provider }}</td>
            <td>{{ formatNumber(r.requests) }}</td>
            <td>{{ formatNumber(r.errors) }}</td>
            <td>
              <div class="rate" :class="`rate--${rateTone(r.errorRate)}`">
                <div class="rate-bar">
                  <div class="rate-fill" :style="{ width: `${r.errorRate * 100}%` }" />
                </div>
                <span class="rate-num">{{ (r.errorRate * 100).toFixed(1) }}%</span>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
      <div class="subgrid" v-if="outcomeSplit.length">
        <div>
          <h3>Outcome split</h3>
          <MiniBars :items="outcomeSplit" :format="formatNumber" />
        </div>
        <div v-if="attemptRows.length">
          <h3>Attempts (provider / outcome)</h3>
          <MiniBars :items="attemptRows" :format="formatNumber" />
        </div>
      </div>
      <div v-if="gatewayDecisionRows.length" class="subgrid">
        <div>
          <h3>Gateway decisions (decision / reason)</h3>
          <MiniBars :items="gatewayDecisionRows" :format="formatNumber" />
        </div>
      </div>
      <div class="subgrid" v-if="failoverRows.length || cascadeRows.length || lbRows.length">
        <div v-if="failoverRows.length">
          <h3>Failovers (from / to / reason)</h3>
          <MiniBars :items="failoverRows" :format="formatNumber" />
        </div>
        <div v-if="cascadeRows.length">
          <h3>Cascade tiers (tier / outcome)</h3>
          <MiniBars :items="cascadeRows" :format="formatNumber" />
        </div>
        <div v-if="lbRows.length">
          <h3>Router decisions (strategy / provider)</h3>
          <MiniBars :items="lbRows" :format="formatNumber" />
        </div>
      </div>
    </section>

    <section class="panel">
      <h2>Streaming latency</h2>
      <p v-if="!hasStreaming" class="hint">
        No streamed completions yet. TTFT, TPOT, and throughput record once per
        streaming response.
      </p>
      <div class="subgrid" v-else>
        <div>
          <h3>TTFT p95 (provider / model)</h3>
          <MiniBars :items="ttftByModel" :format="formatSecs" />
        </div>
        <div>
          <h3>TPOT p95 (provider / model)</h3>
          <MiniBars v-if="tpotByModel.length" :items="tpotByModel" :format="formatSecs" />
          <p v-else class="hint">
            No inter-token latency samples yet (needs a streamed completion
            with at least two tokens).
          </p>
        </div>
        <div>
          <h3>Throughput by model (avg)</h3>
          <MiniBars :items="tpsByModel" :format="formatTps" />
        </div>
      </div>
    </section>

    <section class="panel" v-if="latencyBySurface.length">
      <h2>Request latency p95 by surface</h2>
      <MiniBars :items="latencyBySurface" :format="formatSecs" />
    </section>

    <section class="panel" v-if="hasCompression">
      <h2>Context compression</h2>
      <div class="tiles">
        <StatCard
          label="compressed requests"
          :value="formatNumber(compressionTotalRequests)"
          tone="accent"
        />
        <StatCard label="tokens saved" :value="formatNumber(compressionTokensSaved)" />
        <StatCard
          v-if="compressionCostSaved > 0"
          label="cost saved"
          :value="formatUsd(compressionCostSaved)"
        />
      </div>
      <div class="cols">
        <div v-if="compressionSavedByLever.length">
          <h3>Tokens saved by lever</h3>
          <MiniBars :items="compressionSavedByLever" />
        </div>
        <div v-if="compressionByOutcome.length">
          <h3>Requests by outcome</h3>
          <MiniBars :items="compressionByOutcome" />
        </div>
        <div v-if="compressionRatioByLever.length">
          <h3>Avg compression ratio by lever</h3>
          <MiniBars :items="compressionRatioByLever" />
        </div>
      </div>
    </section>
  </template>
</template>

<style scoped>
.tiles {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: 12px;
  margin-bottom: 20px;
}
.cols {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
  gap: var(--sb-space-5);
}
.cols h3 {
  font-size: 0.85rem;
  margin-bottom: var(--sb-space-3);
}
.panel {
  margin-bottom: 24px;
}
.panel h2 {
  font-size: 13px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: var(--sb-text-muted);
  margin: 0 0 8px;
}
.panel h3 {
  font-size: 12px;
  font-weight: 600;
  color: var(--sb-text-muted);
  margin: 12px 0 6px;
}
.subgrid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
  gap: 8px 24px;
}
.detail {
  width: 100%;
  border-collapse: collapse;
  margin-top: 8px;
  font-size: 13px;
}
.detail th {
  text-align: left;
  font-weight: 500;
  color: var(--sb-text-muted);
  padding: 6px 8px;
  border-bottom: 1px solid var(--sb-border);
}
.detail td {
  padding: 6px 8px;
  border-bottom: 1px solid var(--sb-border);
  font-variant-numeric: tabular-nums;
}
.code {
  font-size: 11px;
  margin-top: 2px;
}
.rate {
  display: flex;
  align-items: center;
  gap: 8px;
  min-width: 180px;
}
.rate-bar {
  flex: 1;
  height: 8px;
  border-radius: 0;
  background: var(--sb-bg-subtle, rgba(127, 127, 127, 0.15));
  overflow: hidden;
}
.rate-fill {
  height: 100%;
  border-radius: 0;
}
.rate--ok .rate-fill {
  background: var(--sb-ok, #178a50);
}
.rate--warn .rate-fill {
  background: var(--sb-warn, #b7791f);
}
.rate--err .rate-fill {
  background: var(--sb-err, #c53030);
}
.rate--err .rate-num {
  color: var(--sb-err, #c53030);
  font-weight: 700;
}
.rate-num {
  font-variant-numeric: tabular-nums;
  font-size: 12px;
}
.hint {
  font-size: 13px;
  color: var(--sb-text-muted);
  margin: 4px 0 0;
}
</style>
