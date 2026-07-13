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
  type MetricFamily,
} from "../lib/metrics";
import { formatNumber, formatUsd } from "../lib/format";
import PageHeader from "../components/PageHeader.vue";
import StatCard from "../components/StatCard.vue";
import MiniBars from "../components/MiniBars.vue";
import ErrorState from "../components/ErrorState.vue";

const req = useAsync(() => api.metrics());
onMounted(req.run);

const families = computed<MetricFamily[]>(() => {
  const text = req.data.value;
  return text ? parsePrometheus(text) : [];
});

function fam(name: string) {
  return findFamily(families.value, name);
}

// --- Guardrail block families (WOR-1872) ---
const guardrailBlocks = computed(() => fam("sbproxy_ai_guardrail_blocks_total"));
const streamViolations = computed(() =>
  fam("sbproxy_ai_stream_guardrail_violations_total"),
);
const streamSkipped = computed(() => fam("sbproxy_ai_stream_guardrail_skipped_total"));
const decodeFallback = computed(() =>
  fam("sbproxy_ai_stream_guardrail_decode_fallback_total"),
);
const poisoningFindings = computed(() =>
  fam("sbproxy_ai_context_poisoning_findings_total"),
);
const poisoningBlocked = computed(() =>
  fam("sbproxy_ai_context_poisoning_blocked_total"),
);
const wafBlocks = computed(() => fam("sbproxy_waf_persistent_blocks_total"));
const framingBlocks = computed(() => fam("sbproxy_http_framing_blocks_total"));
const objectAuthz = computed(() => fam("sbproxy_object_authz_violations_total"));

const blocksByCategory = computed(() => groupByLabel(guardrailBlocks.value, "category"));
const streamByGuardrail = computed(() => groupByLabel(streamViolations.value, "guardrail"));
const poisoningByRule = computed(() =>
  groupByLabels(poisoningFindings.value, ["rule_id", "action"]),
);

const totalBlocks = computed(
  () =>
    sumSamples(guardrailBlocks.value) +
    sumSamples(streamViolations.value) +
    sumSamples(poisoningBlocked.value),
);
const totalWafPlane = computed(
  () =>
    sumSamples(wafBlocks.value) +
    sumSamples(framingBlocks.value) +
    sumSamples(objectAuthz.value),
);

// --- Waste (WOR-1872): what retries and abandoned streams cost ---
const wastedTokens = computed(() => fam("sbproxy_ai_wasted_tokens_total"));
const wastedCost = computed(() => fam("sbproxy_ai_wasted_cost_dollars_total"));
const wasteTokensByKind = computed(() => groupByLabel(wastedTokens.value, "kind"));
const wasteCostByKind = computed(() => groupByLabel(wastedCost.value, "kind"));
const totalWastedCost = computed(() => sumSamples(wastedCost.value));
const totalWastedTokens = computed(() => sumSamples(wastedTokens.value));

const hasAnySignal = computed(
  () =>
    totalBlocks.value > 0 ||
    totalWafPlane.value > 0 ||
    totalWastedTokens.value > 0 ||
    sumSamples(streamSkipped.value) > 0,
);
</script>

<template>
  <PageHeader
    title="Guardrails"
    subtitle="Governance outcomes: what the guardrail, WAF, and authz planes blocked, and what wasted spend the gateway flagged."
  >
    <template #actions>
      <RouterLink class="sb-btn" :to="{ path: '/logs', query: { guardrail_action: 'block' } }">
        Blocked requests in Logs
      </RouterLink>
    </template>
  </PageHeader>

  <ErrorState v-if="req.error.value" :error="req.error.value" @retry="req.run" />

  <div v-else-if="!req.loading.value && !hasAnySignal" class="sb-card empty-card">
    <p>
      No guardrail activity recorded since the proxy started. This view fills in
      once an origin declares guardrails (input or output) and one intervenes,
      or once the gateway flags wasted spend (duplicate requests, abandoned
      streams, validation failures).
    </p>
    <p class="sb-faint">
      Guardrails are configured per origin under the AI handler's
      guardrails block; see the AI gateway docs for the catalogue.
    </p>
  </div>

  <template v-else-if="hasAnySignal">
    <div class="tiles">
      <StatCard label="Guardrail blocks" :value="formatNumber(totalBlocks)" tone="accent" sub="since start" />
      <StatCard label="WAF / framing / authz" :value="formatNumber(totalWafPlane)" sub="protocol-plane blocks" />
      <StatCard label="Wasted tokens" :value="formatNumber(totalWastedTokens)" sub="flagged by waste detectors" />
      <StatCard label="Wasted spend" :value="formatUsd(totalWastedCost)" sub="tokens with no served outcome" />
    </div>

    <section class="panel" v-if="blocksByCategory.length || streamByGuardrail.length || poisoningByRule.length">
      <h2>Blocks by category</h2>
      <div class="subgrid">
        <div v-if="blocksByCategory.length">
          <h3>Input / output guardrails</h3>
          <MiniBars :items="blocksByCategory" :format="formatNumber" />
        </div>
        <div v-if="streamByGuardrail.length">
          <h3>Streaming guardrails</h3>
          <MiniBars :items="streamByGuardrail" :format="formatNumber" />
          <p class="hint" v-if="sumSamples(streamSkipped) > 0 || sumSamples(decodeFallback) > 0">
            {{ formatNumber(sumSamples(streamSkipped)) }} evaluations skipped,
            {{ formatNumber(sumSamples(decodeFallback)) }} decode fallbacks.
          </p>
        </div>
        <div v-if="poisoningByRule.length">
          <h3>Context poisoning (rule / action)</h3>
          <MiniBars :items="poisoningByRule" :format="formatNumber" />
        </div>
      </div>
    </section>

    <section class="panel" v-if="totalWafPlane > 0">
      <h2>Protocol-plane blocks</h2>
      <div class="subgrid">
        <div v-if="sumSamples(wafBlocks) > 0">
          <h3>WAF persistent blocks (origin / event)</h3>
          <MiniBars :items="groupByLabels(wafBlocks, ['origin', 'event'])" :format="formatNumber" />
        </div>
        <div v-if="sumSamples(framingBlocks) > 0">
          <h3>HTTP framing blocks (reason)</h3>
          <MiniBars :items="groupByLabels(framingBlocks, ['reason'])" :format="formatNumber" />
        </div>
        <div v-if="sumSamples(objectAuthz) > 0">
          <h3>Object authz violations (kind)</h3>
          <MiniBars :items="groupByLabels(objectAuthz, ['kind'])" :format="formatNumber" />
        </div>
      </div>
    </section>

    <section class="panel" v-if="totalWastedTokens > 0 || totalWastedCost > 0">
      <h2>Waste by kind</h2>
      <p class="hint">
        Deterministic detectors: duplicate requests, abandoned streams,
        validation failures, context bloat, failover losers. This is the spend
        that bought no served outcome.
      </p>
      <div class="subgrid">
        <div>
          <h3>Wasted tokens</h3>
          <MiniBars :items="wasteTokensByKind" :format="formatNumber" />
        </div>
        <div>
          <h3>Wasted spend</h3>
          <MiniBars :items="wasteCostByKind" :format="formatUsd" />
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
.empty-card p {
  margin: 0 0 8px;
  font-size: 0.9rem;
}
.hint {
  font-size: 13px;
  color: var(--sb-text-muted);
  margin: 4px 0 0;
}
</style>
