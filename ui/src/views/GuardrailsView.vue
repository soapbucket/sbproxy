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
const poisoningFindings = computed(() =>
  fam("sbproxy_ai_context_poisoning_findings_total"),
);
// WOR-2095: blocked poisoning findings are the `action="block"` slice of
// the findings family; the separate *_blocked_total name never existed.
const poisoningBlockCount = computed(() =>
  sumSamples(poisoningFindings.value, { action: "block" }),
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
    poisoningBlockCount.value,
);
const totalWafPlane = computed(
  () =>
    sumSamples(wafBlocks.value) +
    sumSamples(framingBlocks.value) +
    sumSamples(objectAuthz.value),
);

// --- A2A policy engagement (WOR-2120) ---
//
// The a2a policy can be configured and still protect nothing, which is
// the failure this panel exists to surface. Its checks read an envelope
// that is only trustworthy when it comes from a signed token's `act`
// chain or from a peer in `proxy.trusted_proxies`. Without either, the
// policy evaluates an empty envelope: depth 1, no chain, no caller. It
// allows everything and looks identical to a healthy policy unless you
// split the allows apart, which is what the `decision` label now does.
const a2aHops = computed(() => fam("sbproxy_a2a_hops_total"));
const a2aDenied = computed(() => fam("sbproxy_a2a_denied_total"));

const a2aVerified = computed(() => sumSamples(a2aHops.value, { decision: "allow:verified" }));
const a2aUnverified = computed(() =>
  sumSamples(a2aHops.value, { decision: "allow:unverified" }),
);
const a2aSkipped = computed(() => sumSamples(a2aHops.value, { decision: "skip:undetected" }));
const a2aDeniedTotal = computed(() => sumSamples(a2aDenied.value));
const a2aTotal = computed(() => sumSamples(a2aHops.value));

const a2aDeniedByReason = computed(() => groupByLabel(a2aDenied.value, "reason"));
const a2aByDecision = computed(() => groupByLabel(a2aHops.value, "decision"));

/// True when the policy has run but has never once evaluated an
/// envelope it could verify. Every decision it made was on data the
/// caller supplied or on nothing at all.
const a2aNeverVerified = computed(
  () => a2aTotal.value > 0 && a2aVerified.value === 0,
);

/// True when traffic reached the policy without being recognised as
/// A2A. Detection keys on `Content-Type` and `MCP-Method`, both of
/// which the caller chooses, so a high skip count on a route that is
/// meant to be governed usually means `route_glob` is unset.
const a2aMostlySkipped = computed(
  () => a2aTotal.value > 0 && a2aSkipped.value > a2aTotal.value / 2,
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
    sumSamples(streamSkipped.value) > 0 ||
    a2aTotal.value > 0,
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
          <p class="hint" v-if="sumSamples(streamSkipped) > 0">
            {{ formatNumber(sumSamples(streamSkipped)) }} evaluations skipped.
          </p>
        </div>
        <div v-if="poisoningByRule.length">
          <h3>Context poisoning (rule / action)</h3>
          <MiniBars :items="poisoningByRule" :format="formatNumber" />
        </div>
      </div>
    </section>

    <section class="panel" v-if="a2aTotal > 0">
      <h2>Agent-to-agent policy</h2>

      <div v-if="a2aNeverVerified" class="notice">
        <strong>This policy has never evaluated a verified envelope.</strong>
        Every decision so far was made on caller-supplied data or on no data
        at all, so the chain-depth cap, cycle detection, and the caller and
        callee lists have nothing dependable to check. Give it a trustworthy
        source: authenticate callers so the delegation chain arrives in the
        token's <code>act</code> claims, or list the peer that stamps the
        <code>X-A2A-*</code> headers in <code>proxy.trusted_proxies</code>.
      </div>

      <div v-else-if="a2aMostlySkipped" class="notice">
        <strong>Most requests here were never recognised as A2A.</strong>
        Detection keys on <code>Content-Type</code> and
        <code>MCP-Method</code>, which the caller chooses, and an
        unrecognised request is allowed. Set <code>route_glob</code> on the
        routes you mean to govern; it is the only detection signal a caller
        cannot opt out of.
      </div>

      <div class="tiles">
        <StatCard
          label="Verified hops"
          :value="formatNumber(a2aVerified)"
          :tone="a2aVerified > 0 ? 'accent' : undefined"
          sub="chain came from a signed token"
        />
        <StatCard
          label="Unverified hops"
          :value="formatNumber(a2aUnverified)"
          sub="envelope could not be trusted"
        />
        <StatCard
          label="Not recognised"
          :value="formatNumber(a2aSkipped)"
          sub="policy did not engage"
        />
        <StatCard
          label="Denied"
          :value="formatNumber(a2aDeniedTotal)"
          sub="depth, cycle, or list"
        />
      </div>

      <div class="subgrid">
        <div>
          <h3>Hops by decision</h3>
          <MiniBars :items="a2aByDecision" :format="formatNumber" />
        </div>
        <div v-if="a2aDeniedByReason.length">
          <h3>Denials by reason</h3>
          <MiniBars :items="a2aDeniedByReason" :format="formatNumber" />
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
.notice {
  border: 1px solid var(--sb-border);
  border-left: 3px solid var(--sb-warn);
  background: var(--sb-warn-bg);
  color: var(--sb-warn-fg);
  padding: 10px 12px;
  margin-bottom: 12px;
  font-size: 13px;
  line-height: 1.5;
}
.notice code {
  font-size: 12px;
}
</style>
