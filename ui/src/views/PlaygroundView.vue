<script setup lang="ts">
import { computed, onMounted, ref, watch } from "vue";
import { api, ApiError, type AdminKeySummary, type PlaygroundChatResult } from "../api";
import { useAsync } from "../composables/useAsync";
import { formatMs, formatNumber, formatUsd } from "../lib/format";
import PageHeader from "../components/PageHeader.vue";
import StatCard from "../components/StatCard.vue";
import StatusBadge from "../components/StatusBadge.vue";
import ErrorState from "../components/ErrorState.vue";
import EmptyState from "../components/EmptyState.vue";

const endpointsReq = useAsync(() => api.playgroundEndpoints());
const keysReq = useAsync(() => api.keysList());
function refresh() {
  endpointsReq.run();
  keysReq.run();
}
onMounted(refresh);

const endpoints = computed(() => endpointsReq.data.value?.endpoints ?? []);
// Only an active key can dispatch; a blocked or revoked one would just
// deny once impersonated, so leave it out of the picker.
const activeKeys = computed<AdminKeySummary[]>(() =>
  (keysReq.data.value?.keys ?? []).filter((key) => key.status === "active"),
);

const selectedOrigin = ref("");
const selectedModel = ref("");
const selectedKeyId = ref("");
const prompt = ref("");
const sending = ref(false);
const result = ref<PlaygroundChatResult | null>(null);
const chatError = ref<ApiError | null>(null);

// Default the origin to the first configured endpoint once loaded.
const originModels = computed<string[]>(() => {
  const ep = endpoints.value.find((e) => e.origin === selectedOrigin.value);
  if (!ep) return [];
  const models = new Set<string>();
  for (const p of ep.providers) {
    for (const m of p.models) models.add(m);
    if (p.default_model) models.add(p.default_model);
  }
  return [...models];
});

function onOriginChange() {
  selectedModel.value = originModels.value[0] ?? "";
}

// Pick a sensible default once endpoints (or keys) arrive.
const ready = computed(() => endpoints.value.length > 0);
watch(endpoints, (eps) => {
  if (!selectedOrigin.value && eps.length) {
    selectedOrigin.value = eps[0].origin;
    onOriginChange();
  }
});
watch(activeKeys, (keys) => {
  if (!selectedKeyId.value && keys.length) {
    selectedKeyId.value = keys[0].key_id;
  }
});

const answer = computed<string>(() => {
  const r = result.value?.response as any;
  const choice = r?.choices?.[0];
  return (
    choice?.message?.content ??
    choice?.text ??
    (r ? JSON.stringify(r, null, 2) : "")
  );
});

const showRaw = ref(false);
const debugMode = ref(false);

async function send() {
  if (
    !selectedOrigin.value ||
    !selectedKeyId.value ||
    !prompt.value.trim() ||
    sending.value
  ) {
    return;
  }
  sending.value = true;
  chatError.value = null;
  result.value = null;
  const request: Record<string, unknown> = {
    messages: [{ role: "user", content: prompt.value }],
    stream: false,
  };
  if (selectedModel.value) request.model = selectedModel.value;
  try {
    // Real dispatch: this runs the request through the actual data-plane
    // pipeline for the selected virtual key (key policy, governance,
    // routing, guardrails all apply), rather than the bypass path
    // `playgroundChat` used to call directly.
    result.value = await api.playgroundDispatch({
      key_id: selectedKeyId.value,
      origin: selectedOrigin.value,
      request,
      debug: debugMode.value,
    });
  } catch (e) {
    chatError.value = e as ApiError;
  } finally {
    sending.value = false;
  }
}
</script>

<template>
  <PageHeader
    title="Playground"
    subtitle="Send a chat completion to any AI endpoint this server is configured with, and see the response, token usage, cost, and latency."
  >
    <template #actions>
      <button class="sb-btn sb-btn--sm" @click="refresh">Refresh</button>
    </template>
  </PageHeader>

  <ErrorState
    v-if="endpointsReq.error.value"
    :error="endpointsReq.error.value"
    @retry="endpointsReq.run"
  />
  <EmptyState
    v-else-if="endpointsReq.data.value !== null && !ready"
    message="No AI endpoints are configured on this server. Add an ai_proxy origin to use the playground."
  />
  <template v-else>
    <ErrorState
      v-if="keysReq.error.value"
      :error="keysReq.error.value"
      title="Could not load virtual keys"
      @retry="keysReq.run"
    />
    <div class="sb-card form">
      <div class="row">
        <label>
          <span class="lbl">Endpoint</span>
          <select v-model="selectedOrigin" @change="onOriginChange" class="sb-input">
            <option v-for="e in endpoints" :key="e.origin" :value="e.origin">
              {{ e.origin }}
            </option>
          </select>
        </label>
        <label>
          <span class="lbl">Model</span>
          <select v-if="originModels.length" v-model="selectedModel" class="sb-input">
            <option v-for="m in originModels" :key="m" :value="m">{{ m }}</option>
          </select>
          <input
            v-else
            v-model="selectedModel"
            class="sb-input"
            placeholder="model name (provider catalog)"
          />
        </label>
        <label>
          <span class="lbl">Dispatch as key</span>
          <select v-model="selectedKeyId" class="sb-input" :disabled="!activeKeys.length">
            <option v-if="!activeKeys.length" value="">No active keys</option>
            <option v-for="k in activeKeys" :key="k.key_id" :value="k.key_id">
              {{ k.name || k.key_id }}
            </option>
          </select>
          <span v-if="keysReq.succeeded.value && !activeKeys.length" class="sb-faint hint">
            No active virtual keys. Create one on the Keys page first.
          </span>
        </label>
      </div>
      <label class="prompt-label">
        <span class="lbl">Prompt</span>
        <textarea
          v-model="prompt"
          class="sb-input prompt"
          rows="4"
          placeholder="Ask the model something..."
          @keydown.ctrl.enter="send"
          @keydown.meta.enter="send"
        ></textarea>
      </label>
      <div class="actions">
        <label class="debug-toggle">
          <input type="checkbox" v-model="debugMode" />
          <span>Debug</span>
        </label>
        <span class="sb-faint hint">Ctrl/Cmd + Enter to send</span>
        <button
          class="sb-btn sb-btn--primary"
          :disabled="sending || !prompt.trim() || !selectedOrigin || !selectedKeyId"
          :title="!selectedKeyId ? 'Choose an active virtual key to dispatch as' : undefined"
          @click="send"
        >
          {{ sending ? "Sending..." : "Send" }}
        </button>
      </div>
    </div>

    <ErrorState v-if="chatError" :error="chatError" />

    <template v-if="result">
      <div class="grid">
        <StatCard
          label="Status"
          :value="result.status ?? '?'"
          :tone="(result.status ?? 0) < 300 ? 'accent' : 'default'"
        />
        <StatCard label="Model" :value="result.model || 'n/a'" />
        <StatCard
          label="Tokens"
          :value="formatNumber((result.usage?.input_tokens ?? 0) + (result.usage?.output_tokens ?? 0))"
          :sub="`${result.usage?.input_tokens ?? 0} in / ${result.usage?.output_tokens ?? 0} out`"
        />
        <StatCard label="Cost" :value="formatUsd(result.cost_usd)" />
        <StatCard label="Latency" :value="formatMs(result.latency_ms)" />
      </div>

      <div class="sb-card answer">
        <div class="answer__head">
          <h3>Response</h3>
          <div class="answer__meta">
            <StatusBadge
              :label="String(result.status ?? '?')"
              :tone="(result.status ?? 0) < 300 ? 'ok' : 'warn'"
            />
            <button class="sb-btn sb-btn--sm" @click="showRaw = !showRaw">
              {{ showRaw ? "Hide raw" : "Raw JSON" }}
            </button>
          </div>
        </div>
        <pre v-if="showRaw" class="sb-code">{{ JSON.stringify(result.response, null, 2) }}</pre>
        <pre v-else class="answer__text">{{ answer }}</pre>
      </div>

      <div class="sb-card debug" v-if="result.debug">
        <h3>Debug</h3>
        <dl class="debug-grid">
          <dt>Request id</dt>
          <dd class="sb-mono">{{ result.debug.request_id ?? "-" }}</dd>
          <dt>Config revision</dt>
          <dd class="sb-mono">{{ result.debug.config_revision ?? "-" }}</dd>
        </dl>
        <p class="sb-faint">
          Logged server-side under the admin::playground target; grep the
          request id to correlate. The config revision is the pipeline that
          served this request.
        </p>
      </div>
    </template>
  </template>
</template>

<style scoped>
.form {
  display: flex;
  flex-direction: column;
  gap: var(--sb-space-4);
  margin-bottom: var(--sb-space-5);
}
.row {
  display: grid;
  grid-template-columns: 1fr 1fr 1fr;
  gap: var(--sb-space-4);
}
label {
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.lbl {
  font-size: 0.78rem;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--sb-text-muted);
}
.prompt {
  font-family: var(--sb-font-mono);
  resize: vertical;
}
.actions {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: var(--sb-space-4);
}
.debug-toggle {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 0.85rem;
  color: var(--sb-text-muted);
  margin-right: auto;
  cursor: pointer;
}
.debug-grid {
  display: grid;
  grid-template-columns: max-content 1fr;
  gap: 6px 16px;
  margin-bottom: var(--sb-space-3);
  font-size: 0.85rem;
}
.debug-grid dt {
  color: var(--sb-text-muted);
}
.debug-grid dd {
  margin: 0;
  word-break: break-all;
}
.debug h3 {
  margin-bottom: var(--sb-space-3);
}
.hint {
  font-size: 0.78rem;
}
.grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
  gap: var(--sb-space-4);
  margin-bottom: var(--sb-space-5);
}
.answer__head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: var(--sb-space-4);
}
.answer__meta {
  display: flex;
  align-items: center;
  gap: var(--sb-space-3);
}
.answer__text {
  white-space: pre-wrap;
  word-break: break-word;
  margin: 0;
  font-family: var(--sb-font-mono);
  font-size: 0.9rem;
  line-height: 1.5;
}
@media (max-width: 720px) {
  .row {
    grid-template-columns: 1fr;
  }
}
</style>
