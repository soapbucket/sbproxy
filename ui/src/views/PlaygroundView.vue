<script setup lang="ts">
import { computed, onMounted, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";
import {
  api,
  ApiError,
  type AdminKeySummary,
  type ContentSample,
  type PlaygroundChatResult,
} from "../api";
import { useAsync } from "../composables/useAsync";
import { formatMs, formatNumber, formatUsd, shortId } from "../lib/format";
import {
  beginReplay,
  replayAvailabilityNotes,
  replayDispatchMessages,
  replayGaps,
  resolveReplayContent,
  type ReplayDraft,
} from "../lib/replay";
import PageHeader from "../components/PageHeader.vue";
import StatCard from "../components/StatCard.vue";
import StatusBadge from "../components/StatusBadge.vue";
import ErrorState from "../components/ErrorState.vue";
import EmptyState from "../components/EmptyState.vue";

const route = useRoute();
const router = useRouter();

const endpointsReq = useAsync(() => api.playgroundEndpoints());
const keysReq = useAsync(() => api.keysList());
function refresh() {
  endpointsReq.run();
  keysReq.run();
}
onMounted(() => {
  refresh();
  // WOR-2580: a Logs row hands its request id over as `?replay=`; the
  // metadata the ring retains (origin, model, minted key) rides along
  // so the form pre-fills even when no content sample exists.
  if (typeof route.query.replay === "string" && route.query.replay) {
    startReplay();
  }
});

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

// The model picker's options: the endpoint's declared list, plus the
// replayed model when the endpoint no longer declares it, so the
// selection stays visible instead of rendering as a blank select.
const modelOptions = computed<string[]>(() => {
  const models = [...originModels.value];
  const replayModel = replay.value?.model;
  if (replayModel && !models.includes(replayModel)) models.push(replayModel);
  return models;
});

// Pick a sensible default once endpoints (or keys) arrive.
const ready = computed(() => endpoints.value.length > 0);
watch(endpoints, (eps) => {
  if (!selectedOrigin.value && eps.length) {
    selectedOrigin.value = eps[0].origin;
    onOriginChange();
  }
});
watch(activeKeys, (keys) => {
  if (!keys.length) return;
  // A replay prefers the key the original request ran as, so the same
  // key policy governs both runs; anything else defaults to the first
  // active key, and a selection the operator already made stands.
  const replayKey = replay.value?.keyId;
  if (replayKey && keys.some((k) => k.key_id === replayKey)) {
    if (!selectedKeyId.value || selectedKeyId.value === keys[0].key_id) {
      selectedKeyId.value = replayKey;
    }
    return;
  }
  if (!selectedKeyId.value) {
    selectedKeyId.value = keys[0].key_id;
  }
});

// WOR-2580: replay a logged request through the governed dispatch path.
const replay = ref<ReplayDraft | null>(null);

function queryString(value: unknown): string | undefined {
  return typeof value === "string" && value ? value : undefined;
}

async function startReplay() {
  const requestId = queryString(route.query.replay);
  if (!requestId) return;
  const draft = beginReplay({
    requestId,
    origin: queryString(route.query.origin),
    model: queryString(route.query.model),
    keyId: queryString(route.query.key),
  });
  replay.value = draft;
  applyReplaySelections(draft);
  // The body exists only as the WOR-2096 redacted content sample, read
  // through the same audited admin endpoint as any other log read. A
  // miss (no capture consent, evicted, or a read_only operator) leaves
  // the body unreconstructed and says so; nothing is invented.
  let sample: ContentSample | null = null;
  let sampleError: string | null = null;
  try {
    sample = await api.requestContent(requestId);
  } catch (e) {
    sampleError = e instanceof Error ? e.message : "content sample unavailable";
  }
  if (replay.value?.requestId !== requestId) return; // superseded or cleared
  const settled = resolveReplayContent(replay.value, sample, sampleError);
  replay.value = settled;
  // Re-apply only the fields the URL lacked and the sample filled in,
  // so a selection the operator changed while the fetch was in flight
  // stands.
  applyReplaySelections({
    ...settled,
    origin: draft.origin ? undefined : settled.origin,
    model: draft.model ? undefined : settled.model,
    keyId: draft.keyId ? undefined : settled.keyId,
  });
  if (settled.prompt) prompt.value = settled.prompt;
}

function applyReplaySelections(draft: ReplayDraft) {
  if (draft.origin) selectedOrigin.value = draft.origin;
  if (draft.model) selectedModel.value = draft.model;
  const keys = activeKeys.value;
  if (draft.keyId && keys.some((k) => k.key_id === draft.keyId)) {
    selectedKeyId.value = draft.keyId;
  }
}

function clearReplay() {
  replay.value = null;
  router.replace({ name: "playground" });
}

watch(
  () => route.query.replay,
  (id) => {
    if (typeof id === "string" && id && id !== replay.value?.requestId) {
      startReplay();
    }
  },
);

/** Everything the reconstruction could not recover or no longer resolves. */
const replayNotes = computed<string[]>(() => {
  const draft = replay.value;
  if (!draft) return [];
  return [
    ...replayGaps(draft),
    ...replayAvailabilityNotes(draft, {
      origins: endpointsReq.data.value
        ? endpoints.value.map((e) => e.origin)
        : undefined,
      keyIds: keysReq.data.value
        ? activeKeys.value.map((k) => k.key_id)
        : undefined,
      models: originModels.value.length ? originModels.value : undefined,
    }),
  ];
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
  // A replay carries every captured message in order, with the prompt
  // box's text in the last user slot; otherwise this is the plain
  // single-prompt form.
  const request: Record<string, unknown> = {
    messages: replayDispatchMessages(replay.value, prompt.value),
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
    <div v-if="replay" class="sb-card replay">
      <div class="replay__head">
        <h3>
          Replaying request
          <span class="sb-mono" :title="replay.requestId">{{
            shortId(replay.requestId)
          }}</span>
        </h3>
        <button class="sb-btn sb-btn--sm" @click="clearReplay">Clear replay</button>
      </div>
      <p class="replay__lede">
        The reconstructed request dispatches through the governed pipeline:
        key policy, budgets, routing, and guardrails all apply, exactly as
        they did for the original request.
      </p>
      <div v-if="replay.content === 'captured' && replay.messages" class="replay__capture">
        <p class="sb-eyebrow">Captured input (redacted)</p>
        <div
          v-for="(msg, msgIndex) in replay.messages"
          :key="msgIndex"
          class="replay__message"
        >
          <span class="replay__role sb-mono">{{ msg.role }}</span>
          <span class="replay__text">{{ msg.content }}</span>
        </div>
        <p class="sb-faint">
          The Prompt box below edits the last user message; the other captured
          messages replay unchanged.
        </p>
      </div>
      <ul class="replay__notes">
        <li v-for="note in replayNotes" :key="note">{{ note }}</li>
      </ul>
    </div>
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
          <select v-if="modelOptions.length" v-model="selectedModel" class="sb-input">
            <option v-for="m in modelOptions" :key="m" :value="m">{{ m }}</option>
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
.replay {
  display: flex;
  flex-direction: column;
  gap: var(--sb-space-3);
  margin-bottom: var(--sb-space-4);
}
.replay__head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--sb-space-3);
}
.replay__lede {
  margin: 0;
  color: var(--sb-text-muted);
  font-size: 0.85rem;
}
.replay__capture {
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.replay__message {
  display: grid;
  grid-template-columns: 90px 1fr;
  gap: var(--sb-space-3);
  font-size: 0.85rem;
}
.replay__role {
  color: var(--sb-text-muted);
}
.replay__text {
  white-space: pre-wrap;
  word-break: break-word;
}
.replay__notes {
  margin: 0;
  padding-left: 1.2em;
  color: var(--sb-text-muted);
  font-size: 0.82rem;
  display: flex;
  flex-direction: column;
  gap: 4px;
}
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
