<script setup lang="ts">
import { computed, onMounted } from "vue";

import {
  api,
  type ExtensionBundleRecord,
  type ExtensionHookRecord,
  type ExtensionLoadRecord,
} from "../api";
import EmptyState from "../components/EmptyState.vue";
import ErrorState from "../components/ErrorState.vue";
import PageHeader from "../components/PageHeader.vue";
import StatusBadge from "../components/StatusBadge.vue";
import { useAsync } from "../composables/useAsync";
import {
  hooksForBundle,
  loadLabel,
  sourceLabel,
  stateTone,
} from "../lib/extensions";

const inventory = useAsync(() => api.extensions(), {
  pollMs: 15_000,
  refreshLabel: "Extension inventory",
});
const snapshot = inventory.data;

function loadExtensions() {
  return inventory.run();
}

onMounted(loadExtensions);

const failedBundles = computed(
  () => snapshot.value?.bundles.filter((bundle) => bundle.state === "failed") ?? [],
);

function label(value: string): string {
  const words = value.replaceAll("_", " ");
  if (value === "javascript") return "JavaScript";
  if (value === "proxy_wasm") return "Proxy-Wasm";
  if (value === "mcp") return "MCP";
  return words;
}

function shortRevision(revision: string | null): string {
  if (!revision) return "not reported";
  return revision.length > 28 ? `${revision.slice(0, 25)}...` : revision;
}

function loadTone(load: ExtensionLoadRecord) {
  return load.status === "ok"
    ? "ok"
    : load.status === "failed" || load.status === "degraded"
      ? "err"
      : "neutral";
}

function hookPosition(hook: ExtensionHookRecord): string {
  return hook.position === null ? "not attached" : `chain ${hook.position + 1}`;
}

function timeoutLabel(timeoutMs: number | null): string {
  return timeoutMs === null ? "host default" : `${timeoutMs} ms`;
}

function bufferLabel(bytes: number | null): string {
  if (bytes === null) return "none";
  if (bytes < 1024) return `${bytes} B`;
  return `${Math.round(bytes / 1024)} KiB`;
}

function bundleHooks(bundle: ExtensionBundleRecord): ExtensionHookRecord[] {
  return snapshot.value ? hooksForBundle(snapshot.value, bundle.id) : [];
}
</script>

<template>
  <PageHeader
    title="Extensions"
    subtitle="Installed code, active hooks, and loader evidence for this running generation."
  >
    <template #actions>
      <button
        class="sb-btn sb-btn--sm"
        :disabled="inventory.loading.value || inventory.refreshing.value"
        @click="loadExtensions"
      >
        {{ inventory.refreshing.value ? "Refreshing..." : "Refresh" }}
      </button>
    </template>
  </PageHeader>

  <ErrorState
    v-if="inventory.error.value && !snapshot"
    :error="inventory.error.value"
    title="Could not load extension inventory"
    @retry="loadExtensions"
  />
  <EmptyState
    v-else-if="!snapshot"
    :message="
      inventory.loading.value
        ? 'Loading extension inventory...'
        : 'Extension inventory is unavailable.'
    "
  />

  <template v-else>
    <section
      v-if="inventory.error.value"
      class="refresh-warning"
      aria-label="Extension inventory refresh warning"
    >
      <div>
        <strong>Showing the last loaded generation.</strong>
        <span>{{ inventory.error.value.hint }}</span>
      </div>
      <button class="sb-btn sb-btn--sm" @click="loadExtensions">Retry refresh</button>
    </section>

    <section class="generation" aria-labelledby="generation-title">
      <div class="generation__identity">
        <span class="generation__eyebrow sb-mono">
          {{ snapshot.scope.mode }} snapshot
        </span>
        <h2 id="generation-title">Running generation</h2>
        <code :title="snapshot.scope.config_revision ?? undefined">
          {{ shortRevision(snapshot.scope.config_revision) }}
        </code>
      </div>
      <dl class="generation__meta">
        <div>
          <dt>Proxy</dt>
          <dd>v{{ snapshot.scope.proxy_version }}</dd>
        </div>
        <div>
          <dt>Inventory schema</dt>
          <dd>v{{ snapshot.schema_version }}</dd>
        </div>
        <div>
          <dt>Authority</dt>
          <dd>active pipeline</dd>
        </div>
      </dl>
    </section>

    <section class="summary" aria-label="Extension inventory summary">
      <div>
        <span class="summary__value">{{ snapshot.summary.bundles }}</span>
        <span class="summary__label sb-mono">bundles</span>
      </div>
      <div>
        <span class="summary__value">{{ snapshot.summary.hooks }}</span>
        <span class="summary__label sb-mono">hooks</span>
      </div>
      <div>
        <span class="summary__value summary__value--ok">{{ snapshot.summary.active }}</span>
        <span class="summary__label sb-mono">active</span>
      </div>
      <div>
        <span class="summary__value summary__value--info">{{ snapshot.summary.available }}</span>
        <span class="summary__label sb-mono">available</span>
      </div>
      <div>
        <span class="summary__value" :class="{ 'summary__value--err': snapshot.summary.failed }">
          {{ snapshot.summary.failed }}
        </span>
        <span class="summary__label sb-mono">failed</span>
      </div>
      <div>
        <span
          class="summary__value"
          :class="{ 'summary__value--warn': snapshot.summary.collisions }"
        >
          {{ snapshot.summary.collisions }}
        </span>
        <span class="summary__label sb-mono">collisions</span>
      </div>
    </section>

    <section
      v-if="failedBundles.length || snapshot.collisions.length"
      class="incidents"
      aria-labelledby="attention-title"
    >
      <div class="section-heading">
        <span class="sb-eyebrow">Loader attention</span>
        <h2 id="attention-title">Failures and collisions</h2>
      </div>
      <article v-for="bundle in failedBundles" :key="bundle.id" class="incident">
        <StatusBadge label="failed" tone="err" />
        <div>
          <h3>{{ bundle.name }}</h3>
          <p class="sb-mono">{{ label(bundle.load.phase) }} / {{ bundle.load.status }}</p>
          <p v-if="bundle.load.detail">{{ bundle.load.detail }}</p>
        </div>
      </article>
      <article
        v-for="collision in snapshot.collisions"
        :key="collision.match_key"
        class="incident"
      >
        <StatusBadge label="collision" tone="warn" />
        <div>
          <h3 class="sb-mono">{{ collision.match_key }}</h3>
          <p>{{ collision.resolution }}</p>
          <p class="sb-mono">
            {{ collision.registrations.join(", ") }}
            <template v-if="collision.winner"> · winner {{ collision.winner }}</template>
          </p>
        </div>
      </article>
    </section>

    <section class="ledger" aria-labelledby="ledger-title">
      <div class="section-heading section-heading--ruled">
        <div>
          <span class="sb-eyebrow">Authoritative inventory</span>
          <h2 id="ledger-title">Bundle ledger</h2>
        </div>
        <span class="ledger__note sb-mono">sorted by stable bundle ID</span>
      </div>

      <EmptyState
        v-if="snapshot.bundles.length === 0"
        message="This binary and config report no extension bundles."
      />

      <article
        v-for="(bundle, index) in snapshot.bundles"
        v-else
        :key="bundle.id"
        class="bundle"
        :class="{ 'bundle--failed': bundle.state === 'failed' }"
      >
        <header class="bundle__header">
          <span class="bundle__index sb-mono">{{ String(index + 1).padStart(2, "0") }}</span>
          <div class="bundle__title">
            <h3>{{ bundle.name }}</h3>
            <p class="sb-mono">{{ bundle.id }} · v{{ bundle.version }}</p>
          </div>
          <StatusBadge :label="label(bundle.state)" :tone="stateTone(bundle.state)" />
        </header>

        <dl class="bundle__facts">
          <div>
            <dt>Source</dt>
            <dd>{{ sourceLabel(bundle.source) }}</dd>
          </div>
          <div>
            <dt>Runtime</dt>
            <dd>{{ label(bundle.runtime) }}</dd>
          </div>
          <div>
            <dt>Load</dt>
            <dd>
              <StatusBadge
                :label="loadLabel(bundle.load)"
                :tone="loadTone(bundle.load)"
              />
              <small>{{ label(bundle.load.phase) }}</small>
            </dd>
          </div>
          <div>
            <dt>Artifact</dt>
            <dd class="sb-mono">{{ bundle.package ?? "linked" }}</dd>
          </div>
        </dl>

        <p v-if="bundle.load.detail" class="bundle__detail" role="status">
          {{ bundle.load.detail }}
        </p>

        <section class="hooks" :aria-label="`Hooks from ${bundle.name}`">
          <div class="hooks__heading">
            <span class="sb-eyebrow">Hooks</span>
            <span class="sb-mono">{{ bundleHooks(bundle).length }}</span>
          </div>
          <p v-if="bundleHooks(bundle).length === 0" class="hooks__empty">
            No hooks were attributed to this bundle.
          </p>
          <article
            v-for="hook in bundleHooks(bundle)"
            :key="hook.id"
            class="hook"
          >
            <header class="hook__header">
              <div>
                <span class="hook__kind sb-mono">{{ label(hook.kind) }}</span>
                <h4 class="sb-mono">{{ hook.match_key }}</h4>
              </div>
              <StatusBadge :label="label(hook.state)" :tone="stateTone(hook.state)" />
            </header>
            <dl class="hook__facts">
              <div>
                <dt>Dispatch</dt>
                <dd>{{ label(hook.dispatch) }}</dd>
              </div>
              <div>
                <dt>Position</dt>
                <dd>{{ hookPosition(hook) }}</dd>
              </div>
              <div>
                <dt>Phase</dt>
                <dd>{{ label(hook.execution.phase) }}</dd>
              </div>
              <div>
                <dt>Body</dt>
                <dd>{{ label(hook.execution.body_mode) }}</dd>
              </div>
              <div>
                <dt>Timeout</dt>
                <dd>{{ timeoutLabel(hook.execution.timeout_ms) }}</dd>
              </div>
              <div>
                <dt>Buffer</dt>
                <dd>{{ bufferLabel(hook.execution.max_buffer_bytes) }}</dd>
              </div>
            </dl>
            <div class="hook__footer">
              <code :title="hook.id">{{ hook.id }}</code>
              <ul v-if="hook.capabilities.length" class="capabilities" aria-label="Capabilities">
                <li v-for="capability in hook.capabilities" :key="capability">
                  {{ capability }}
                </li>
              </ul>
              <span v-else class="hook__none">no host capabilities</span>
            </div>
            <p v-if="hook.detail" class="hook__detail">{{ hook.detail }}</p>
          </article>
        </section>
      </article>
    </section>
  </template>
</template>

<style scoped>
.refresh-warning {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--sb-space-4);
  padding: var(--sb-space-3) var(--sb-space-4);
  margin-bottom: var(--sb-space-4);
  color: var(--sb-warn-fg);
  background: var(--sb-warn-bg);
  border: 1px solid var(--sb-warn);
}

.refresh-warning div {
  display: flex;
  flex-wrap: wrap;
  gap: var(--sb-space-2);
}

.generation {
  display: grid;
  grid-template-columns: minmax(0, 1.35fr) minmax(360px, 1fr);
  gap: var(--sb-space-6);
  padding: var(--sb-space-5);
  color: var(--sb-on-ink);
  background: var(--sb-ink);
}

.generation__eyebrow {
  display: block;
  margin-bottom: var(--sb-space-2);
  color: var(--sb-code-key);
  font-size: 0.68rem;
  text-transform: uppercase;
  letter-spacing: 0.12em;
}

.generation h2 {
  margin-bottom: var(--sb-space-2);
  font-size: 1.35rem;
}

.generation code {
  display: block;
  color: var(--sb-code-str);
  font-size: 0.8rem;
  overflow-wrap: anywhere;
}

.generation__meta,
.bundle__facts,
.hook__facts {
  margin: 0;
}

.generation__meta {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  align-items: end;
}

.generation__meta div {
  padding-left: var(--sb-space-4);
  border-left: 1px solid rgba(246, 244, 238, 0.25);
}

dt {
  font-family: var(--sb-font-mono);
  font-size: 0.63rem;
  color: var(--sb-text-faint);
  text-transform: uppercase;
  letter-spacing: 0.1em;
}

dd {
  margin: 3px 0 0;
  font-size: 0.82rem;
}

.generation dt {
  color: var(--sb-code-com);
}

.generation dd {
  color: var(--sb-code-fg);
}

.summary {
  display: grid;
  grid-template-columns: repeat(6, minmax(0, 1fr));
  border: 1px solid var(--sb-border-ink);
  border-top: 0;
  margin-bottom: var(--sb-space-6);
}

.summary > div {
  display: flex;
  align-items: baseline;
  gap: var(--sb-space-2);
  padding: 10px var(--sb-space-3);
  border-right: 1px solid var(--sb-border-strong);
}

.summary > div:last-child {
  border-right: 0;
}

.summary__value {
  font-size: 1.15rem;
  font-weight: 600;
}

.summary__value--ok {
  color: var(--sb-ok);
}

.summary__value--info {
  color: var(--sb-info);
}

.summary__value--warn {
  color: var(--sb-warn);
}

.summary__value--err {
  color: var(--sb-err);
}

.summary__label {
  color: var(--sb-text-faint);
  font-size: 0.66rem;
  text-transform: uppercase;
  letter-spacing: 0.08em;
}

.incidents {
  margin-bottom: var(--sb-space-6);
}

.section-heading {
  margin-bottom: var(--sb-space-3);
}

.section-heading h2 {
  margin-top: 3px;
}

.section-heading--ruled {
  display: flex;
  align-items: end;
  justify-content: space-between;
  gap: var(--sb-space-4);
  padding-bottom: var(--sb-space-3);
  border-bottom: 1px solid var(--sb-border-ink);
}

.incident {
  display: grid;
  grid-template-columns: 90px minmax(0, 1fr);
  gap: var(--sb-space-3);
  padding: var(--sb-space-4);
  border: 1px solid var(--sb-err);
  border-bottom: 0;
  background: var(--sb-err-bg);
}

.incident:last-child {
  border-bottom: 1px solid var(--sb-err);
}

.incident h3,
.incident p {
  margin: 0;
}

.incident p {
  color: var(--sb-text-muted);
  font-size: 0.8rem;
}

.ledger__note {
  color: var(--sb-text-faint);
  font-size: 0.68rem;
}

.bundle {
  margin-bottom: var(--sb-space-4);
  border: 1px solid var(--sb-border-strong);
  background: var(--sb-surface);
}

.bundle--failed {
  border-left: 3px solid var(--sb-err);
}

.bundle__header {
  display: grid;
  grid-template-columns: 42px minmax(0, 1fr) auto;
  align-items: start;
  gap: var(--sb-space-3);
  padding: var(--sb-space-4);
  border-bottom: 1px solid var(--sb-border);
}

.bundle__index {
  color: var(--sb-text-faint);
  font-size: 0.72rem;
}

.bundle__title h3,
.bundle__title p {
  margin: 0;
}

.bundle__title p {
  margin-top: 2px;
  color: var(--sb-text-faint);
  font-size: 0.72rem;
  overflow-wrap: anywhere;
}

.bundle__facts {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  padding: var(--sb-space-3) var(--sb-space-4);
  border-bottom: 1px solid var(--sb-border);
}

.bundle__facts > div {
  min-width: 0;
  padding-right: var(--sb-space-4);
}

.bundle__facts dd {
  display: flex;
  flex-wrap: wrap;
  align-items: baseline;
  gap: var(--sb-space-2);
  overflow-wrap: anywhere;
}

.bundle__facts small {
  color: var(--sb-text-faint);
  font-family: var(--sb-font-mono);
  font-size: 0.62rem;
}

.bundle__detail,
.hook__detail {
  margin: 0;
  padding: var(--sb-space-3) var(--sb-space-4);
  color: var(--sb-err);
  background: var(--sb-err-bg);
  font-size: 0.78rem;
  overflow-wrap: anywhere;
}

.hooks {
  padding: var(--sb-space-4);
  background: var(--sb-surface-2);
}

.hooks__heading {
  display: flex;
  justify-content: space-between;
  padding-bottom: var(--sb-space-2);
}

.hooks__heading > span:last-child {
  color: var(--sb-text-faint);
  font-size: 0.68rem;
}

.hooks__empty {
  margin: 0;
  color: var(--sb-text-muted);
  font-size: 0.8rem;
}

.hook {
  display: grid;
  grid-template-columns: minmax(170px, 0.8fr) minmax(0, 2fr);
  border-top: 1px solid var(--sb-border-strong);
  padding: var(--sb-space-3) 0;
}

.hook:last-child {
  padding-bottom: 0;
}

.hook__header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: var(--sb-space-3);
  padding-right: var(--sb-space-4);
}

.hook__kind {
  color: var(--sb-text-faint);
  font-size: 0.64rem;
  text-transform: uppercase;
  letter-spacing: 0.08em;
}

.hook h4 {
  margin-top: 3px;
  font-size: 0.8rem;
  overflow-wrap: anywhere;
}

.hook__facts {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: var(--sb-space-3);
}

.hook__footer {
  grid-column: 2;
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: var(--sb-space-4);
  margin-top: var(--sb-space-3);
  padding-top: var(--sb-space-3);
  border-top: 1px solid var(--sb-border);
}

.hook__footer > code {
  color: var(--sb-text-faint);
  font-size: 0.66rem;
  overflow-wrap: anywhere;
}

.capabilities {
  display: flex;
  flex-wrap: wrap;
  justify-content: flex-end;
  gap: var(--sb-space-1);
  list-style: none;
  margin: 0;
  padding: 0;
}

.capabilities li {
  padding: 2px 5px;
  border: 1px solid var(--sb-border-strong);
  background: var(--sb-surface);
  color: var(--sb-text-muted);
  font-family: var(--sb-font-mono);
  font-size: 0.6rem;
}

.hook__none {
  color: var(--sb-text-faint);
  font-size: 0.68rem;
}

.hook__detail {
  grid-column: 2;
  margin-top: var(--sb-space-3);
}

@media (max-width: 900px) {
  .generation {
    grid-template-columns: 1fr;
  }

  .summary {
    grid-template-columns: repeat(3, 1fr);
  }

  .summary > div:nth-child(3) {
    border-right: 0;
  }

  .summary > div:nth-child(-n + 3) {
    border-bottom: 1px solid var(--sb-border-strong);
  }

  .bundle__facts {
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: var(--sb-space-3);
  }

  .hook {
    grid-template-columns: 1fr;
  }

  .hook__header {
    margin-bottom: var(--sb-space-3);
    padding-right: 0;
  }

  .hook__footer,
  .hook__detail {
    grid-column: 1;
  }
}

@media (max-width: 620px) {
  .generation__meta,
  .hook__facts {
    grid-template-columns: 1fr;
    gap: var(--sb-space-3);
  }

  .generation__meta div {
    padding-left: 0;
    border-left: 0;
  }

  .summary {
    grid-template-columns: repeat(2, 1fr);
  }

  .summary > div:nth-child(odd) {
    border-right: 1px solid var(--sb-border-strong);
  }

  .summary > div:nth-child(even) {
    border-right: 0;
  }

  .summary > div:nth-child(-n + 4) {
    border-bottom: 1px solid var(--sb-border-strong);
  }

  .incident {
    grid-template-columns: 1fr;
  }

  .bundle__header {
    grid-template-columns: 32px minmax(0, 1fr);
  }

  .bundle__header > :last-child {
    grid-column: 2;
  }

  .bundle__facts {
    grid-template-columns: 1fr;
  }

  .hook__facts {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .hook__footer {
    flex-direction: column;
  }

  .capabilities {
    justify-content: flex-start;
  }
}
</style>
