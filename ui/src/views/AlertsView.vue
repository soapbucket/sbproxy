<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from "vue";
import {
  api,
  type AlertChannel,
  type AlertHistoryEntry,
  type AlertRule,
} from "../api";
import { useAsync } from "../composables/useAsync";
import { toast } from "../composables/useToasts";
import { formatNumber, formatTime } from "../lib/format";
import PageHeader from "../components/PageHeader.vue";
import StatusBadge from "../components/StatusBadge.vue";
import ErrorState from "../components/ErrorState.vue";
import EmptyState from "../components/EmptyState.vue";

const req = useAsync(() => api.alerts());
const snapshot = computed(() => req.data.value);
onMounted(req.run);

const testingIndex = ref<number | null>(null);
let pollGeneration = 0;
onUnmounted(() => {
  pollGeneration += 1;
});

function wait(milliseconds: number): Promise<void> {
  return new Promise((resolve) => window.setTimeout(resolve, milliseconds));
}

async function testChannel(channel: AlertChannel) {
  if (!snapshot.value?.enabled || testingIndex.value !== null) return;
  const generation = ++pollGeneration;
  const previousAttempt = channel.health.last_attempt_at;
  testingIndex.value = channel.index;
  try {
    await api.testAlertChannel(channel.index);
    toast.info(`Test queued for channel ${channel.index}`);
    for (let attempt = 0; attempt < 8; attempt += 1) {
      await wait(350);
      if (generation !== pollGeneration) return;
      await req.run();
      const current = snapshot.value?.channels.find(
        (candidate) => candidate.index === channel.index,
      );
      if (
        current?.health.last_attempt_at &&
        current.health.last_attempt_at !== previousAttempt
      ) {
        toast.success(`Channel ${channel.index} test completed`);
        return;
      }
    }
    toast.warn(
      `Channel ${channel.index} test is still pending`,
      "Refresh to see the eventual delivery result.",
    );
  } catch (error) {
    toast.error(error, `Test channel ${channel.index}`);
  } finally {
    if (generation === pollGeneration) testingIndex.value = null;
  }
}

function ruleTone(
  state: AlertRule["state"],
): "ok" | "warn" | "err" | "info" | "neutral" {
  if (state === "ok") return "ok";
  if (state === "firing") return "err";
  return "neutral";
}

function deliveryTone(
  status: AlertChannel["health"]["status"],
): "ok" | "warn" | "err" | "info" | "neutral" {
  if (status === "healthy") return "ok";
  if (status === "failing") return "err";
  return "neutral";
}

function historyTone(
  entry: AlertHistoryEntry,
): "ok" | "warn" | "err" | "info" | "neutral" {
  if (entry.event === "resolved") return "ok";
  if (entry.event === "test") return "info";
  return entry.alert.severity === "critical" ? "err" : "warn";
}

function formatRate(value: number | undefined): string {
  if (value === undefined || !Number.isFinite(value)) return "n/a";
  return `${formatNumber(value * 100)}%`;
}

function formatThresholds(rule: AlertRule): string {
  return rule.thresholds.map((threshold) => formatRate(threshold)).join(" / ");
}

function channelDescriptor(channel: AlertChannel): string {
  if (channel.target) return channel.target;
  if (channel.type === "pagerduty") {
    return channel.routing_key_configured
      ? "routing key configured"
      : "routing key missing";
  }
  if (channel.type === "log") return "sbproxy process log";
  return "target unavailable";
}

const newestHistory = computed(() => [...(snapshot.value?.history ?? [])].reverse());
</script>

<template>
  <PageHeader
    title="Alerts"
    subtitle="Read-only rule evaluation, channel delivery health, and bounded process-lifetime history."
  >
    <template #actions>
      <button class="sb-btn sb-btn--primary" @click="req.run">Refresh</button>
    </template>
  </PageHeader>

  <p
    v-if="req.loading.value && !snapshot"
    class="loading-state sb-mono sb-faint"
    role="status"
    aria-live="polite"
  >
    Loading alert runtime...
  </p>
  <ErrorState v-else-if="req.error.value" :error="req.error.value" @retry="req.run" />
  <template v-else-if="snapshot">
    <aside class="authority-note">
      <div>
        <span class="authority-note__eyebrow sb-mono">configuration authority</span>
        <strong>sb.yml is authoritative</strong>
      </div>
      <p>
        Rules and channels are read-only here. Update the alerting block in sb.yml and
        reload the proxy to change configuration. Channel tests exercise delivery only.
      </p>
      <StatusBadge label="read only" tone="neutral" />
    </aside>

    <EmptyState
      v-if="!snapshot.enabled"
      message="Alerting is not enabled in the running configuration. Add an alerting block to sb.yml to install the runtime."
    />
    <template v-else>
      <section class="alert-section">
        <div class="section-heading">
          <div>
            <span class="section-number sb-mono">01</span>
            <h2>Rules</h2>
          </div>
          <span class="sb-faint">latest evaluation</span>
        </div>
        <EmptyState
          v-if="!snapshot.rules.length"
          message="No built-in rules are active."
        />
        <div v-else class="table-wrap">
          <table class="sb-table">
            <thead>
              <tr>
                <th>Rule</th>
                <th>Thresholds</th>
                <th>Reading</th>
                <th>Samples</th>
                <th>State</th>
                <th>Last evaluation</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="rule in snapshot.rules" :key="rule.rule">
                <td>
                  <strong class="sb-mono">{{ rule.rule }}</strong>
                  <span class="rule-description">{{ rule.description }}</span>
                </td>
                <td class="sb-mono">{{ formatThresholds(rule) }}</td>
                <td class="sb-mono">{{ formatRate(rule.reading) }}</td>
                <td>
                  <span v-if="rule.minimum_samples">
                    {{ formatNumber(rule.sample_count ?? 0) }} /
                    {{ formatNumber(rule.minimum_samples) }} min
                  </span>
                  <span v-else class="sb-faint">not gated</span>
                </td>
                <td><StatusBadge :label="rule.state" :tone="ruleTone(rule.state)" /></td>
                <td class="nowrap">{{ formatTime(rule.last_evaluated_at) }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section class="alert-section">
        <div class="section-heading">
          <div>
            <span class="section-number sb-mono">02</span>
            <h2>Channels</h2>
          </div>
          <span class="sb-faint">sanitized targets and latest delivery</span>
        </div>
        <EmptyState
          v-if="!snapshot.channels.length"
          message="No alert channels are configured, so targeted tests are unavailable."
        />
        <div v-else class="channel-grid">
          <article
            v-for="channel in snapshot.channels"
            :key="channel.index"
            class="channel-card"
          >
            <header>
              <span class="channel-index sb-mono">{{ channel.index }}</span>
              <div>
                <strong>{{ channel.type }}</strong>
                <span class="channel-target sb-mono">{{ channelDescriptor(channel) }}</span>
              </div>
              <StatusBadge
                :label="channel.health.status"
                :tone="deliveryTone(channel.health.status)"
              />
            </header>
            <dl>
              <div>
                <dt>Last attempt</dt>
                <dd>{{ formatTime(channel.health.last_attempt_at) }}</dd>
              </div>
              <div v-if="channel.health.error">
                <dt>Latest error</dt>
                <dd class="channel-error sb-mono">{{ channel.health.error }}</dd>
              </div>
            </dl>
            <button
              class="sb-btn sb-btn--sm"
              :disabled="testingIndex !== null"
              :aria-label="`Test ${channel.type} channel ${channel.index}`"
              @click="testChannel(channel)"
            >
              {{ testingIndex === channel.index ? "Testing..." : "Test channel" }}
            </button>
          </article>
        </div>
      </section>

      <section class="alert-section">
        <div class="section-heading">
          <div>
            <span class="section-number sb-mono">03</span>
            <h2>History</h2>
          </div>
          <span class="sb-faint">newest first, up to 200 process-lifetime events</span>
        </div>
        <EmptyState
          v-if="!newestHistory.length"
          message="No alerts have fired, resolved, or been tested since process start."
        />
        <ol v-else class="history-list">
          <li
            v-for="(entry, index) in newestHistory"
            :key="`${entry.alert.timestamp}-${entry.event}-${index}`"
          >
            <span class="history-rail" aria-hidden="true" />
            <article>
              <header>
                <StatusBadge :label="entry.event" :tone="historyTone(entry)" />
                <StatusBadge
                  :label="entry.alert.severity"
                  :tone="entry.alert.severity === 'critical' ? 'err' : 'warn'"
                />
                <strong class="sb-mono">{{ entry.alert.rule }}</strong>
                <time>{{ formatTime(entry.alert.timestamp) }}</time>
              </header>
              <p>{{ entry.alert.message }}</p>
              <span v-if="entry.channel_index !== undefined" class="sb-mono sb-faint">
                channel {{ entry.channel_index }}
              </span>
            </article>
          </li>
        </ol>
      </section>
    </template>
  </template>
</template>

<style scoped>
.authority-note {
  display: grid;
  grid-template-columns: minmax(180px, 0.7fr) minmax(260px, 1.5fr) auto;
  gap: var(--sb-space-4);
  align-items: center;
  margin-bottom: var(--sb-space-6);
  padding: var(--sb-space-4);
  border: 1px solid var(--sb-border-ink);
  background: var(--sb-surface);
}
.loading-state {
  padding: var(--sb-space-5) 0;
  font-size: 0.78rem;
}
.authority-note__eyebrow {
  display: block;
  margin-bottom: 4px;
  color: var(--sb-accent-strong);
  font-size: 0.64rem;
  text-transform: uppercase;
  letter-spacing: 0.1em;
}
.authority-note p {
  margin: 0;
  color: var(--sb-text-muted);
  font-size: 0.84rem;
}
.alert-section {
  margin-top: var(--sb-space-6);
}
.section-heading {
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  gap: var(--sb-space-4);
  margin-bottom: var(--sb-space-3);
  padding-bottom: var(--sb-space-3);
  border-bottom: 1px solid var(--sb-border-ink);
}
.section-heading > div {
  display: flex;
  align-items: baseline;
  gap: var(--sb-space-3);
}
.section-heading h2 {
  margin: 0;
}
.section-heading > span {
  font-size: 0.74rem;
}
.section-number {
  color: var(--sb-accent);
  font-size: 0.68rem;
}
.table-wrap {
  border: 1px solid var(--sb-border);
  overflow-x: auto;
}
.rule-description,
.channel-target {
  display: block;
  margin-top: 4px;
  color: var(--sb-text-muted);
  font-size: 0.74rem;
}
.nowrap {
  white-space: nowrap;
}
.channel-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: var(--sb-space-3);
}
.channel-card {
  display: flex;
  flex-direction: column;
  gap: var(--sb-space-4);
  min-width: 0;
  padding: var(--sb-space-4);
  border: 1px solid var(--sb-border);
  background: var(--sb-surface);
}
.channel-card header {
  display: grid;
  grid-template-columns: 30px minmax(0, 1fr) auto;
  gap: var(--sb-space-3);
  align-items: start;
}
.channel-index {
  display: grid;
  width: 28px;
  height: 28px;
  place-items: center;
  border: 1px solid var(--sb-accent);
  color: var(--sb-accent-strong);
  font-size: 0.68rem;
}
.channel-target {
  overflow-wrap: anywhere;
}
.channel-card dl {
  display: grid;
  gap: var(--sb-space-3);
  margin: 0;
}
.channel-card dt {
  color: var(--sb-text-faint);
  font-family: var(--sb-font-mono);
  font-size: 0.64rem;
  text-transform: uppercase;
  letter-spacing: 0.08em;
}
.channel-card dd {
  margin: 3px 0 0;
  font-size: 0.8rem;
}
.channel-error {
  color: var(--sb-err);
  overflow-wrap: anywhere;
}
.channel-card .sb-btn {
  align-self: flex-start;
  margin-top: auto;
}
.history-list {
  margin: 0;
  padding: 0;
  list-style: none;
}
.history-list li {
  display: grid;
  grid-template-columns: 22px minmax(0, 1fr);
  position: relative;
}
.history-list li:not(:last-child)::before {
  content: "";
  position: absolute;
  left: 4px;
  top: 13px;
  bottom: -1px;
  width: 1px;
  background: var(--sb-border-accent);
}
.history-rail {
  position: relative;
  z-index: 1;
  width: 9px;
  height: 9px;
  margin-top: 6px;
  border: 2px solid var(--sb-accent);
  background: var(--sb-bg);
}
.history-list article {
  padding-bottom: var(--sb-space-4);
}
.history-list header {
  display: flex;
  align-items: baseline;
  flex-wrap: wrap;
  gap: var(--sb-space-3);
}
.history-list time {
  margin-left: auto;
  color: var(--sb-text-faint);
  font-size: 0.76rem;
}
.history-list p {
  margin: 5px 0 0;
  color: var(--sb-text-muted);
}
@media (max-width: 720px) {
  .authority-note {
    grid-template-columns: 1fr;
  }
  .section-heading {
    align-items: flex-start;
    flex-direction: column;
  }
  .history-list time {
    width: 100%;
    margin-left: 0;
  }
}
</style>
