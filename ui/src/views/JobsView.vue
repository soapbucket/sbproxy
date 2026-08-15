<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from "vue";
import { api, type OperationJob } from "../api";
import { useAsync } from "../composables/useAsync";
import { formatBytes, formatTime, relativeTime, shortId } from "../lib/format";
import PageHeader from "../components/PageHeader.vue";
import StatusBadge from "../components/StatusBadge.vue";
import ErrorState from "../components/ErrorState.vue";
import EmptyState from "../components/EmptyState.vue";

const jobsReq = useAsync(() => api.modelHostJobs(), { pollMs: 5_000 });
onMounted(jobsReq.run);

const filter = ref("");
const jobs = computed<OperationJob[]>(() => jobsReq.data.value?.jobs ?? []);
const filteredJobs = computed(() => {
  const needle = filter.value.trim().toLowerCase();
  const rows = needle
    ? jobs.value.filter(
        (job) =>
          job.subject.toLowerCase().includes(needle) ||
          job.kind.toLowerCase().includes(needle) ||
          job.state.toLowerCase().includes(needle) ||
          job.id.toLowerCase().includes(needle),
      )
    : jobs.value;
  return [...rows].sort((a, b) => b.created_at_ms - a.created_at_ms);
});

function jobTone(state: OperationJob["state"]): "ok" | "warn" | "err" | "info" | "neutral" {
  if (state === "ready") return "ok";
  if (state === "failed") return "err";
  if (state === "deleted") return "neutral";
  return "info"; // queued, downloading, verifying, deleting
}

function isTerminal(state: OperationJob["state"]): boolean {
  return state === "ready" || state === "failed" || state === "deleted";
}

function progressPercent(job: OperationJob): number | null {
  if (job.progress.total_bytes <= 0) return null;
  return Math.min(
    100,
    Math.round((job.progress.completed_bytes / job.progress.total_bytes) * 100),
  );
}

// Detail expansion: selecting a row opens a live SSE tail of that job's
// durable state (Last-Event-ID replay is handled natively by EventSource
// on a reconnect it initiates itself). The server closes its end once
// the job reaches a terminal state; we mirror that by closing our end
// too, rather than leaving an idle connection open.
const selectedJobId = ref<string | null>(null);
const liveJob = ref<OperationJob | null>(null);
const streamState = ref<"idle" | "open" | "reconnecting">("idle");
let source: EventSource | null = null;

function stopStream() {
  source?.close();
  source = null;
  streamState.value = "idle";
}

function selectJob(job: OperationJob) {
  if (selectedJobId.value === job.id) {
    closeDetail();
    return;
  }
  stopStream();
  selectedJobId.value = job.id;
  liveJob.value = job;
  if (isTerminal(job.state)) return;
  streamState.value = "reconnecting";
  source = new EventSource(api.modelHostJobStreamUrl(job.id));
  source.onopen = () => {
    streamState.value = "open";
  };
  source.onerror = () => {
    streamState.value = "reconnecting";
  };
  source.onmessage = (event) => {
    try {
      const next = JSON.parse(event.data) as OperationJob;
      liveJob.value = next;
      if (isTerminal(next.state)) {
        stopStream();
        void jobsReq.run();
      }
    } catch {
      // Heartbeats (`: connected`) and malformed frames are not job rows.
    }
  };
}

function closeDetail() {
  selectedJobId.value = null;
  liveJob.value = null;
  stopStream();
}

onUnmounted(stopStream);
</script>

<template>
  <PageHeader
    title="Jobs"
    subtitle="Durable operation jobs: model loads and evictions, artifact pulls and verification, and other lifecycle work."
  >
    <template #actions>
      <button class="sb-btn sb-btn--sm" @click="jobsReq.run">Refresh</button>
    </template>
  </PageHeader>

  <ErrorState v-if="jobsReq.error.value" :error="jobsReq.error.value" @retry="jobsReq.run" />
  <template v-else>
    <div class="sb-card filter-card">
      <input
        v-model="filter"
        class="sb-input"
        placeholder="Filter by deployment, kind, state, or job id"
      />
    </div>

    <EmptyState
      v-if="!jobsReq.loading.value && !filteredJobs.length"
      :message="
        jobs.length
          ? 'No jobs match this filter.'
          : 'No operation jobs. Load or evict a deployment, or pull an artifact, to see one here.'
      "
    />
    <div class="sb-table-wrap" v-else>
      <table class="sb-table">
        <thead>
          <tr>
            <th>Job</th>
            <th>Kind</th>
            <th>Deployment</th>
            <th>State</th>
            <th>Progress</th>
            <th>Started</th>
            <th>Updated</th>
          </tr>
        </thead>
        <tbody>
        <template v-for="job in filteredJobs" :key="job.id">
          <tr class="job-row" @click="selectJob(job)" :class="{ 'job-row--active': selectedJobId === job.id }">
            <td class="sb-mono" :title="job.id">{{ shortId(job.id) }}</td>
            <td class="sb-mono">{{ job.kind }}</td>
            <td class="sb-mono">{{ job.subject }}</td>
            <td><StatusBadge :label="job.state" :tone="jobTone(job.state)" /></td>
            <td>
              <span v-if="progressPercent(job) !== null">{{ progressPercent(job) }}%</span>
              <span v-else class="sb-faint">n/a</span>
            </td>
            <td class="sb-muted" :title="formatTime(job.created_at_ms)">
              {{ relativeTime(job.created_at_ms) }}
            </td>
            <td class="sb-muted" :title="formatTime(job.updated_at_ms)">
              {{ relativeTime(job.updated_at_ms) }}
            </td>
          </tr>
          <tr v-if="selectedJobId === job.id" class="detail-row">
            <td colspan="7">
              <div class="detail">
                <div class="detail__head">
                  <StatusBadge
                    :label="streamState === 'open' ? 'live' : isTerminal(liveJob?.state ?? job.state) ? 'settled' : streamState"
                    :tone="streamState === 'open' ? 'ok' : 'neutral'"
                  />
                  <button class="sb-btn sb-btn--sm" @click="closeDetail">Close</button>
                </div>
                <dl class="detail-grid">
                  <dt>State</dt>
                  <dd><StatusBadge :label="(liveJob ?? job).state" :tone="jobTone((liveJob ?? job).state)" /></dd>
                  <dt>Progress</dt>
                  <dd>
                    {{ formatBytes((liveJob ?? job).progress.completed_bytes) }}
                    /
                    {{ formatBytes((liveJob ?? job).progress.total_bytes) }}
                    <span v-if="(liveJob ?? job).progress.current_file" class="sb-faint">
                      ({{ (liveJob ?? job).progress.current_file }})
                    </span>
                  </dd>
                  <dt>Created</dt>
                  <dd>{{ formatTime((liveJob ?? job).created_at_ms) }}</dd>
                  <dt>Updated</dt>
                  <dd>{{ formatTime((liveJob ?? job).updated_at_ms) }}</dd>
                  <dt v-if="(liveJob ?? job).terminal_at_ms">Terminal</dt>
                  <dd v-if="(liveJob ?? job).terminal_at_ms">
                    {{ formatTime((liveJob ?? job).terminal_at_ms) }}
                  </dd>
                  <dt v-if="(liveJob ?? job).error">Error</dt>
                  <dd v-if="(liveJob ?? job).error" class="sb-mono error-text">
                    {{ (liveJob ?? job).error }}
                  </dd>
                </dl>
              </div>
            </td>
          </tr>
        </template>
        </tbody>
      </table>
    </div>
  </template>
</template>

<style scoped>
.filter-card {
  margin-bottom: var(--sb-space-4);
}
.job-row {
  cursor: pointer;
}
.job-row:hover {
  background: var(--sb-surface-hover);
}
.job-row--active {
  background: var(--sb-surface-hover);
}
.detail-row td {
  padding: 0;
}
.detail {
  padding: var(--sb-space-4);
  border-top: 1px dashed var(--sb-border);
  background: var(--sb-surface);
}
.detail__head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: var(--sb-space-3);
}
.detail-grid {
  display: grid;
  grid-template-columns: max-content 1fr;
  gap: 6px 16px;
  font-size: 0.85rem;
  margin: 0;
}
.detail-grid dt {
  color: var(--sb-text-muted);
}
.detail-grid dd {
  margin: 0;
}
.error-text {
  color: var(--sb-err);
  word-break: break-word;
}
</style>
