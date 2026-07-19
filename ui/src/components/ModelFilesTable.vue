<script setup lang="ts">
import { formatBytes, formatTime, relativeTime } from "../lib/format";
import type { StorageArtifactRow } from "../lib/storage";
import EmptyState from "./EmptyState.vue";
import StatusBadge from "./StatusBadge.vue";

const props = defineProps<{
  rows: readonly StorageArtifactRow[];
  // Digest currently being deleted; disables every delete button so two
  // removals cannot race each other.
  deleteBusyDigest?: string;
  // Per-digest fail-closed refusal reasons, rendered inline on the row.
  refusals?: Readonly<Record<string, string>>;
}>();

defineEmits<{
  (event: "delete", row: StorageArtifactRow): void;
}>();

function lastAccessedText(row: StorageArtifactRow): string {
  if (!row.lastAccessedMs) return "Never";
  return relativeTime(row.lastAccessedMs) || "just now";
}

function lastAccessedTitle(row: StorageArtifactRow): string | undefined {
  return row.lastAccessedMs ? formatTime(row.lastAccessedMs) : undefined;
}

function refusalFor(row: StorageArtifactRow): string | null {
  return props.refusals?.[row.digest] ?? null;
}
</script>

<template>
  <div v-if="rows.length" class="sb-card table-shell">
    <div class="table-wrap" role="region" aria-label="Cached model artifacts" tabindex="0">
      <table class="sb-table files-table">
        <thead>
          <tr>
            <th>Model</th>
            <th>Variant</th>
            <th>Digest</th>
            <th>Size</th>
            <th>Last accessed</th>
            <th>Residency</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="row in rows" :key="row.digest">
            <th scope="row">
              <strong class="sb-mono model-name">{{ row.model }}</strong>
            </th>
            <td><span class="sb-mono">{{ row.variant }}</span></td>
            <td>
              <span class="sb-mono digest" :title="row.digest">{{ row.digestShort }}</span>
            </td>
            <td>{{ formatBytes(row.sizeBytes) }}</td>
            <td>
              <span :title="lastAccessedTitle(row)">{{ lastAccessedText(row) }}</span>
            </td>
            <td>
              <StatusBadge
                :label="row.resident ? 'Resident' : 'On disk'"
                :tone="row.resident ? 'ok' : 'neutral'"
              />
            </td>
            <td class="actions-cell">
              <button
                class="sb-btn sb-btn--sm sb-btn--danger"
                :aria-label="`Delete ${row.model} ${row.variant}`"
                :disabled="Boolean(deleteBusyDigest)"
                @click="$emit('delete', row)"
              >
                {{ deleteBusyDigest === row.digest ? "Deleting..." : "Delete" }}
              </button>
              <span v-if="refusalFor(row)" class="action-reason" role="alert">
                {{ refusalFor(row) }}
              </span>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
  <EmptyState v-else message="The artifact cache holds no verified model weights." />
</template>

<style scoped>
.table-shell {
  padding: 0;
  overflow: hidden;
}

.table-wrap {
  overflow-x: auto;
}

.table-wrap:focus-visible {
  outline: 3px solid var(--sb-accent-ring);
  outline-offset: -3px;
}

.files-table {
  min-width: 880px;
}

.files-table td,
.files-table tbody th {
  min-width: 0;
  overflow-wrap: anywhere;
}

.files-table tbody th {
  padding: 10px 12px;
  color: var(--sb-text);
  border-bottom: 1px solid var(--sb-border);
  font-size: inherit;
  text-transform: none;
  letter-spacing: normal;
  vertical-align: top;
  white-space: normal;
}

.files-table tbody tr:last-child th {
  border-bottom: none;
}

.model-name,
.digest {
  overflow-wrap: anywhere;
}

.actions-cell {
  min-width: 120px;
}

.action-reason {
  display: block;
  margin-top: var(--sb-space-1);
  max-width: 34ch;
  font-size: 0.72rem;
  color: var(--sb-err);
  overflow-wrap: anywhere;
}
</style>
