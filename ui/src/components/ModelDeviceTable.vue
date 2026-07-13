<script setup lang="ts">
import type { DeviceVram } from "../api";
import { formatBytes } from "../lib/format";

defineProps<{ devices: readonly DeviceVram[] }>();

function deviceRowKey(device: DeviceVram, rowIndex: number): string {
  return `${device.index ?? "no-index"}:${device.name ?? "unknown"}:${rowIndex}`;
}
</script>

<template>
  <section class="sb-card device-panel" aria-labelledby="devices-heading">
    <div class="section-heading">
      <div>
        <p class="sb-eyebrow">Local capacity</p>
        <h2 id="devices-heading">Observed devices</h2>
      </div>
    </div>
    <div class="table-wrap" role="region" aria-label="Observed model devices" tabindex="0">
      <table class="sb-table">
        <thead><tr><th>Index</th><th>Device</th><th>Total</th><th>Free</th></tr></thead>
        <tbody>
          <tr v-for="(device, rowIndex) in devices" :key="deviceRowKey(device, rowIndex)">
            <td class="sb-mono">{{ device.index ?? "n/a" }}</td>
            <td>{{ device.name ?? "Unknown device" }}</td>
            <td>{{ formatBytes(device.total_bytes) }}</td>
            <td>{{ formatBytes(device.free_bytes) }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </section>
</template>

<style scoped>
.device-panel {
  margin-bottom: var(--sb-space-6);
}

.section-heading {
  margin-bottom: var(--sb-space-4);
}

.section-heading .sb-eyebrow {
  margin: 0 0 var(--sb-space-1);
}

.table-wrap {
  overflow-x: auto;
}

.table-wrap:focus-visible {
  outline: 3px solid var(--sb-accent-ring);
  outline-offset: 2px;
}
</style>
