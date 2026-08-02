<script setup lang="ts">
import Sparkline from "./Sparkline.vue";
import type { SeriesPoint } from "../lib/timeseries";

defineProps<{
  label: string;
  value: string | number;
  sub?: string;
  tone?: "default" | "accent";
  /** Optional trend line rendered under the value. */
  spark?: SeriesPoint[];
  sparkColor?: string;
}>();
</script>

<template>
  <div class="stat" :class="{ 'stat--accent': tone === 'accent' }">
    <div class="stat__label sb-mono">{{ label }}</div>
    <div class="stat__value">{{ value }}</div>
    <Sparkline
      v-if="spark && spark.length >= 2"
      class="stat__spark"
      :points="spark"
      :color="sparkColor"
    />
    <div class="stat__sub" v-if="sub">{{ sub }}</div>
  </div>
</template>

<style scoped>
.stat {
  background: var(--sb-surface);
  border: 1px solid var(--sb-border-strong);
  border-top: 2px solid var(--sb-border-ink);
  padding: var(--sb-space-4) var(--sb-space-4) var(--sb-space-3);
  display: flex;
  flex-direction: column;
  gap: 4px;
  min-width: 0;
}
.stat--accent {
  border-top-color: var(--sb-accent);
}
.stat__label {
  font-size: 0.66rem;
  text-transform: uppercase;
  letter-spacing: 0.11em;
  color: var(--sb-text-faint);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.stat__value {
  font-size: 1.55rem;
  font-weight: 600;
  line-height: 1.15;
  letter-spacing: -0.02em;
  font-variant-numeric: tabular-nums;
}
.stat--accent .stat__value {
  color: var(--sb-accent-strong);
}
.stat__spark {
  margin-top: 2px;
}
.stat__sub {
  font-size: 0.76rem;
  color: var(--sb-text-muted);
}
</style>
