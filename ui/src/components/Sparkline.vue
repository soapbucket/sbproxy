<script setup lang="ts">
import { computed } from "vue";
import type { SeriesPoint } from "../lib/timeseries";

const props = defineProps<{
  points: SeriesPoint[];
  color?: string;
  width?: number;
  height?: number;
}>();

const w = computed(() => props.width ?? 96);
const h = computed(() => props.height ?? 26);

const path = computed(() => {
  const pts = props.points;
  if (pts.length < 2) return "";
  let lo = Infinity;
  let hi = -Infinity;
  for (const p of pts) {
    if (p.v < lo) lo = p.v;
    if (p.v > hi) hi = p.v;
  }
  if (hi === lo) hi = lo + 1;
  const t0 = pts[0].t;
  const t1 = pts[pts.length - 1].t || t0 + 1;
  const px = (t: number) => 1 + ((t - t0) / (t1 - t0)) * (w.value - 2);
  const py = (v: number) => 2 + (1 - (v - lo) / (hi - lo)) * (h.value - 4);
  return pts
    .map((p, i) => `${i === 0 ? "M" : "L"}${px(p.t).toFixed(1)} ${py(p.v).toFixed(1)}`)
    .join(" ");
});
</script>

<template>
  <svg
    v-if="path"
    :width="w"
    :height="h"
    class="spark"
    aria-hidden="true"
  >
    <path
      :d="path"
      fill="none"
      :stroke="color ?? 'var(--sb-chart-1)'"
      stroke-width="1.5"
      stroke-linejoin="round"
      stroke-linecap="round"
    />
  </svg>
</template>

<style scoped>
.spark {
  display: block;
}
</style>
