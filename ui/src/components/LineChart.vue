<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from "vue";
import type { SeriesPoint } from "../lib/timeseries";

export interface ChartSeries {
  name: string;
  points: SeriesPoint[];
  /** CSS color; defaults to the categorical palette by index. */
  color?: string;
}

const props = defineProps<{
  series: ChartSeries[];
  /** Y-value formatter used by the axis, tooltip, and direct labels. */
  format?: (v: number) => string;
  height?: number;
  /** Y-axis upper bound; defaults to the data maximum. */
  max?: number;
}>();

const PALETTE = [
  "var(--sb-chart-1)",
  "var(--sb-chart-2)",
  "var(--sb-chart-3)",
  "var(--sb-chart-4)",
  "var(--sb-chart-5)",
];

const PAD = { top: 10, right: 12, bottom: 22, left: 46 };

const wrap = ref<HTMLElement | null>(null);
const width = ref(600);
let observer: ResizeObserver | null = null;

onMounted(() => {
  if (!wrap.value) return;
  width.value = wrap.value.clientWidth || 600;
  observer = new ResizeObserver(() => {
    if (wrap.value) width.value = wrap.value.clientWidth || 600;
  });
  observer.observe(wrap.value);
});
onBeforeUnmount(() => observer?.disconnect());

const chartHeight = computed(() => props.height ?? 180);
const plotW = computed(() => Math.max(40, width.value - PAD.left - PAD.right));
const plotH = computed(() => chartHeight.value - PAD.top - PAD.bottom);

const drawn = computed(() =>
  props.series
    .map((s, i) => ({
      name: s.name,
      color: s.color ?? PALETTE[i % PALETTE.length],
      points: s.points,
    }))
    .filter((s) => s.points.length > 0),
);

const tExtent = computed<[number, number]>(() => {
  let lo = Infinity;
  let hi = -Infinity;
  for (const s of drawn.value) {
    for (const p of s.points) {
      if (p.t < lo) lo = p.t;
      if (p.t > hi) hi = p.t;
    }
  }
  return lo === Infinity ? [0, 1] : [lo, hi === lo ? lo + 1 : hi];
});

const vMax = computed(() => {
  if (props.max !== undefined) return props.max;
  let hi = 0;
  for (const s of drawn.value) {
    for (const p of s.points) if (p.v > hi) hi = p.v;
  }
  return hi <= 0 ? 1 : hi * 1.08;
});

function x(t: number): number {
  const [lo, hi] = tExtent.value;
  return PAD.left + ((t - lo) / (hi - lo)) * plotW.value;
}
function y(v: number): number {
  return PAD.top + plotH.value * (1 - Math.min(1, v / vMax.value));
}

function pathFor(points: SeriesPoint[]): string {
  return points
    .map((p, i) => `${i === 0 ? "M" : "L"}${x(p.t).toFixed(1)} ${y(p.v).toFixed(1)}`)
    .join(" ");
}

const fmt = computed(
  () =>
    props.format ??
    ((v: number) =>
      v.toLocaleString(undefined, { maximumFractionDigits: 2 })),
);

const yTicks = computed(() => {
  const n = 3;
  return Array.from({ length: n + 1 }, (_, i) => (vMax.value / n) * i);
});

function clock(t: number): string {
  const d = new Date(t);
  return `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}:${String(d.getSeconds()).padStart(2, "0")}`;
}

const xTicks = computed(() => {
  const [lo, hi] = tExtent.value;
  return [lo, (lo + hi) / 2, hi];
});

const hasData = computed(() =>
  drawn.value.some((s) => s.points.length >= 2),
);

/* --- Hover crosshair + tooltip --- */
const hover = ref<{ t: number; px: number } | null>(null);

function onMove(e: MouseEvent) {
  const el = wrap.value;
  if (!el || !hasData.value) return;
  const rect = el.getBoundingClientRect();
  const px = e.clientX - rect.left;
  if (px < PAD.left || px > PAD.left + plotW.value) {
    hover.value = null;
    return;
  }
  const [lo, hi] = tExtent.value;
  const t = lo + ((px - PAD.left) / plotW.value) * (hi - lo);
  // Snap to the nearest sample time of the first series.
  const pts = drawn.value[0]?.points ?? [];
  let best = pts[0];
  for (const p of pts) {
    if (Math.abs(p.t - t) < Math.abs((best?.t ?? 0) - t)) best = p;
  }
  if (best) hover.value = { t: best.t, px: x(best.t) };
}
function onLeave() {
  hover.value = null;
}

const hoverRows = computed(() => {
  if (!hover.value) return [];
  const at = hover.value.t;
  return drawn.value.flatMap((s) => {
    let best: SeriesPoint | undefined;
    for (const p of s.points) {
      if (!best || Math.abs(p.t - at) < Math.abs(best.t - at)) best = p;
    }
    return best ? [{ name: s.name, color: s.color, point: best }] : [];
  });
});

const tooltipLeft = computed(() => {
  if (!hover.value) return "0px";
  const flip = hover.value.px > width.value - 150;
  return `${hover.value.px + (flip ? -138 : 10)}px`;
});
</script>

<template>
  <div class="chart" ref="wrap" @mousemove="onMove" @mouseleave="onLeave">
    <p v-if="!hasData" class="chart__empty sb-mono">collecting samples…</p>
    <svg
      v-else
      :width="width"
      :height="chartHeight"
      role="img"
      aria-label="Time series chart"
    >
      <!-- Recessive grid -->
      <g>
        <line
          v-for="tick in yTicks"
          :key="`g${tick}`"
          :x1="PAD.left"
          :x2="PAD.left + plotW"
          :y1="y(tick)"
          :y2="y(tick)"
          class="grid"
        />
      </g>
      <!-- Y labels -->
      <text
        v-for="tick in yTicks"
        :key="`yl${tick}`"
        :x="PAD.left - 6"
        :y="y(tick) + 3"
        class="tick tick--y"
      >
        {{ fmt(tick) }}
      </text>
      <!-- X labels -->
      <text
        v-for="(tick, i) in xTicks"
        :key="`xl${i}`"
        :x="x(tick)"
        :y="chartHeight - 6"
        class="tick"
        :class="{ 'tick--start': i === 0, 'tick--end': i === xTicks.length - 1 }"
      >
        {{ clock(tick) }}
      </text>
      <!-- Series -->
      <path
        v-for="s in drawn"
        :key="s.name"
        :d="pathFor(s.points)"
        fill="none"
        :stroke="s.color"
        stroke-width="2"
        stroke-linejoin="round"
        stroke-linecap="round"
      />
      <!-- Crosshair -->
      <g v-if="hover">
        <line
          :x1="hover.px"
          :x2="hover.px"
          :y1="PAD.top"
          :y2="PAD.top + plotH"
          class="crosshair"
        />
        <circle
          v-for="row in hoverRows"
          :key="row.name"
          :cx="x(row.point.t)"
          :cy="y(row.point.v)"
          r="3.5"
          :fill="row.color"
          stroke="var(--sb-surface)"
          stroke-width="2"
        />
      </g>
    </svg>
    <div v-if="hover && hoverRows.length" class="tip" :style="{ left: tooltipLeft }">
      <div class="tip__time sb-mono">{{ clock(hover.t) }}</div>
      <div class="tip__row" v-for="row in hoverRows" :key="row.name">
        <span class="tip__swatch" :style="{ background: row.color }" />
        <span class="tip__name">{{ row.name }}</span>
        <span class="tip__val">{{ fmt(row.point.v) }}</span>
      </div>
    </div>
    <div class="legend" v-if="drawn.length >= 2">
      <span class="legend__item" v-for="s in drawn" :key="s.name">
        <span class="legend__swatch" :style="{ background: s.color }" />
        <span class="sb-mono">{{ s.name }}</span>
      </span>
    </div>
  </div>
</template>

<style scoped>
.chart {
  position: relative;
  width: 100%;
}
.chart__empty {
  margin: 0;
  padding: var(--sb-space-6) 0;
  text-align: center;
  color: var(--sb-text-faint);
  font-size: 0.78rem;
}
.grid {
  stroke: var(--sb-border);
  stroke-width: 1;
}
.crosshair {
  stroke: var(--sb-text-faint);
  stroke-width: 1;
  stroke-dasharray: 3 3;
}
.tick {
  font-family: var(--sb-font-mono);
  font-size: 10px;
  fill: var(--sb-text-faint);
  text-anchor: middle;
}
.tick--y {
  text-anchor: end;
}
.tick--start {
  text-anchor: start;
}
.tick--end {
  text-anchor: end;
}
.tip {
  position: absolute;
  top: 8px;
  background: var(--sb-surface);
  border: 1px solid var(--sb-border-ink);
  padding: 6px 8px;
  font-size: 0.74rem;
  pointer-events: none;
  min-width: 120px;
  z-index: 5;
}
.tip__time {
  color: var(--sb-text-faint);
  font-size: 0.68rem;
  margin-bottom: 3px;
}
.tip__row {
  display: flex;
  align-items: center;
  gap: 6px;
}
.tip__swatch {
  width: 8px;
  height: 8px;
  flex: none;
}
.tip__name {
  color: var(--sb-text-muted);
  flex: 1;
}
.tip__val {
  font-variant-numeric: tabular-nums;
  font-weight: 600;
}
.legend {
  display: flex;
  gap: var(--sb-space-4);
  margin-top: 6px;
  flex-wrap: wrap;
}
.legend__item {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 0.72rem;
  color: var(--sb-text-muted);
}
.legend__swatch {
  width: 10px;
  height: 10px;
}
</style>
