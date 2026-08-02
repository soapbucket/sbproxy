<script setup lang="ts">
import { computed } from "vue";

const props = defineProps<{
  items: { key: string; value: number; color?: string }[];
  unit?: string;
  /** Custom value formatter; wins over the default fmt + unit pair. */
  format?: (v: number) => string;
  /** Fill for bars without their own color. Defaults to series 1. */
  color?: string;
  /**
   * Turn each label into a link to the requests behind it. Given the bar's
   * key, return a router path. Omit for a plain, unlinked chart: a label
   * that looks clickable and is not is worse than no link at all.
   */
  linkFor?: (key: string) => string;
}>();

const max = computed(() =>
  props.items.reduce((m, i) => Math.max(m, i.value), 0) || 1,
);

function fmt(v: number): string {
  return v.toLocaleString(undefined, { maximumFractionDigits: 2 });
}
</script>

<template>
  <div class="bars">
    <div class="bar" v-for="item in items" :key="item.key">
      <div class="bar__head">
        <RouterLink
          v-if="linkFor"
          class="bar__key bar__key--link sb-mono"
          :to="linkFor(item.key)"
          :title="`Show requests for ${item.key}`"
        >
          {{ item.key }}
        </RouterLink>
        <span v-else class="bar__key sb-mono">{{ item.key }}</span>
        <span class="bar__val">{{
          format ? format(item.value) : fmt(item.value) + (unit || "")
        }}</span>
      </div>
      <div class="bar__track">
        <div
          class="bar__fill"
          :style="{
            width: `${Math.max(1.5, (item.value / max) * 100)}%`,
            background: item.color ?? color ?? 'var(--sb-chart-1)',
          }"
        />
      </div>
    </div>
  </div>
</template>

<style scoped>
.bars {
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.bar__head {
  display: flex;
  justify-content: space-between;
  font-size: 0.8rem;
  margin-bottom: 4px;
}
.bar__key {
  color: var(--sb-text-muted);
  font-size: 0.74rem;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  max-width: 70%;
}
.bar__val {
  font-variant-numeric: tabular-nums;
  color: var(--sb-text);
}
.bar__track {
  height: 6px;
  background: var(--sb-bg-sunken);
}
.bar__fill {
  height: 100%;
}
.bar__key--link {
  color: inherit;
  text-decoration: underline;
  text-decoration-style: dotted;
  text-underline-offset: 2px;
}
.bar__key--link:hover {
  text-decoration-style: solid;
}
</style>
