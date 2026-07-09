<script setup lang="ts">
import { computed } from "vue";

const props = defineProps<{
  items: { key: string; value: number }[];
  unit?: string;
  /** Custom value formatter; wins over the default fmt + unit pair. */
  format?: (v: number) => string;
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
        <span class="bar__key sb-mono">{{ item.key }}</span>
        <span class="bar__val">{{
          format ? format(item.value) : fmt(item.value) + (unit || "")
        }}</span>
      </div>
      <div class="bar__track">
        <div
          class="bar__fill"
          :style="{ width: `${Math.max(2, (item.value / max) * 100)}%` }"
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
  height: 8px;
  background: var(--sb-bg-sunken);
  border-radius: var(--sb-radius-pill);
  overflow: hidden;
}
.bar__fill {
  height: 100%;
  background: linear-gradient(
    90deg,
    var(--sb-navy-soft),
    var(--sb-accent)
  );
  border-radius: var(--sb-radius-pill);
}
</style>
