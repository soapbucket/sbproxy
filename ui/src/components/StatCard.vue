<script setup lang="ts">
defineProps<{
  label: string;
  value: string | number;
  sub?: string;
  tone?: "default" | "accent";
}>();
</script>

<template>
  <div class="stat" :class="{ 'stat--accent': tone === 'accent' }">
    <div class="stat__label">{{ label }}</div>
    <div class="stat__value">{{ value }}</div>
    <div class="stat__sub" v-if="sub">{{ sub }}</div>
  </div>
</template>

<style scoped>
.stat {
  background: var(--sb-surface);
  border: 1px solid var(--sb-border);
  border-radius: var(--sb-radius);
  padding: var(--sb-space-4) var(--sb-space-5);
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.stat--accent {
  border-color: var(--sb-border-accent);
  background: linear-gradient(
    180deg,
    var(--sb-accent-tint) 0%,
    var(--sb-surface) 60%
  );
}
.stat__label {
  font-size: 0.72rem;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  color: var(--sb-text-faint);
  font-weight: 600;
}
.stat__value {
  font-size: 1.55rem;
  font-weight: 600;
  line-height: 1.15;
  font-variant-numeric: tabular-nums;
}
.stat__sub {
  font-size: 0.8rem;
  color: var(--sb-text-muted);
}
</style>
