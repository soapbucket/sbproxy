<script setup lang="ts">
import { computed } from "vue";

const props = defineProps<{
  label?: string;
  tone?: "ok" | "warn" | "err" | "info" | "neutral";
}>();

// Infer a tone from common status words when one is not given.
const resolvedTone = computed(() => {
  if (props.tone) return props.tone;
  const t = (props.label || "").toLowerCase();
  if (/(ok|healthy|up|ready|active|open|in.?sync|pass|serving|resident)/.test(t))
    return "ok";
  if (/(warn|degraded|pending|rotating|drift|half)/.test(t)) return "warn";
  if (/(err|down|unhealthy|fail|revoked|blocked|closed|tripped|4\d\d|5\d\d)/.test(t))
    return "err";
  return "neutral";
});
</script>

<template>
  <span class="badge" :class="`badge--${resolvedTone}`">
    <span class="dot" />
    {{ label || "unknown" }}
  </span>
</template>

<style scoped>
.badge {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 2px 9px;
  border-radius: var(--sb-radius-pill);
  font-size: 0.74rem;
  font-weight: 600;
  line-height: 1.5;
  border: 1px solid transparent;
  white-space: nowrap;
}
.dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: currentColor;
  flex: none;
}
.badge--ok {
  color: var(--sb-ok);
  background: var(--sb-ok-bg);
}
.badge--warn {
  color: var(--sb-warn);
  background: var(--sb-warn-bg);
}
.badge--err {
  color: var(--sb-err);
  background: var(--sb-err-bg);
}
.badge--info {
  color: var(--sb-info);
  background: var(--sb-info-bg);
}
.badge--neutral {
  color: var(--sb-text-muted);
  background: var(--sb-surface-2);
  border-color: var(--sb-border);
}
</style>
