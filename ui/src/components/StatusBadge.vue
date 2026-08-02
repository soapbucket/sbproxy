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
  <span class="badge sb-mono" :class="`badge--${resolvedTone}`">
    {{ label || "unknown" }}
  </span>
</template>

<style scoped>
/* Status reads as a colored word, the site's instrument-panel idiom:
   no pill, no dot, just ink that changes color. */
.badge {
  font-size: 0.76rem;
  font-weight: 600;
  letter-spacing: 0.01em;
  text-transform: lowercase;
  white-space: nowrap;
}
.badge--ok {
  color: var(--sb-ok);
}
.badge--warn {
  color: var(--sb-warn);
}
.badge--err {
  color: var(--sb-err);
}
.badge--info {
  color: var(--sb-info);
}
.badge--neutral {
  color: var(--sb-text-muted);
}
</style>
