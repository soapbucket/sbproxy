<script setup lang="ts">
/*
 * The banner a page shows when the signed-in role cannot change anything
 * on it (WOR-2576).
 *
 * Renders nothing for a role that can mutate, so a page drops it in
 * unconditionally and it costs an admin operator no vertical space.
 *
 * This is a notice, not a control. The refusal happens twice before a
 * request would reach anything: `assertCapability` in `../api` will not
 * send the call, and `crates/sbproxy-core/src/admin.rs:8043` refuses
 * every state-changing method from a `read_only` operator regardless.
 * What the banner buys is that an operator learns it at the top of the
 * page rather than from the first button they press.
 */
import { useCapabilities } from "../composables/useCapabilities";

defineProps<{
  /** What the page's controls would have done, for the sentence. */
  action?: string;
}>();

const { canMutate, whyNot } = useCapabilities();
</script>

<template>
  <div v-if="!canMutate" class="ro-notice" role="status">
    <span class="ro-notice__tag sb-mono">read only</span>
    <p>
      {{ whyNot("mutate") }}
      <template v-if="action"> {{ action }} is disabled on this page.</template>
    </p>
  </div>
</template>

<style scoped>
.ro-notice {
  display: flex;
  align-items: flex-start;
  gap: var(--sb-space-3);
  border: 1px solid var(--sb-border-strong);
  border-left: 3px solid var(--sb-warn, var(--sb-border-strong));
  border-radius: var(--sb-radius);
  padding: var(--sb-space-3) var(--sb-space-4);
  margin-bottom: var(--sb-space-4);
}
.ro-notice__tag {
  flex: none;
  text-transform: uppercase;
  font-size: 0.75rem;
  letter-spacing: 0.06em;
  color: var(--sb-text-muted);
}
.ro-notice p {
  margin: 0;
  color: var(--sb-text-muted);
}
</style>
