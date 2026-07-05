<script setup lang="ts">
import { ref } from "vue";

const props = defineProps<{ value: string; mono?: boolean }>();
const copied = ref(false);

async function copy() {
  try {
    await navigator.clipboard.writeText(props.value);
  } catch {
    // Fallback for environments without the async clipboard API.
    const el = document.createElement("textarea");
    el.value = props.value;
    document.body.appendChild(el);
    el.select();
    try {
      document.execCommand("copy");
    } catch {
      // ignore
    }
    document.body.removeChild(el);
  }
  copied.value = true;
  setTimeout(() => (copied.value = false), 1600);
}
</script>

<template>
  <div class="copy">
    <code class="copy__val" :class="{ 'copy__val--mono': mono }">{{ value }}</code>
    <button class="sb-btn sb-btn--sm" @click="copy">
      {{ copied ? "Copied" : "Copy" }}
    </button>
  </div>
</template>

<style scoped>
.copy {
  display: flex;
  align-items: stretch;
  gap: 8px;
}
.copy__val {
  flex: 1;
  background: var(--sb-code-bg);
  color: var(--sb-code-fg);
  border: 1px solid var(--sb-border);
  border-radius: var(--sb-radius-sm);
  padding: 8px 10px;
  font-size: 0.82rem;
  word-break: break-all;
  overflow-wrap: anywhere;
}
.copy__val--mono {
  font-family: var(--sb-font-mono);
}
</style>
