<script setup lang="ts">
// The SBproxy cube mark, same paths as the sbproxy.dev site header,
// rendered in the accent green with the mono wordmark beside it.
withDefaults(defineProps<{ size?: number }>(), { size: 20 });
</script>

<template>
  <div class="brand">
    <svg
      class="brand__mark"
      :width="size"
      :height="size"
      viewBox="0 0 24 24"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      aria-label="SBproxy"
    >
      <path
        d="M12 2L3 7v10l9 5 9-5V7l-9-5z"
        stroke="currentColor"
        stroke-width="1.5"
        stroke-linejoin="round"
      />
      <path
        d="M3 7l9 5m0 0l9-5m-9 5v10"
        stroke="currentColor"
        stroke-width="1.5"
        stroke-linejoin="round"
      />
      <path
        d="M7.5 4.5L16.5 9.5"
        stroke="currentColor"
        stroke-width="1.5"
        stroke-linejoin="round"
      />
    </svg>
    <span class="brand__text sb-mono">
      <strong>sbproxy</strong>
      <span class="brand__role">admin</span>
    </span>
  </div>
</template>

<style scoped>
.brand {
  display: flex;
  align-items: center;
  gap: 9px;
}
.brand__mark {
  flex: none;
  color: var(--sb-accent);
}
.brand__text {
  font-size: 0.86rem;
  letter-spacing: 0.01em;
  display: inline-flex;
  gap: 7px;
  align-items: baseline;
  white-space: nowrap;
}
.brand__text strong {
  font-weight: 700;
  color: var(--sb-text);
}
.brand__role {
  color: var(--sb-text-faint);
}
</style>
