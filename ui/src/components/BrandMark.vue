<script setup lang="ts">
// The SBproxy cube mark, same paths as the sbproxy.dev site header.
// Navy is the brand tier (see tokens.css), so the mark reads navy on
// the light chrome.
withDefaults(defineProps<{ size?: number }>(), { size: 28 });
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
    <div class="brand__text">
      <span class="brand__name"><strong>SB</strong>proxy</span>
      <span class="brand__role">Admin</span>
    </div>
  </div>
</template>

<style scoped>
.brand {
  display: flex;
  align-items: center;
  gap: 10px;
}
.brand__mark {
  flex: none;
  color: var(--sb-navy);
}
.brand__text {
  display: flex;
  flex-direction: column;
  line-height: 1.15;
}
.brand__name {
  font-weight: 600;
  letter-spacing: -0.01em;
}
.brand__name strong {
  font-weight: 700;
}
.brand__role {
  font-size: 0.72rem;
  letter-spacing: 0.14em;
  text-transform: uppercase;
  color: var(--sb-text-faint);
}
</style>
