<script setup lang="ts">
import { computed } from "vue";
import { useRoute } from "vue-router";

const route = useRoute();

const href = computed(() => {
  const slug = route.meta.documentation;
  return typeof slug === "string"
    ? `https://sbproxy.dev/docs/${encodeURIComponent(slug)}`
    : null;
});

const accessibleLabel = computed(() => {
  const title = route.meta.title;
  return typeof title === "string"
    ? `Documentation for ${title} (opens in a new tab)`
    : "Documentation (opens in a new tab)";
});
</script>

<template>
  <a
    v-if="href"
    class="sb-btn sb-btn--sm documentation-link"
    :href="href"
    target="_blank"
    rel="noopener noreferrer"
    :aria-label="accessibleLabel"
  >
    Documentation <span aria-hidden="true">↗</span>
  </a>
</template>

<style scoped>
.documentation-link {
  border-color: var(--sb-border-strong);
}
</style>
