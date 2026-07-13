<script setup lang="ts">
import { computed } from "vue";
import type { CatalogEntry, CatalogVariant, EngineKind } from "../api";
import { formatBytes } from "../lib/format";

const props = defineProps<{
  model: string;
  entry: CatalogEntry | null;
  variants: readonly CatalogVariant[];
  automaticSelection: boolean;
  requiresLicenseAcknowledgement: boolean;
  licenseAcknowledged: boolean;
  licenseError?: string;
}>();

const emit = defineEmits<{
  (event: "update:licenseAcknowledged", value: boolean): void;
}>();

const hasPreviewEvidence = computed(() =>
  props.variants.some((variant) => variant.stability === "preview"),
);

function engineLabel(engine: EngineKind): string {
  if (engine === "llama_cpp") return "llama.cpp";
  if (engine === "vllm") return "vLLM";
  return "Embedded";
}

function stabilityLabel(stability: CatalogVariant["stability"]): string {
  if (stability === "config_only") return "Config only";
  return stability.charAt(0).toUpperCase() + stability.slice(1);
}

function updateAcknowledgement(event: Event) {
  emit(
    "update:licenseAcknowledged",
    (event.target as HTMLInputElement).checked,
  );
}
</script>

<template>
  <aside class="evidence-column" aria-label="Selected catalog evidence">
    <div class="evidence-sticky">
      <div class="evidence-heading">
        <p class="sb-eyebrow">Catalog evidence</p>
        <span v-if="hasPreviewEvidence" class="stability stability--preview">Preview</span>
        <span v-else class="stability stability--stable">Stable</span>
      </div>
      <h3 class="sb-mono">{{ model || "Choose a model" }}</h3>

      <dl v-if="entry" class="model-facts">
        <div><dt>Family</dt><dd>{{ entry.family }}</dd></div>
        <div><dt>Parameters</dt><dd>{{ entry.params }}</dd></div>
        <div><dt>License</dt><dd>{{ entry.license }}</dd></div>
        <div><dt>Context</dt><dd>{{ entry.context_length.toLocaleString() }} tokens</dd></div>
      </dl>

      <p v-if="automaticSelection" class="selection-note">
        Automatic selection can use any executable variant below. Worker fit and engine availability decide the exact artifact.
      </p>

      <div class="variant-list">
        <article v-for="variant in variants" :key="variant.id" class="variant-card">
          <div class="variant-card__head">
            <strong class="sb-mono">{{ variant.id }}</strong>
            <span class="stability" :class="`stability--${variant.stability}`">
              {{ stabilityLabel(variant.stability) }}
            </span>
          </div>
          <p>{{ variant.quant }} · {{ variant.format.toUpperCase() }}</p>
          <dl>
            <div><dt>Min memory</dt><dd>{{ formatBytes(variant.min_memory_bytes) }}</dd></div>
            <div><dt>Download</dt><dd>{{ formatBytes(variant.download_size_bytes) }}</dd></div>
            <div><dt>Engines</dt><dd>{{ variant.engines.map(engineLabel).join(", ") }}</dd></div>
            <div><dt>Accelerators</dt><dd>{{ variant.accelerators.join(", ") }}</dd></div>
            <div>
              <dt>Certification</dt><dd class="sb-mono break-value">{{ variant.certification }}</dd>
            </div>
          </dl>
        </article>
      </div>

      <label v-if="requiresLicenseAcknowledgement" class="license-check">
        <input
          type="checkbox"
          :checked="licenseAcknowledged"
          @change="updateAcknowledgement"
        />
        <span>
          I acknowledge that deploying this model is subject to the
          <strong>{{ entry?.license || "selected model" }}</strong> license.
        </span>
      </label>
      <p v-if="licenseError" class="field-error license-error">{{ licenseError }}</p>
    </div>
  </aside>
</template>

<style scoped>
.evidence-column {
  min-width: 0;
  padding-left: var(--sb-space-5);
  border-left: 1px solid var(--sb-border-strong);
}

.evidence-sticky {
  position: sticky;
  top: var(--sb-space-4);
}

.evidence-heading,
.variant-card__head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--sb-space-2);
}

.evidence-heading .sb-eyebrow {
  margin: 0;
}

.evidence-sticky > h3 {
  margin-top: var(--sb-space-2);
  overflow-wrap: anywhere;
}

.stability {
  display: inline-flex;
  padding: 2px 7px;
  border-radius: var(--sb-radius-pill);
  font-size: 0.66rem;
  font-weight: 700;
  white-space: nowrap;
}

.stability--stable {
  color: var(--sb-ok);
  background: var(--sb-ok-bg);
}

.stability--preview,
.stability--config_only {
  color: var(--sb-warn-fg);
  background: var(--sb-warn-bg);
}

.stability--unsupported {
  color: var(--sb-err);
  background: var(--sb-err-bg);
}

.model-facts {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: var(--sb-space-3);
  padding: var(--sb-space-4) 0;
  margin: var(--sb-space-4) 0;
  border-top: 1px solid var(--sb-border);
  border-bottom: 1px solid var(--sb-border);
}

.model-facts div,
.variant-card dl div {
  min-width: 0;
}

.model-facts dt,
.variant-card dt {
  color: var(--sb-text-faint);
  font-size: 0.66rem;
  text-transform: uppercase;
  letter-spacing: 0.06em;
}

.model-facts dd,
.variant-card dd {
  margin: 2px 0 0;
  color: var(--sb-text);
  font-size: 0.76rem;
}

.selection-note {
  color: var(--sb-text-muted);
  font-size: 0.75rem;
}

.variant-list {
  display: grid;
  gap: var(--sb-space-2);
  max-height: 330px;
  overflow-y: auto;
  padding-right: 2px;
}

.variant-card {
  padding: var(--sb-space-3);
  background: var(--sb-surface-2);
  border: 1px solid var(--sb-border);
  border-radius: var(--sb-radius-sm);
}

.variant-card > p {
  margin: var(--sb-space-1) 0 var(--sb-space-2);
  color: var(--sb-text-muted);
  font-size: 0.72rem;
}

.variant-card dl {
  display: grid;
  gap: var(--sb-space-2);
  margin: 0;
}

.break-value {
  overflow-wrap: anywhere;
}

.license-check {
  display: flex;
  align-items: flex-start;
  gap: var(--sb-space-2);
  padding: var(--sb-space-3);
  margin-top: var(--sb-space-4);
  color: var(--sb-text-muted);
  background: var(--sb-accent-tint);
  border: 1px solid var(--sb-border-accent);
  border-radius: var(--sb-radius-sm);
  font-size: 0.75rem;
  cursor: pointer;
}

.license-check input {
  margin: 3px 0 0;
  accent-color: var(--sb-accent);
}

.field-error {
  color: var(--sb-err);
  font-size: 0.7rem;
  line-height: 1.4;
}

.license-error {
  margin: var(--sb-space-2) 0 0;
}

@media (max-width: 840px) {
  .evidence-column {
    grid-row: 1;
    padding: 0 0 var(--sb-space-5);
    border-left: 0;
    border-bottom: 1px solid var(--sb-border-strong);
  }

  .evidence-sticky {
    position: static;
  }

  .variant-list {
    max-height: none;
  }
}

@media (max-width: 620px) {
  .model-facts {
    grid-template-columns: 1fr;
  }
}
</style>
