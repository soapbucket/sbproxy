<script setup lang="ts">
import { computed } from "vue";
import type { CatalogEntry, CatalogVariant, EngineKind } from "../api";
import { formatBytes } from "../lib/format";
import {
  catalogVariantDisabledReason,
  catalogVariantSupportLabel,
} from "../lib/model-management";

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

const evidenceSummary = computed(() => {
  if (!props.entry || props.variants.length === 0) {
    return { label: "Evidence unavailable", tone: "neutral" };
  }
  const runnable = props.variants.filter(
    (variant) => catalogVariantDisabledReason(variant) === null,
  );
  if (runnable.length === 0) {
    return { label: "Not runnable", tone: "unsupported" };
  }
  if (runnable.length !== props.variants.length) {
    return { label: "Mixed support", tone: "config_only" };
  }
  if (runnable.every((variant) => variant.stability === "stable")) {
    return { label: "Stable", tone: "stable" };
  }
  return { label: "Preview included", tone: "preview" };
});

function engineLabel(engine: EngineKind): string {
  if (engine === "llama_cpp") return "llama.cpp";
  if (engine === "vllm") return "vLLM";
  return "Embedded";
}

function variantSupportTone(variant: CatalogVariant): string {
  return catalogVariantSupportLabel(variant) === "Incomplete"
    ? "unsupported"
    : variant.stability;
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
        <span
          class="stability"
          :class="`stability--${evidenceSummary.tone}`"
          role="status"
          aria-live="polite"
        >
          {{ evidenceSummary.label }}
        </span>
      </div>
      <h3 class="sb-mono">{{ model || "Choose a model" }}</h3>

      <dl v-if="entry" class="model-facts">
        <div><dt>Family</dt><dd>{{ entry.family }}</dd></div>
        <div><dt>Parameters</dt><dd>{{ entry.params }}</dd></div>
        <div><dt>License</dt><dd>{{ entry.license }}</dd></div>
        <div><dt>Context</dt><dd>{{ entry.context_length.toLocaleString() }} tokens</dd></div>
      </dl>
      <p v-else class="selection-note" role="status" aria-live="polite">
        This model is no longer present in the active catalog. Choose a current model before saving.
      </p>

      <p v-if="automaticSelection" class="selection-note">
        Automatic selection can use the runnable variants below. Disabled variants remain visible as catalog evidence.
      </p>

      <div class="variant-list">
        <article
          v-for="variant in variants"
          :key="variant.id"
          class="variant-card"
          :class="{ 'variant-card--disabled': catalogVariantDisabledReason(variant) }"
        >
          <div class="variant-card__head">
            <strong class="sb-mono">{{ variant.id }}</strong>
            <span class="stability" :class="`stability--${variantSupportTone(variant)}`">
              {{ catalogVariantSupportLabel(variant) }}
            </span>
          </div>
          <p>{{ variant.quant }} · {{ variant.format.toUpperCase() }}</p>
          <p
            v-if="catalogVariantDisabledReason(variant)"
            class="variant-disabled-reason"
            role="status"
          >
            {{ catalogVariantDisabledReason(variant) }}
          </p>
          <dl>
            <div><dt>Min memory</dt><dd>{{ formatBytes(variant.min_memory_bytes) }}</dd></div>
            <div><dt>Download</dt><dd>{{ formatBytes(variant.download_size_bytes) }}</dd></div>
            <div><dt>Engines</dt><dd>{{ variant.engines.map(engineLabel).join(", ") || "None listed" }}</dd></div>
            <div><dt>Accelerators</dt><dd>{{ variant.accelerators.join(", ") || "None listed" }}</dd></div>
            <div>
              <dt>Certification</dt><dd class="sb-mono break-value">{{ variant.certification }}</dd>
            </div>
          </dl>
        </article>
      </div>

      <label v-if="requiresLicenseAcknowledgement" class="license-check">
        <input
          id="license-acknowledgement"
          type="checkbox"
          :checked="licenseAcknowledged"
          :aria-invalid="Boolean(licenseError)"
          aria-describedby="license-acknowledgement-description license-acknowledgement-error"
          @change="updateAcknowledgement"
        />
        <span id="license-acknowledgement-description">
          I acknowledge that deploying this model is subject to the
          <strong>{{ entry?.license || "selected model" }}</strong> license.
        </span>
      </label>
      <p
        id="license-acknowledgement-error"
        v-show="licenseError"
        class="field-error license-error"
        role="alert"
      >
        {{ licenseError }}
      </p>
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
  min-width: 0;
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

.stability--neutral {
  color: var(--sb-text-muted);
  background: var(--sb-surface-2);
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
  overflow-wrap: anywhere;
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
  min-width: 0;
  padding: var(--sb-space-3);
  background: var(--sb-surface-2);
  border: 1px solid var(--sb-border);
  border-radius: var(--sb-radius-sm);
}

.variant-card--disabled {
  border-style: dashed;
}

.variant-card > p {
  margin: var(--sb-space-1) 0 var(--sb-space-2);
  color: var(--sb-text-muted);
  font-size: 0.72rem;
  overflow-wrap: anywhere;
}

.variant-card > .variant-disabled-reason {
  color: var(--sb-warn-fg);
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
  overflow-wrap: anywhere;
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
