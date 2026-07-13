<script setup lang="ts">
import { computed, reactive, ref } from "vue";
import type {
  CatalogEntry,
  CatalogResponse,
  CatalogVariant,
  EngineChoice,
  ModelDeployment,
} from "../api";
import {
  deployableCatalogEntries,
  deployableCatalogVariants,
  deploymentFormDefaults,
  deploymentFormFromDeployment,
  parseDeploymentForm,
  type DeploymentConflictState,
  type DeploymentFormDraft,
  type DeploymentFormField,
  type DeploymentFormValue,
} from "../lib/model-management";
import ModelCatalogEvidence from "./ModelCatalogEvidence.vue";
import ModalDialog from "./ModalDialog.vue";

const props = defineProps<{
  catalog: CatalogResponse;
  existingDeploymentIds: readonly string[];
  initialDeploymentId?: string | null;
  initialDeployment?: ModelDeployment | null;
  saving?: boolean;
  submitError?: string | null;
  conflict?: DeploymentConflictState | null;
}>();

const emit = defineEmits<{
  (event: "close"): void;
  (event: "save", value: DeploymentFormValue): void;
}>();

const catalogModels = computed(() => deployableCatalogEntries(props.catalog));

function uniqueDeploymentId(model: string): string {
  const base =
    model
      .trim()
      .replace(/[^A-Za-z0-9._-]+/g, "-")
      .replace(/^-+|-+$/g, "") || "model";
  if (!props.existingDeploymentIds.includes(base)) return base;
  let suffix = 2;
  while (props.existingDeploymentIds.includes(`${base}-${suffix}`)) suffix += 1;
  return `${base}-${suffix}`;
}

const firstModel = catalogModels.value[0]?.id ?? "";
const originalModel = props.initialDeployment?.model ?? null;
const originalDeploymentId = props.initialDeploymentId ?? null;
const initialDraft = props.initialDeployment && originalDeploymentId
  ? deploymentFormFromDeployment(originalDeploymentId, props.initialDeployment)
  : deploymentFormDefaults(uniqueDeploymentId(firstModel), firstModel, null);
const draft = reactive<DeploymentFormDraft>(initialDraft);
const errors = reactive<Partial<Record<DeploymentFormField, string>>>({});
const deploymentIdTouched = ref(Boolean(originalDeploymentId));

const selectedEntry = computed<CatalogEntry | null>(
  () => props.catalog.models[draft.model] ?? null,
);
const selectedVariants = computed<CatalogVariant[]>(() =>
  selectedEntry.value
    ? deployableCatalogVariants(selectedEntry.value)
    : [],
);
const selectedVariant = computed<CatalogVariant | null>(() =>
  selectedVariants.value.find((variant) => variant.id === draft.variant) ?? null,
);
const evidenceVariants = computed(() =>
  selectedVariant.value ? [selectedVariant.value] : selectedVariants.value,
);
const availableEngines = computed(() => {
  const engines = new Set(
    evidenceVariants.value.flatMap((variant) => variant.engines),
  );
  return [...engines].sort();
});
const requiresLicenseAcknowledgement = computed(
  () => originalModel === null || originalModel !== draft.model,
);

function onDeploymentIdInput() {
  deploymentIdTouched.value = true;
}

function onModelChange() {
  draft.variant = "";
  draft.engine = "auto";
  draft.licenseAcknowledged = false;
  if (!deploymentIdTouched.value) {
    draft.deploymentId = uniqueDeploymentId(draft.model);
  }
}

function onVariantChange() {
  if (
    draft.engine !== "auto" &&
    !availableEngines.value.includes(draft.engine)
  ) {
    draft.engine = "auto";
  }
}

function variantLabel(variant: CatalogVariant): string {
  const stability =
    variant.stability === "stable"
      ? "Stable"
      : variant.stability === "preview"
        ? "Preview"
        : variant.stability === "config_only"
          ? "Config only"
          : "Unsupported";
  return `${variant.id} · ${variant.quant} · ${stability}`;
}

function engineLabel(engine: EngineChoice): string {
  if (engine === "auto") return "Automatic";
  if (engine === "llama_cpp") return "llama.cpp";
  if (engine === "vllm") return "vLLM";
  return "Embedded";
}

function errorFor(field: DeploymentFormField): string | undefined {
  return errors[field];
}

function submit() {
  for (const field of Object.keys(errors) as DeploymentFormField[]) {
    delete errors[field];
  }
  const parsed = parseDeploymentForm(draft, {
    requireLicenseAcknowledgement: requiresLicenseAcknowledgement.value,
    existingDeploymentIds: props.existingDeploymentIds,
    originalDeploymentId,
  });
  Object.assign(errors, parsed.errors);
  if (parsed.value) emit("save", parsed.value);
}

function comparisonCue(conflict: DeploymentConflictState): string {
  const { added, changed, removed } = conflict.comparison;
  return `${added.length} added, ${changed.length} changed, ${removed.length} removed compared with the reloaded map.`;
}
</script>

<template>
  <ModalDialog
    :title="initialDeployment ? 'Edit deployment' : 'Add deployment'"
    wide
    @close="emit('close')"
  >
    <form id="model-deployment-form" class="deployment-form" novalidate @submit.prevent="submit">
      <div class="form-column">
        <section class="form-section" aria-labelledby="deployment-identity-heading">
          <div class="section-heading">
            <p class="sb-eyebrow">Desired identity</p>
            <h3 id="deployment-identity-heading">Model and variant</h3>
          </div>

          <div class="form-grid form-grid--two">
            <label class="sb-field">
              <span class="sb-label">Deployment ID</span>
              <input
                v-model="draft.deploymentId"
                class="sb-input sb-mono"
                :aria-invalid="Boolean(errorFor('deploymentId'))"
                :aria-describedby="errorFor('deploymentId') ? 'deployment-id-error' : undefined"
                autocomplete="off"
                autofocus
                @input="onDeploymentIdInput"
              />
              <span v-if="errorFor('deploymentId')" id="deployment-id-error" class="field-error">
                {{ errorFor("deploymentId") }}
              </span>
              <span v-else class="field-hint">Canonical ID used by routes and lifecycle actions.</span>
            </label>

            <label class="sb-field">
              <span class="sb-label">Logical model</span>
              <select
                v-model="draft.model"
                class="sb-select"
                :aria-invalid="Boolean(errorFor('model'))"
                @change="onModelChange"
              >
                <option v-for="model in catalogModels" :key="model.id" :value="model.id">
                  {{ model.id }}
                </option>
              </select>
              <span v-if="errorFor('model')" class="field-error">{{ errorFor("model") }}</span>
            </label>
          </div>

          <div class="form-grid form-grid--two">
            <label class="sb-field">
              <span class="sb-label">Variant</span>
              <select
                v-model="draft.variant"
                class="sb-select"
                :aria-invalid="Boolean(errorFor('variant'))"
                @change="onVariantChange"
              >
                <option value="">Automatic selection</option>
                <option
                  v-for="variant in selectedVariants"
                  :key="variant.id"
                  :value="variant.id"
                >
                  {{ variantLabel(variant) }}
                </option>
              </select>
              <span v-if="errorFor('variant')" class="field-error">{{ errorFor("variant") }}</span>
              <span v-else class="field-hint">Pin an exact artifact for homogeneous replicas.</span>
            </label>

            <label class="sb-field">
              <span class="sb-label">Replicas</span>
              <input
                v-model="draft.replicas"
                class="sb-input"
                type="number"
                min="1"
                max="1024"
                inputmode="numeric"
                :aria-invalid="Boolean(errorFor('replicas'))"
              />
              <span v-if="errorFor('replicas')" class="field-error">{{ errorFor("replicas") }}</span>
            </label>
          </div>

          <label class="check-row">
            <input v-model="draft.heterogeneousVariants" type="checkbox" />
            <span>
              <strong>Allow heterogeneous variants</strong>
              <small>Replicas may resolve different compatible variants when selection is automatic.</small>
            </span>
          </label>
        </section>

        <section class="form-section" aria-labelledby="placement-heading">
          <div class="section-heading">
            <p class="sb-eyebrow">Placement</p>
            <h3 id="placement-heading">Worker constraints</h3>
          </div>
          <div class="form-grid form-grid--two">
            <label class="sb-field">
              <span class="sb-label">Required labels</span>
              <textarea
                v-model="draft.requiredLabels"
                class="sb-textarea compact-textarea"
                placeholder="pool=gpu&#10;region=us-west"
                :aria-invalid="Boolean(errorFor('requiredLabels'))"
              />
              <span v-if="errorFor('requiredLabels')" class="field-error">
                {{ errorFor("requiredLabels") }}
              </span>
              <span v-else class="field-hint">One <span class="sb-mono">key=value</span> per line.</span>
            </label>
            <label class="sb-field">
              <span class="sb-label">Spread keys</span>
              <textarea
                v-model="draft.spreadBy"
                class="sb-textarea compact-textarea"
                placeholder="zone&#10;rack"
                :aria-invalid="Boolean(errorFor('spreadBy'))"
              />
              <span v-if="errorFor('spreadBy')" class="field-error">{{ errorFor("spreadBy") }}</span>
              <span v-else class="field-hint">Ordered label keys, one per line.</span>
            </label>
          </div>
        </section>

        <section class="form-section" aria-labelledby="runtime-policy-heading">
          <div class="section-heading">
            <p class="sb-eyebrow">Runtime policy</p>
            <h3 id="runtime-policy-heading">Acquisition and serving</h3>
          </div>
          <div class="form-grid form-grid--three">
            <label class="sb-field">
              <span class="sb-label">Pull policy</span>
              <select v-model="draft.pull" class="sb-select">
                <option value="on_demand">On demand</option>
                <option value="on_boot">On boot</option>
                <option value="manual">Manual</option>
              </select>
            </label>
            <label class="sb-field">
              <span class="sb-label">Engine</span>
              <select v-model="draft.engine" class="sb-select">
                <option value="auto">Automatic</option>
                <option v-for="engine in availableEngines" :key="engine" :value="engine">
                  {{ engineLabel(engine) }}
                </option>
              </select>
            </label>
            <label class="sb-field">
              <span class="sb-label">Rollout</span>
              <select v-model="draft.rollout" class="sb-select">
                <option value="rolling">Rolling</option>
                <option value="recreate">Recreate</option>
              </select>
            </label>
          </div>

          <label class="check-row">
            <input v-model="draft.warm" type="checkbox" />
            <span>
              <strong>Warm before traffic</strong>
              <small>Prepare the artifact and engine before this deployment receives requests.</small>
            </span>
          </label>

          <div class="form-grid form-grid--two admission-grid">
            <label class="sb-field">
              <span class="sb-label">Keep-alive seconds</span>
              <input
                v-model="draft.keepAliveSecs"
                class="sb-input"
                type="number"
                min="0"
                inputmode="numeric"
                placeholder="Runtime default"
                :aria-invalid="Boolean(errorFor('keepAliveSecs'))"
              />
              <span v-if="errorFor('keepAliveSecs')" class="field-error">
                {{ errorFor("keepAliveSecs") }}
              </span>
            </label>
            <label class="sb-field">
              <span class="sb-label">Max concurrency</span>
              <input
                v-model="draft.maxConcurrency"
                class="sb-input"
                type="number"
                min="1"
                inputmode="numeric"
                placeholder="Runtime default"
                :aria-invalid="Boolean(errorFor('maxConcurrency'))"
              />
              <span v-if="errorFor('maxConcurrency')" class="field-error">
                {{ errorFor("maxConcurrency") }}
              </span>
            </label>
            <label class="sb-field">
              <span class="sb-label">Max queue depth</span>
              <input
                v-model="draft.maxQueueDepth"
                class="sb-input"
                type="number"
                min="0"
                inputmode="numeric"
                :aria-invalid="Boolean(errorFor('maxQueueDepth'))"
              />
              <span v-if="errorFor('maxQueueDepth')" class="field-error">
                {{ errorFor("maxQueueDepth") }}
              </span>
            </label>
            <label class="sb-field">
              <span class="sb-label">Queue timeout milliseconds</span>
              <input
                v-model="draft.queueTimeoutMs"
                class="sb-input"
                type="number"
                min="1"
                inputmode="numeric"
                :aria-invalid="Boolean(errorFor('queueTimeoutMs'))"
              />
              <span v-if="errorFor('queueTimeoutMs')" class="field-error">
                {{ errorFor("queueTimeoutMs") }}
              </span>
            </label>
          </div>
        </section>
      </div>

      <ModelCatalogEvidence
        :model="draft.model"
        :entry="selectedEntry"
        :variants="evidenceVariants"
        :automatic-selection="!draft.variant"
        :requires-license-acknowledgement="requiresLicenseAcknowledgement"
        :license-acknowledged="draft.licenseAcknowledged"
        :license-error="errorFor('licenseAcknowledged')"
        @update:license-acknowledged="draft.licenseAcknowledged = $event"
      />

      <section v-if="conflict" class="submit-notice submit-notice--conflict" role="alert">
        <strong>Desired state changed while you were editing.</strong>
        <p>
          Revision {{ conflict.expectedRevision ?? "none" }} was replaced by revision
          {{ conflict.currentRevision ?? "none" }}. Your form is unchanged.
          {{ comparisonCue(conflict) }} Review it and save again to replace the current complete map.
        </p>
      </section>
      <section v-else-if="submitError" class="submit-notice submit-notice--error" role="alert">
        <strong>Deployment was not saved.</strong>
        <p>{{ submitError }}</p>
      </section>
    </form>

    <template #footer>
      <button class="sb-btn" type="button" :disabled="saving" @click="emit('close')">Cancel</button>
      <button
        class="sb-btn sb-btn--primary"
        type="submit"
        form="model-deployment-form"
        :disabled="saving || catalogModels.length === 0"
      >
        {{ saving ? "Saving..." : initialDeployment ? "Save changes" : "Add deployment" }}
      </button>
    </template>
  </ModalDialog>
</template>

<style scoped>
.deployment-form {
  display: grid;
  grid-template-columns: minmax(0, 1.55fr) minmax(250px, 0.85fr);
  gap: var(--sb-space-5);
}

.form-column {
  min-width: 0;
}

.form-section + .form-section {
  padding-top: var(--sb-space-5);
  margin-top: var(--sb-space-5);
  border-top: 1px solid var(--sb-border);
}

.section-heading {
  margin-bottom: var(--sb-space-4);
}

.section-heading .sb-eyebrow {
  margin: 0 0 var(--sb-space-1);
}

.form-grid {
  display: grid;
  gap: 0 var(--sb-space-4);
}

.form-grid--two {
  grid-template-columns: repeat(2, minmax(0, 1fr));
}

.form-grid--three {
  grid-template-columns: repeat(3, minmax(0, 1fr));
}

.compact-textarea {
  min-height: 78px;
}

.field-hint,
.field-error {
  font-size: 0.7rem;
  line-height: 1.4;
}

.field-hint {
  color: var(--sb-text-faint);
}

.field-error {
  color: var(--sb-err);
}

.check-row {
  display: flex;
  align-items: flex-start;
  gap: var(--sb-space-2);
  padding: var(--sb-space-3);
  color: var(--sb-text-muted);
  background: var(--sb-surface-2);
  border: 1px solid var(--sb-border);
  border-radius: var(--sb-radius-sm);
  cursor: pointer;
}

.check-row input {
  margin: 3px 0 0;
  accent-color: var(--sb-accent);
}

.check-row span {
  display: grid;
  gap: 2px;
}

.check-row strong {
  color: var(--sb-text);
  font-size: 0.78rem;
}

.check-row small {
  font-size: 0.7rem;
}

.admission-grid {
  margin-top: var(--sb-space-4);
}

.submit-notice {
  grid-column: 1 / -1;
  padding: var(--sb-space-3) var(--sb-space-4);
  border-radius: var(--sb-radius-sm);
  font-size: 0.78rem;
}

.submit-notice p {
  margin: var(--sb-space-1) 0 0;
}

.submit-notice--conflict {
  color: var(--sb-warn-fg);
  background: var(--sb-warn-bg);
  border: 1px solid var(--sb-warn);
}

.submit-notice--error {
  color: var(--sb-err);
  background: var(--sb-err-bg);
  border: 1px solid var(--sb-err);
}

@media (max-width: 840px) {
  .deployment-form {
    grid-template-columns: 1fr;
  }
}

@media (max-width: 620px) {
  .form-grid--two,
  .form-grid--three {
    grid-template-columns: 1fr;
  }
}
</style>
