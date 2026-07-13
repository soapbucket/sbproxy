<script setup lang="ts">
import { computed, nextTick, reactive, ref } from "vue";
import type {
  CatalogEntry,
  CatalogResponse,
  CatalogVariant,
  EngineChoice,
  ModelDeployment,
} from "../api";
import {
  catalogVariantDisabledReason,
  catalogVariantSupportLabel,
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
  canSave?: boolean;
  submitError?: string | null;
  conflict?: DeploymentConflictState | null;
}>();

const emit = defineEmits<{
  (event: "close"): void;
  (event: "save", value: DeploymentFormValue): void;
  (event: "reload-conflict"): void;
}>();

const allCatalogModels = computed(() =>
  Object.entries(props.catalog.models)
    .map(([id, entry]) => ({ id, entry }))
    .sort((left, right) => left.id.localeCompare(right.id)),
);
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
const errorSummary = ref<HTMLElement | null>(null);

const selectedEntry = computed<CatalogEntry | null>(
  () =>
    Object.hasOwn(props.catalog.models, draft.model)
      ? props.catalog.models[draft.model]
      : null,
);
const selectedVariants = computed<CatalogVariant[]>(() =>
  selectedEntry.value ? selectedEntry.value.variants : [],
);
const selectedRunnableVariants = computed<CatalogVariant[]>(() =>
  selectedEntry.value ? deployableCatalogVariants(selectedEntry.value) : [],
);
const selectedVariant = computed<CatalogVariant | null>(() =>
  selectedVariants.value.find((variant) => variant.id === draft.variant) ?? null,
);
const evidenceVariants = computed(() =>
  selectedVariant.value ? [selectedVariant.value] : selectedVariants.value,
);
const availableEngines = computed(() => {
  const variants = selectedVariant.value
    ? catalogVariantDisabledReason(selectedVariant.value) === null
      ? [selectedVariant.value]
      : []
    : selectedRunnableVariants.value;
  const engines = new Set(
    variants.flatMap((variant) => variant.engines),
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
  const reason = catalogVariantDisabledReason(variant);
  return `${variant.id} · ${variant.quant} · ${catalogVariantSupportLabel(variant)}${reason ? ` · ${reason}` : ""}`;
}

function modelDisabledReason(entry: CatalogEntry): string | null {
  if (entry.variants.length === 0) return "No variants are listed.";
  if (deployableCatalogVariants(entry).length === 0) {
    return "No runnable stable or preview variants.";
  }
  return null;
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

function describedBy(
  field: DeploymentFormField,
  hintId?: string,
): string | undefined {
  const ids = [hintId, errorFor(field) ? `${field}-error` : undefined].filter(
    (id): id is string => Boolean(id),
  );
  return ids.length > 0 ? ids.join(" ") : undefined;
}

const ERROR_ORDER: DeploymentFormField[] = [
  "deploymentId",
  "model",
  "variant",
  "replicas",
  "requiredLabels",
  "spreadBy",
  "keepAliveSecs",
  "maxConcurrency",
  "maxQueueDepth",
  "queueTimeoutMs",
  "licenseAcknowledged",
];

const CONTROL_IDS: Partial<Record<DeploymentFormField, string>> = {
  deploymentId: "deployment-id",
  model: "deployment-model",
  variant: "deployment-variant",
  replicas: "deployment-replicas",
  requiredLabels: "deployment-required-labels",
  spreadBy: "deployment-spread-by",
  keepAliveSecs: "deployment-keep-alive",
  maxConcurrency: "deployment-max-concurrency",
  maxQueueDepth: "deployment-max-queue-depth",
  queueTimeoutMs: "deployment-queue-timeout",
  licenseAcknowledged: "license-acknowledgement",
};
const validationErrors = computed(() =>
  ERROR_ORDER.flatMap((field) => {
    const message = errorFor(field);
    return message ? [{ field, message }] : [];
  }),
);

async function focusFirstError(): Promise<void> {
  await nextTick();
  const firstField = ERROR_ORDER.find((field) => Boolean(errorFor(field)));
  const controlId = firstField ? CONTROL_IDS[firstField] : undefined;
  const control = controlId ? document.getElementById(controlId) : null;
  (control ?? errorSummary.value)?.focus();
}

async function submit() {
  for (const field of Object.keys(errors) as DeploymentFormField[]) {
    delete errors[field];
  }
  const parsed = parseDeploymentForm(draft, {
    requireLicenseAcknowledgement: requiresLicenseAcknowledgement.value,
    existingDeploymentIds: props.existingDeploymentIds,
    originalDeploymentId,
    catalog: props.catalog,
  });
  Object.assign(errors, parsed.errors);
  if (parsed.value) {
    emit("save", parsed.value);
    return;
  }
  await focusFirstError();
}

function comparisonCue(conflict: DeploymentConflictState): string {
  if (!conflict.comparison) {
    return conflict.reloadError
      ? `Current authority state was not loaded: ${conflict.reloadError}`
      : "Current authority state is still loading.";
  }
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
      <section
        v-if="validationErrors.length"
        id="deployment-form-errors"
        ref="errorSummary"
        class="error-summary"
        role="alert"
        aria-live="assertive"
        tabindex="-1"
      >
        <strong>Fix the following fields before saving.</strong>
        <ul>
          <li v-for="error in validationErrors" :key="error.field">
            {{ error.message }}
          </li>
        </ul>
      </section>
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
                id="deployment-id"
                v-model="draft.deploymentId"
                class="sb-input sb-mono"
                :aria-invalid="Boolean(errorFor('deploymentId'))"
                :aria-describedby="describedBy('deploymentId', 'deploymentId-hint')"
                autocomplete="off"
                autofocus
                @input="onDeploymentIdInput"
              />
              <span v-if="errorFor('deploymentId')" id="deploymentId-error" class="field-error">
                {{ errorFor("deploymentId") }}
              </span>
              <span id="deploymentId-hint" class="field-hint">Canonical ID used by routes and lifecycle actions.</span>
            </label>

            <label class="sb-field">
              <span class="sb-label">Logical model</span>
              <select
                id="deployment-model"
                v-model="draft.model"
                class="sb-select"
                :aria-invalid="Boolean(errorFor('model'))"
                :aria-describedby="describedBy('model')"
                @change="onModelChange"
              >
                <option
                  v-if="draft.model && !selectedEntry"
                  :value="draft.model"
                  disabled
                >
                  {{ draft.model }} · No longer in the active catalog
                </option>
                <option
                  v-for="model in allCatalogModels"
                  :key="model.id"
                  :value="model.id"
                  :disabled="Boolean(modelDisabledReason(model.entry))"
                >
                  {{ model.id }}<template v-if="modelDisabledReason(model.entry)"> · {{ modelDisabledReason(model.entry) }}</template>
                </option>
              </select>
              <span v-if="errorFor('model')" id="model-error" class="field-error">{{ errorFor("model") }}</span>
            </label>
          </div>

          <div class="form-grid form-grid--two">
            <label class="sb-field">
              <span class="sb-label">Variant</span>
              <select
                id="deployment-variant"
                v-model="draft.variant"
                class="sb-select"
                :aria-invalid="Boolean(errorFor('variant'))"
                :aria-describedby="describedBy('variant', 'variant-hint')"
                @change="onVariantChange"
              >
                <option value="" :disabled="selectedRunnableVariants.length === 0">
                  Automatic selection
                </option>
                <option
                  v-if="draft.variant && !selectedVariant"
                  :value="draft.variant"
                  disabled
                >
                  {{ draft.variant }} · No longer in the active catalog
                </option>
                <option
                  v-for="variant in selectedVariants"
                  :key="variant.id"
                  :value="variant.id"
                  :disabled="Boolean(catalogVariantDisabledReason(variant))"
                >
                  {{ variantLabel(variant) }}
                </option>
              </select>
              <span v-if="errorFor('variant')" id="variant-error" class="field-error">{{ errorFor("variant") }}</span>
              <span id="variant-hint" class="field-hint">Pin an exact runnable artifact for homogeneous replicas.</span>
            </label>

            <label class="sb-field">
              <span class="sb-label">Replicas</span>
              <input
                id="deployment-replicas"
                v-model="draft.replicas"
                class="sb-input"
                type="number"
                min="1"
                max="1024"
                inputmode="numeric"
                :aria-invalid="Boolean(errorFor('replicas'))"
                :aria-describedby="describedBy('replicas')"
              />
              <span v-if="errorFor('replicas')" id="replicas-error" class="field-error">{{ errorFor("replicas") }}</span>
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
                id="deployment-required-labels"
                v-model="draft.requiredLabels"
                class="sb-textarea compact-textarea"
                placeholder="pool=gpu&#10;region=us-west"
                :aria-invalid="Boolean(errorFor('requiredLabels'))"
                :aria-describedby="describedBy('requiredLabels', 'requiredLabels-hint')"
              />
              <span v-if="errorFor('requiredLabels')" id="requiredLabels-error" class="field-error">
                {{ errorFor("requiredLabels") }}
              </span>
              <span id="requiredLabels-hint" class="field-hint">One <span class="sb-mono">key=value</span> per line.</span>
            </label>
            <label class="sb-field">
              <span class="sb-label">Spread keys</span>
              <textarea
                id="deployment-spread-by"
                v-model="draft.spreadBy"
                class="sb-textarea compact-textarea"
                placeholder="zone&#10;rack"
                :aria-invalid="Boolean(errorFor('spreadBy'))"
                :aria-describedby="describedBy('spreadBy', 'spreadBy-hint')"
              />
              <span v-if="errorFor('spreadBy')" id="spreadBy-error" class="field-error">{{ errorFor("spreadBy") }}</span>
              <span id="spreadBy-hint" class="field-hint">Ordered label keys, one per line.</span>
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
                id="deployment-keep-alive"
                v-model="draft.keepAliveSecs"
                class="sb-input"
                type="number"
                min="0"
                inputmode="numeric"
                placeholder="Runtime default"
                :aria-invalid="Boolean(errorFor('keepAliveSecs'))"
                :aria-describedby="describedBy('keepAliveSecs')"
              />
              <span v-if="errorFor('keepAliveSecs')" id="keepAliveSecs-error" class="field-error">
                {{ errorFor("keepAliveSecs") }}
              </span>
            </label>
            <label class="sb-field">
              <span class="sb-label">Max concurrency</span>
              <input
                id="deployment-max-concurrency"
                v-model="draft.maxConcurrency"
                class="sb-input"
                type="number"
                min="1"
                inputmode="numeric"
                placeholder="Runtime default"
                :aria-invalid="Boolean(errorFor('maxConcurrency'))"
                :aria-describedby="describedBy('maxConcurrency')"
              />
              <span v-if="errorFor('maxConcurrency')" id="maxConcurrency-error" class="field-error">
                {{ errorFor("maxConcurrency") }}
              </span>
            </label>
            <label class="sb-field">
              <span class="sb-label">Max queue depth</span>
              <input
                id="deployment-max-queue-depth"
                v-model="draft.maxQueueDepth"
                class="sb-input"
                type="number"
                min="0"
                inputmode="numeric"
                :aria-invalid="Boolean(errorFor('maxQueueDepth'))"
                :aria-describedby="describedBy('maxQueueDepth')"
              />
              <span v-if="errorFor('maxQueueDepth')" id="maxQueueDepth-error" class="field-error">
                {{ errorFor("maxQueueDepth") }}
              </span>
            </label>
            <label class="sb-field">
              <span class="sb-label">Queue timeout milliseconds</span>
              <input
                id="deployment-queue-timeout"
                v-model="draft.queueTimeoutMs"
                class="sb-input"
                type="number"
                min="1"
                inputmode="numeric"
                :aria-invalid="Boolean(errorFor('queueTimeoutMs'))"
                :aria-describedby="describedBy('queueTimeoutMs')"
              />
              <span v-if="errorFor('queueTimeoutMs')" id="queueTimeoutMs-error" class="field-error">
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
          Conflict response {{ conflict.status }}. Expected revision
          {{ conflict.expectedRevision ?? "none" }}. Your form is unchanged.
        </p>
        <pre class="raw-conflict">{{ conflict.body || "(empty response body)" }}</pre>
        <p>{{ comparisonCue(conflict) }}</p>
        <button
          v-if="!conflict.comparison"
          class="sb-btn sb-btn--sm"
          type="button"
          :disabled="saving"
          @click="emit('reload-conflict')"
        >
          {{ saving ? "Reloading..." : "Reload current state" }}
        </button>
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
        :disabled="saving || canSave === false || catalogModels.length === 0"
        :title="canSave === false ? 'Save is paused until current authority proof is available.' : undefined"
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
  min-width: 0;
}

.form-column,
.form-section,
.form-grid,
.sb-field {
  min-width: 0;
}

.error-summary {
  grid-column: 1 / -1;
  min-width: 0;
  padding: var(--sb-space-3) var(--sb-space-4);
  color: var(--sb-err);
  background: var(--sb-err-bg);
  border: 1px solid var(--sb-err);
  border-radius: var(--sb-radius-sm);
  overflow-wrap: anywhere;
}

.error-summary:focus {
  outline: 3px solid var(--sb-accent-ring);
  outline-offset: 2px;
}

.error-summary ul {
  margin: var(--sb-space-2) 0 0;
  padding-left: 1.2rem;
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
  overflow-wrap: anywhere;
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

.raw-conflict {
  max-width: 100%;
  margin: var(--sb-space-2) 0;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
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
