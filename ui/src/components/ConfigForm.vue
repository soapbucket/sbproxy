<script setup lang="ts">
// One level of the schema-generated config form. Recurses into itself for
// nested sections.
//
// The component holds draft text for the field being typed into and nothing
// else. The document is the source of truth and lives in the view, so a field
// mid-edit can be invalid (a half-typed port) without that invalid state ever
// reaching the patch. Committing happens on change, not on keystroke.
import { computed, ref } from "vue";
import { parse as parseYaml, stringify as stringifyYaml } from "yaml";
import { coerceScalar, dottedPath } from "../lib/config-patch";
import { fieldState, type OwnershipContext } from "../lib/config-form";
import { valueAt, type FormNode } from "../lib/config-schema";

const props = defineProps<{
  nodes: FormNode[];
  doc: unknown;
  ownership: OwnershipContext;
  /** Dotted paths a write guard rejected, rendered on the offending field. */
  conflicts: Record<string, true>;
  depth?: number;
}>();

const emit = defineEmits<{
  (e: "set", path: string[], value: unknown): void;
  (e: "remove", path: string[]): void;
}>();

const level = computed(() => props.depth ?? 0);

/** Draft text per field, present only while a field is being edited. */
const drafts = ref<Record<string, string>>({});
/** Per-field validation message, cleared when the field parses again. */
const errors = ref<Record<string, string>>({});

function key(node: FormNode): string {
  return dottedPath(node.path).dotted;
}

function state(node: FormNode) {
  return fieldState(node, props.ownership);
}

function conflicted(node: FormNode): boolean {
  return props.conflicts[key(node)] === true;
}

function current(node: FormNode): unknown {
  return valueAt(props.doc, node.path);
}

function textValue(node: FormNode): string {
  const id = key(node);
  if (id in drafts.value) return drafts.value[id];
  const value = current(node);
  if (value === undefined || value === null) return "";
  return String(value);
}

function boolValue(node: FormNode): boolean {
  return current(node) === true;
}

function commitScalar(node: FormNode, raw: string) {
  const id = key(node);
  drafts.value[id] = raw;
  if (node.kind !== "scalar") return;

  // Empty means "unset this", not "set it to the empty string". A cleared
  // optional field should fall back to the documented default rather than
  // pinning an empty value the schema may not accept.
  if (raw.trim() === "" && node.nullable) {
    delete errors.value[id];
    emit("remove", node.path);
    return;
  }
  const coerced = coerceScalar(raw, node.type);
  if ("error" in coerced) {
    errors.value[id] = coerced.error;
    return;
  }
  delete errors.value[id];
  emit("set", node.path, coerced.value);
}

function commitBool(node: FormNode, checked: boolean) {
  emit("set", node.path, checked);
}

function commitChoice(node: FormNode, raw: string) {
  if (node.kind !== "scalar") return;
  if (raw === "" && node.nullable) {
    emit("remove", node.path);
    return;
  }
  // A choice list can hold numbers, so send back the typed value rather than
  // the option's string form.
  const match = node.choices?.find((choice) => String(choice) === raw);
  emit("set", node.path, match ?? raw);
}

function listText(node: FormNode): string {
  const id = key(node);
  if (id in drafts.value) return drafts.value[id];
  const value = current(node);
  return Array.isArray(value) ? value.map((v) => String(v)).join("\n") : "";
}

function commitList(node: FormNode, raw: string) {
  const id = key(node);
  drafts.value[id] = raw;
  if (node.kind !== "scalarList") return;
  const lines = raw
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
  if (!lines.length) {
    delete errors.value[id];
    emit("remove", node.path);
    return;
  }
  const values: unknown[] = [];
  for (const line of lines) {
    const coerced = coerceScalar(line, node.itemType);
    if ("error" in coerced) {
      errors.value[id] = `${line}: ${coerced.error}`;
      return;
    }
    values.push(coerced.value);
  }
  delete errors.value[id];
  emit("set", node.path, values);
}

/**
 * YAML for one opaque subtree.
 *
 * The form cannot describe these nodes, so it hands back the YAML for that
 * node alone rather than for the whole document. An operator editing a policy
 * list still edits YAML, but they edit six lines of it instead of six hundred,
 * and everything around it stays in the form.
 */
function opaqueText(node: FormNode): string {
  const id = key(node);
  if (id in drafts.value) return drafts.value[id];
  const value = current(node);
  if (value === undefined) return "";
  return stringifyYaml(value);
}

function commitOpaque(node: FormNode, raw: string) {
  const id = key(node);
  drafts.value[id] = raw;
  if (raw.trim() === "") {
    delete errors.value[id];
    emit("remove", node.path);
    return;
  }
  try {
    const parsed = parseYaml(raw);
    delete errors.value[id];
    emit("set", node.path, parsed);
  } catch (e) {
    errors.value[id] = e instanceof Error ? e.message : "not valid YAML";
  }
}

function bubbleSet(path: string[], value: unknown) {
  emit("set", path, value);
}

function bubbleRemove(path: string[]) {
  emit("remove", path);
}
</script>

<template>
  <div class="form-level" :class="`form-level--${level}`">
    <template v-for="node in nodes" :key="key(node)">
      <!-- A section with declared properties. -->
      <details v-if="node.kind === 'object'" class="group">
        <summary>
          <span class="group__title">{{ node.title }}</span>
          <span class="sb-faint group__hint" v-if="node.description">{{ node.description }}</span>
        </summary>
        <ConfigForm
          :nodes="node.fields"
          :doc="doc"
          :ownership="ownership"
          :conflicts="conflicts"
          :depth="level + 1"
          @set="bubbleSet"
          @remove="bubbleRemove"
        />
      </details>

      <!-- A free-form map: one group per key in the document. -->
      <details v-else-if="node.kind === 'map'" class="group">
        <summary>
          <span class="group__title">{{ node.title }}</span>
          <span class="sb-faint group__hint">
            {{ node.entries.length }} entr{{ node.entries.length === 1 ? "y" : "ies" }}
          </span>
        </summary>
        <p class="sb-faint" v-if="!node.entries.length">
          Nothing here yet. Add one in the raw editor; this form edits entries
          that already exist rather than inventing keys.
        </p>
        <details v-for="entry in node.entries" :key="entry.key" class="group group--entry">
          <summary><span class="sb-mono">{{ entry.key }}</span></summary>
          <ConfigForm
            :nodes="entry.fields"
            :doc="doc"
            :ownership="ownership"
            :conflicts="conflicts"
            :depth="level + 1"
            @set="bubbleSet"
            @remove="bubbleRemove"
          />
        </details>
      </details>

      <!-- A node the schema does not describe: YAML, scoped to this node. -->
      <div v-else-if="node.kind === 'opaque'" class="field field--opaque">
        <label :for="`f-${key(node)}`">
          {{ node.title }}
          <span class="badge badge--yaml">YAML</span>
          <span class="badge badge--locked" v-if="state(node).locked">{{ state(node).badge }}</span>
        </label>
        <p class="sb-faint field__hint" v-if="node.description">{{ node.description }}</p>
        <p class="sb-faint field__hint">
          Edited as YAML because {{ node.reason }}.
        </p>
        <textarea
          :id="`f-${key(node)}`"
          class="sb-input field__yaml"
          spellcheck="false"
          :readonly="state(node).locked"
          :value="opaqueText(node)"
          @change="commitOpaque(node, ($event.target as HTMLTextAreaElement).value)"
        ></textarea>
        <p class="field__error" v-if="errors[key(node)]">{{ errors[key(node)] }}</p>
        <p class="field__error" v-else-if="conflicted(node)">
          The server refused this path: it is set outside this node.
        </p>
      </div>

      <!-- A list of scalars, one per line. -->
      <div v-else-if="node.kind === 'scalarList'" class="field">
        <label :for="`f-${key(node)}`">
          {{ node.title }}
          <span class="badge badge--locked" v-if="state(node).locked">{{ state(node).badge }}</span>
        </label>
        <p class="sb-faint field__hint" v-if="node.description">{{ node.description }}</p>
        <textarea
          :id="`f-${key(node)}`"
          class="sb-input field__list"
          spellcheck="false"
          :readonly="state(node).locked"
          :value="listText(node)"
          @change="commitList(node, ($event.target as HTMLTextAreaElement).value)"
        ></textarea>
        <p class="sb-faint field__hint">One per line.</p>
        <p class="field__error" v-if="errors[key(node)]">{{ errors[key(node)] }}</p>
        <p class="field__error" v-else-if="conflicted(node)">
          The server refused this path: it is set outside this node.
        </p>
      </div>

      <!-- A single value. -->
      <div v-else class="field">
        <label :for="`f-${key(node)}`">
          {{ node.title }}
          <span class="badge badge--locked" v-if="state(node).locked">{{ state(node).badge }}</span>
        </label>
        <p class="sb-faint field__hint" v-if="node.description">{{ node.description }}</p>

        <select
          v-if="node.choices"
          :id="`f-${key(node)}`"
          class="sb-input"
          :disabled="state(node).locked"
          :value="textValue(node)"
          @change="commitChoice(node, ($event.target as HTMLSelectElement).value)"
        >
          <option value="" v-if="node.nullable">(unset)</option>
          <option v-for="choice in node.choices" :key="String(choice)" :value="String(choice)">
            {{ choice }}
          </option>
        </select>

        <input
          v-else-if="node.type === 'boolean'"
          :id="`f-${key(node)}`"
          type="checkbox"
          :disabled="state(node).locked"
          :checked="boolValue(node)"
          @change="commitBool(node, ($event.target as HTMLInputElement).checked)"
        />

        <input
          v-else
          :id="`f-${key(node)}`"
          class="sb-input"
          :type="node.type === 'string' ? 'text' : 'number'"
          :readonly="state(node).locked"
          :value="textValue(node)"
          :placeholder="node.default !== undefined && node.default !== null ? String(node.default) : ''"
          @change="commitScalar(node, ($event.target as HTMLInputElement).value)"
        />

        <p class="field__error" v-if="errors[key(node)]">{{ errors[key(node)] }}</p>
        <p class="field__error" v-else-if="conflicted(node)">
          The server refused this path: it is set outside this node.
        </p>
      </div>
    </template>
  </div>
</template>

<style scoped>
.form-level {
  display: flex;
  flex-direction: column;
  gap: var(--sb-space-3);
}
.form-level--0 > .group {
  border-top: 1px solid var(--sb-border);
  padding-top: var(--sb-space-3);
}
.group {
  padding-left: 0;
}
.group--entry {
  margin-left: var(--sb-space-4);
}
.group summary {
  cursor: pointer;
  display: flex;
  align-items: baseline;
  gap: var(--sb-space-3);
  flex-wrap: wrap;
}
.group__title {
  font-weight: 600;
}
.group__hint {
  font-size: 0.85rem;
}
.group > *:not(summary) {
  margin-left: var(--sb-space-4);
  margin-top: var(--sb-space-3);
}
.field {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}
.field label {
  display: flex;
  align-items: baseline;
  gap: var(--sb-space-2);
  font-weight: 500;
}
.field__hint {
  margin: 0;
  font-size: 0.85rem;
}
.field__error {
  margin: 0;
  font-size: 0.85rem;
  color: #c0392b;
}
.field__yaml,
.field__list {
  min-height: 5rem;
  font-family: var(--sb-font-mono, monospace);
  font-size: 0.85rem;
}
.badge {
  font-size: 0.7rem;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  padding: 0.1rem 0.35rem;
  border: 1px solid var(--sb-border);
}
.badge--locked {
  background: #fdf3e0;
  color: #8a5a12;
  border-color: #e6cfa3;
}
.badge--yaml {
  color: var(--sb-text-faint);
}
input[readonly].sb-input,
textarea[readonly].sb-input {
  opacity: 0.7;
  cursor: not-allowed;
}
</style>
