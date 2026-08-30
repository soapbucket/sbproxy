<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import {
  api,
  asList,
  ApiError,
  type ConfigHistoryDetail,
  type ConfigHistoryEntry,
  type ConfigWriteConflict,
  type EffectiveConfigResponse,
  type TargetHealth,
} from "../api";
import {
  isEditorLocked,
  ownedElsewhere,
  ownershipSummary,
  provenanceLabel,
  readOwnership,
} from "../lib/config-ownership";
import { applyEdits, PatchError } from "../lib/config-patch";
import { authorityLabel, conflictsByPath } from "../lib/config-form";
import { buildForm } from "../lib/config-schema";
import {
  blastRadiusLabel,
  blastRadiusTone,
  degradedSummary,
  historyStateTone,
  isConfigHistoryDisabled,
} from "../lib/config-history";
import ConfigForm from "../components/ConfigForm.vue";
import { parse as parseYaml } from "yaml";
import { useAsync } from "../composables/useAsync";
import { toast } from "../composables/useToasts";
import { formatMs, formatTime, shortId } from "../lib/format";
import PageHeader from "../components/PageHeader.vue";
import StatusBadge from "../components/StatusBadge.vue";
import ErrorState from "../components/ErrorState.vue";
import EmptyState from "../components/EmptyState.vue";

const openapi = useAsync(() => api.openapi());
const drift = useAsync(() => api.drift());
const targetsReq = useAsync(() => api.targets());

const effective = useAsync(() => api.effectiveConfig());
const configSchema = useAsync(() => api.configSchema());
const configHistory = useAsync(() => api.configHistory());

function refresh() {
  openapi.run();
  drift.run();
  targetsReq.run();
  effective.run();
  configSchema.run();
  configHistory.run();
  loadConfig();
}
onMounted(refresh);

// ---- configuration ownership (WOR-2012) ----
//
// The editor is offered only on a node whose own file is the whole
// configuration. This is a courtesy, not the enforcement: the server
// refuses the same writes with a 409 whether they arrive from this page or
// from curl. Showing the lock here just means an operator finds out before
// they have typed an edit rather than after.
//
// The reading of the response lives in lib/config-ownership so the cases
// that matter (an authority configured but never reached, a git base under
// an overlay, a response that has not arrived) are testable without a
// browser.
const ownership = computed(() =>
  readOwnership(effective.data.value as EffectiveConfigResponse | null),
);
const editorLocked = computed(() => isEditorLocked(ownership.value));
const ownerSummary = computed(() => ownershipSummary(ownership.value));
const notOwnedHere = computed(() =>
  ownedElsewhere(effective.data.value as EffectiveConfigResponse | null),
);

// ---- live config editor (WOR-1763) ----
const editorText = ref("");
const editorRev = ref("");
const configLoading = ref(false);
const configErr = ref<ApiError | null>(null);
const saveBusy = ref(false);
const saveBanner = ref<{ tone: "ok" | "err"; text: string } | null>(null);

// ---- schema-generated form (WOR-2013) ----
//
// `editorText` stays the single source of truth for both views. A form edit
// applies its patch to that text immediately rather than accumulating a
// separate edit list, which is what makes switching between form and raw
// unable to lose anything: there is only ever one document.
//
// The patch goes through the YAML document tree rather than a parse and
// re-serialize, so comments and key order survive. A form that rewrote the
// whole file on every change would be a worse editor than the textarea it
// replaced.
const mode = ref<"form" | "raw">("raw");
// Paths the write guard rejected, indexed so each field renders its own
// error. A 409 naming six paths as one toast is a puzzle; the same
// information on the six fields is a to-do list.
const fieldConflicts = ref<Record<string, true>>({});
const patchError = ref<string | null>(null);

/** The current document, parsed. `null` while the raw text does not parse. */
const parsedDoc = computed<unknown>(() => {
  if (!editorText.value.trim()) return {};
  try {
    return parseYaml(editorText.value) ?? {};
  } catch {
    return null;
  }
});

const formNodes = computed(() => {
  const schema = configSchema.data.value;
  if (!schema || parsedDoc.value === null) return [];
  return buildForm(schema, parsedDoc.value);
});

/**
 * Under `mode: replace`, or on a git-sourced node, nothing on this node is
 * editable and the form says so once at the top rather than on every field.
 */
const formOwnership = computed(() => ({
  wholeDocumentLocked: editorLocked.value,
  provenance:
    (effective.data.value as EffectiveConfigResponse | null)?.provenance ?? {},
  authorityLabel: authorityLabel(ownership.value?.authority),
}));

function onFormSet(path: string[], value: unknown) {
  applyToDocument([{ path, value }]);
}

function onFormRemove(path: string[]) {
  applyToDocument([{ path, remove: true as const }]);
}

function applyToDocument(edits: Parameters<typeof applyEdits>[1]) {
  try {
    editorText.value = applyEdits(editorText.value, edits);
    patchError.value = null;
    // An edited field is no longer the field the server complained about.
    for (const edit of edits) delete fieldConflicts.value[edit.path.join(".")];
  } catch (e) {
    patchError.value =
      e instanceof PatchError ? e.message : "could not apply that change to the document";
  }
}

const formUnavailable = computed(() => {
  if (configSchema.error.value) return "The config schema could not be loaded, so the form is unavailable.";
  if (!configSchema.data.value) return "Loading the config schema...";
  if (parsedDoc.value === null)
    return "The raw text does not parse as YAML, so the form cannot render it. Fix it in the raw editor.";
  return null;
});

async function loadConfig() {
  configLoading.value = true;
  configErr.value = null;
  try {
    const doc = await api.config();
    editorText.value = doc.yaml ?? "";
    editorRev.value = doc.revision ?? "";
  } catch (e) {
    configErr.value = e instanceof ApiError ? e : new ApiError(0, String(e));
  } finally {
    configLoading.value = false;
  }
}

async function saveConfig() {
  if (saveBusy.value || editorLocked.value || !editorText.value.trim()) return;
  if (editorText.value.includes("[REDACTED]")) {
    saveBanner.value = {
      tone: "err",
      text: "Replace every [REDACTED] secret before saving. The editor loaded a redacted copy; submitting those markers would corrupt or reject the file.",
    };
    return;
  }
  saveBusy.value = true;
  saveBanner.value = null;
  try {
    await api.putConfig(editorText.value, editorRev.value || undefined);
    toast.success("Config saved", "Validated and hot-swapped into the live pipeline.");
    saveBanner.value = null;
    await loadConfig(); // pick up the new revision
    fieldConflicts.value = {};
    drift.run();
    effective.run(); // ownership can move with the config
    targetsReq.run();
  } catch (e) {
    // Validation detail and revision conflicts render next to the
    // editor, where the fix happens; anything else raises a toast.
    if (e instanceof ApiError && e.status === 409) {
      // Two different 409s share this status and need opposite advice.
      // A revision mismatch says reload and reapply. An ownership refusal
      // says reapplying will fail exactly the same way, so name the paths
      // and where they are actually set.
      let conflict: ConfigWriteConflict | null = null;
      try {
        conflict = JSON.parse(e.body) as ConfigWriteConflict;
      } catch {
        // non-JSON body; fall through to the revision-mismatch wording
      }
      if (conflict?.code === "config_not_locally_owned") {
        const paths = (conflict.conflicts ?? []).map((c) => c.path);
        // Attach the rejection to the fields it names, so the form shows it
        // where the fix is rather than only in a banner.
        fieldConflicts.value = conflictsByPath(conflict.conflicts);
        saveBanner.value = {
          tone: "err",
          text: [
            paths.length === 1
              ? `This node does not own ${paths[0]}.`
              : `This node does not own these paths: ${paths.join(", ")}.`,
            conflict.remedy ?? "",
          ]
            .filter(Boolean)
            .join(" "),
        };
        effective.run(); // the layers may have moved since the page loaded
      } else if (conflict?.code === "config_ownership_unknown") {
        saveBanner.value = {
          tone: "err",
          text:
            conflict.error ??
            "Could not determine which paths this node owns, so the write was refused.",
        };
      } else {
        saveBanner.value = {
          tone: "err",
          text: "Revision mismatch: the on-disk config changed since you loaded it. Reload the editor and reapply your edits.",
        };
      }
    } else if (e instanceof ApiError && e.status === 400) {
      let detail = e.body;
      try {
        detail = JSON.parse(e.body).error ?? e.body;
      } catch {
        // non-JSON body; show it raw
      }
      saveBanner.value = { tone: "err", text: detail || "Invalid config." };
    } else {
      toast.error(e, "Save config");
    }
  } finally {
    saveBusy.value = false;
  }
}

// ---- openapi summary ----
const showRawSpec = ref(false);

const specInfo = computed(() => {
  const s = openapi.data.value as any;
  return {
    title: s?.info?.title ?? "OpenAPI",
    version: s?.info?.version ?? "",
    openapi: s?.openapi ?? "",
  };
});

const servers = computed<string[]>(() => {
  const s = openapi.data.value as any;
  const arr = Array.isArray(s?.servers) ? s.servers : [];
  return arr.map((x: any) => x?.url ?? String(x)).filter(Boolean);
});

const paths = computed(() => {
  const s = openapi.data.value as any;
  const p = s?.paths;
  if (!p || typeof p !== "object") return [];
  return Object.entries(p).map(([path, ops]) => ({
    path,
    methods: ops && typeof ops === "object"
      ? Object.keys(ops as object)
          .filter((m) => ["get", "post", "put", "patch", "delete", "head", "options"].includes(m.toLowerCase()))
          .map((m) => m.toUpperCase())
      : [],
  }));
});

const rawSpec = computed(() => JSON.stringify(openapi.data.value ?? {}, null, 2));

// ---- drift ----
const driftInSync = computed<boolean | null>(() => {
  const d = drift.data.value as any;
  if (!d) return null;
  // Real server shape (GET /admin/drift): a `drift` boolean, true = drifted.
  if (typeof d.drift === "boolean") return !d.drift;
  if (typeof d.in_sync === "boolean") return d.in_sync;
  if (typeof d.drifted === "boolean") return !d.drifted;
  // Empty diff / no changes implies in sync.
  if (typeof d.diff === "string") return d.diff.trim().length === 0;
  if (Array.isArray(d.changes)) return d.changes.length === 0;
  return null;
});

const driftDetail = computed(() => {
  const d = drift.data.value as any;
  if (!d) return "";
  // Real server shape: loaded vs on-disk content hashes plus context.
  if (d.loaded_content_hash !== undefined || d.on_disk_content_hash !== undefined) {
    return JSON.stringify(
      {
        config_path: d.config_path,
        loaded_revision: d.loaded_revision,
        loaded_content_hash: d.loaded_content_hash,
        on_disk_content_hash: d.on_disk_content_hash,
        on_disk_size_bytes: d.on_disk_size_bytes,
        checked_at: d.checked_at,
      },
      null,
      2,
    );
  }
  if (typeof d.diff === "string" && d.diff.trim()) return d.diff;
  if (Array.isArray(d.changes) && d.changes.length) {
    return d.changes.map((c: unknown) => JSON.stringify(c)).join("\n");
  }
  // Fall back to showing on-disk vs loaded if present.
  if (d.on_disk !== undefined || d.loaded !== undefined) {
    return JSON.stringify({ on_disk: d.on_disk, loaded: d.loaded }, null, 2);
  }
  return "";
});

// ---- targets ----
const targets = computed<TargetHealth[]>(() =>
  asList<TargetHealth>(targetsReq.data.value, "targets", "items", "data"),
);

function targetHealthy(t: TargetHealth): string {
  if (typeof t.healthy === "boolean") return t.healthy ? "healthy" : "unhealthy";
  return String(t.status ?? "unknown");
}

// ---- reload ----
const reloadBusy = ref(false);

async function reload() {
  if (!confirm("Reload configuration from disk? Active config will be replaced by the on-disk version.")) {
    return;
  }
  reloadBusy.value = true;
  try {
    await api.reload();
    toast.success("Config reloaded", "Refreshing drift and targets.");
    drift.run();
    targetsReq.run();
  } catch (e) {
    toast.error(e, "Reload config");
  } finally {
    reloadBusy.value = false;
  }
}

// ---- config history (WOR-2456/2457) ----
//
// The applied/good/failed/reverted timeline behind the LKG rollback
// store. Opt-in (proxy.config_history.enabled), so a 404 here is read
// through isConfigHistoryDisabled rather than surfaced as an error: the
// common case is a node that never turned the feature on.
const historyEntries = computed<ConfigHistoryEntry[]>(
  () => configHistory.data.value?.entries ?? [],
);
const historyLineage = computed(() => configHistory.data.value?.lineage);
const historyLkgRevision = computed(() => configHistory.data.value?.lkg_revision ?? null);
const historyDisabled = computed(() => isConfigHistoryDisabled(configHistory.error.value));

// Selecting a row loads its detail (document + rendered plan diff) on
// demand rather than up front: the plan render is a diff against the
// live config, computed server-side per digest, and most rows in a long
// history are never opened.
const selectedDigest = ref<string | null>(null);
const historyDetail = ref<ConfigHistoryDetail | null>(null);
const historyDetailLoading = ref(false);
const historyDetailError = ref<ApiError | null>(null);

function selectHistoryEntry(entry: ConfigHistoryEntry) {
  if (selectedDigest.value === entry.digest) {
    selectedDigest.value = null;
    historyDetail.value = null;
    historyDetailError.value = null;
    return;
  }
  selectedDigest.value = entry.digest;
  void loadHistoryDetail(entry);
}

// Split from selectHistoryEntry so the detail row's retry button re-fetches
// instead of toggling the row shut: retry calls this directly, a row click
// goes through the toggle above.
async function loadHistoryDetail(entry: ConfigHistoryEntry) {
  historyDetail.value = null;
  historyDetailError.value = null;
  historyDetailLoading.value = true;
  try {
    historyDetail.value = await api.configHistoryEntry(entry.digest);
  } catch (e) {
    historyDetailError.value = e instanceof ApiError ? e : new ApiError(0, String(e));
  } finally {
    historyDetailLoading.value = false;
  }
}
</script>

<template>
  <PageHeader
    title="Config"
    subtitle="The running configuration: emitted OpenAPI surface, on-disk drift, and per-target health."
  >
    <template #actions>
      <button class="sb-btn" @click="refresh">Refresh</button>
      <button class="sb-btn sb-btn--primary" :disabled="reloadBusy" @click="reload">
        {{ reloadBusy ? "Reloading..." : "Reload config" }}
      </button>
    </template>
  </PageHeader>


  <!-- Where this node's configuration comes from -->
  <section class="section" v-if="ownership">
    <div class="section__head">
      <h2>Configuration source</h2>
      <StatusBadge
        :tone="ownership.locallyOwned ? 'ok' : 'warn'"
        :label="ownership.locallyOwned ? 'Local' : 'Managed elsewhere'"
      />
      <button class="sb-btn sb-btn--sm" :disabled="effective.loading.value" @click="effective.run">
        {{ effective.loading.value ? "Checking..." : "Recheck" }}
      </button>
    </div>
    <div class="sb-card">
      <p>{{ ownerSummary }}</p>
      <dl class="owner-grid">
        <template v-if="ownership.base?.kind === 'git'">
          <dt>Repository</dt>
          <dd class="sb-mono">{{ ownership.base.repo }}</dd>
          <dt>Reference</dt>
          <dd class="sb-mono">{{ ownership.base.reference }}</dd>
          <dt>Commit</dt>
          <dd class="sb-mono">{{ ownership.base.commit }}</dd>
        </template>
        <template v-if="ownership.authority">
          <dt>Authority</dt>
          <dd class="sb-mono">{{ ownership.authority.authority_id }}</dd>
          <dt>Revision applied</dt>
          <dd class="sb-mono">{{ ownership.authority.revision }}</dd>
          <dt>Merge mode</dt>
          <dd class="sb-mono">{{ ownership.authority.mode }}</dd>
        </template>
        <dt>Settings this node owns</dt>
        <dd class="sb-mono">{{ ownership.localLeaves }} of {{ ownership.totalLeaves }}</dd>
      </dl>
      <details class="owned-elsewhere" v-if="notOwnedHere.length">
        <summary>
          {{ notOwnedHere.length }} setting{{ notOwnedHere.length === 1 ? "" : "s" }}
          set outside this node
        </summary>
        <table>
          <tbody>
            <tr v-for="row in notOwnedHere" :key="row.path">
              <td class="sb-mono">{{ row.path }}</td>
              <td class="sb-faint">{{ provenanceLabel(row.owner) }}</td>
            </tr>
          </tbody>
        </table>
      </details>
    </div>
  </section>

  <!-- Live config editor -->
  <section class="section">
    <div class="section__head">
      <h2>Edit configuration</h2>
      <span class="sb-faint sb-mono" v-if="editorRev">rev {{ editorRev.slice(0, 12) }}</span>
      <button class="sb-btn sb-btn--sm" :disabled="configLoading" @click="loadConfig">
        {{ configLoading ? "Loading..." : "Reload editor" }}
      </button>
    </div>
    <ErrorState v-if="configErr" :error="configErr" @retry="loadConfig" />
    <div v-else class="sb-card">
      <p class="banner banner--warn" v-if="editorLocked">
        This node does not own its configuration, so editing it here would have
        no effect. {{ ownerSummary }} Change it at the source and this node
        will pick it up on its next refresh. The file below is shown read-only;
        on a git-sourced node it may be nothing but the pointer that selected
        the repository.
      </p>
      <p class="banner" v-if="saveBanner" :class="`banner--${saveBanner.tone}`">
        {{ saveBanner.text }}
      </p>
      <p class="banner banner--err" v-if="patchError">{{ patchError }}</p>

      <div class="mode-switch" role="tablist" aria-label="Editor mode">
        <button
          class="sb-btn sb-btn--sm"
          role="tab"
          :aria-selected="mode === 'form'"
          :class="{ 'sb-btn--primary': mode === 'form' }"
          @click="mode = 'form'"
        >
          Form
        </button>
        <button
          class="sb-btn sb-btn--sm"
          role="tab"
          :aria-selected="mode === 'raw'"
          :class="{ 'sb-btn--primary': mode === 'raw' }"
          @click="mode = 'raw'"
        >
          Raw YAML
        </button>
        <span class="sb-faint">
          Both views edit the same document, so switching never loses an edit.
        </span>
      </div>

      <div v-if="mode === 'form'">
        <p class="sb-faint" v-if="formUnavailable">{{ formUnavailable }}</p>
        <ConfigForm
          v-else
          :nodes="formNodes"
          :doc="parsedDoc"
          :ownership="formOwnership"
          :conflicts="fieldConflicts"
          @set="onFormSet"
          @remove="onFormRemove"
        />
      </div>

      <textarea
        v-show="mode === 'raw'"
        v-model="editorText"
        class="sb-input editor"
        spellcheck="false"
        :readonly="editorLocked"
        aria-label="Configuration YAML"
      ></textarea>
      <div class="editor-actions">
        <button
          class="sb-btn sb-btn--primary"
          :disabled="saveBusy || editorLocked || !editorText.trim()"
          @click="saveConfig"
        >
          {{ saveBusy ? "Saving..." : "Validate + save" }}
        </button>
        <span class="sb-faint" v-if="editorLocked">
          Writes are refused by the server, not just hidden here. The same
          request from curl gets the same answer.
        </span>
        <span class="sb-faint" v-else>
          Validated server-side, then hot-swapped. Optimistic concurrency by revision;
          a mismatch means the on-disk config changed under you.
        </span>
      </div>
    </div>
  </section>

  <!-- Config history -->
  <section class="section">
    <div class="section__head">
      <h2>Config history</h2>
      <span class="sb-faint sb-mono" v-if="historyLineage">
        lineage {{ shortId(historyLineage) }}
      </span>
      <span class="sb-faint sb-mono" v-if="historyLkgRevision !== null">
        lkg rev {{ historyLkgRevision }}
      </span>
      <button class="sb-btn sb-btn--sm" :disabled="configHistory.loading.value" @click="configHistory.run">
        {{ configHistory.loading.value ? "Loading..." : "Refresh" }}
      </button>
    </div>
    <EmptyState
      v-if="historyDisabled"
      message="Config history is not enabled on this node. Set proxy.config_history.enabled to turn on the applied/good/failed/reverted timeline behind rollback."
    />
    <ErrorState
      v-else-if="configHistory.error.value"
      :error="configHistory.error.value"
      @retry="configHistory.run"
    />
    <EmptyState v-else-if="!historyEntries.length && !configHistory.loading.value" message="No config history recorded yet." />
    <div class="table-wrap" v-else>
      <table class="sb-table">
        <thead>
          <tr>
            <th>Revision</th>
            <th>State</th>
            <th>Blast radius</th>
            <th>Provenance</th>
            <th>Applied</th>
            <th>Actor</th>
          </tr>
        </thead>
        <tbody>
          <template v-for="entry in historyEntries" :key="entry.digest">
            <tr
              class="history-row"
              :class="{ 'history-row--active': selectedDigest === entry.digest }"
              @click="selectHistoryEntry(entry)"
            >
              <td class="sb-mono">{{ entry.revision }}</td>
              <td>
                <StatusBadge :label="entry.state" :tone="historyStateTone(entry.state)" />
                <StatusBadge v-if="entry.degraded.length" label="degraded" tone="warn" />
                <div v-if="entry.degraded.length" class="sb-faint history-degraded">
                  {{ degradedSummary(entry.degraded) }}
                </div>
              </td>
              <td>
                <StatusBadge
                  :label="blastRadiusLabel(entry.blast_radius)"
                  :tone="blastRadiusTone(entry.blast_radius)"
                />
              </td>
              <td class="sb-mono">{{ entry.provenance }}</td>
              <td class="sb-muted" :title="entry.applied_at">{{ formatTime(entry.applied_at) }}</td>
              <td class="sb-mono">{{ entry.actor || "n/a" }}</td>
            </tr>
            <tr v-if="selectedDigest === entry.digest" class="history-detail-row">
              <td colspan="6">
                <div class="history-detail">
                  <p v-if="historyDetailLoading" class="sb-faint">Loading plan...</p>
                  <ErrorState
                    v-else-if="historyDetailError"
                    :error="historyDetailError"
                    @retry="loadHistoryDetail(entry)"
                  />
                  <template v-else-if="historyDetail">
                    <p class="sb-faint sb-mono">digest {{ entry.digest }}</p>
                    <pre class="sb-code">{{ historyDetail.plan_text }}</pre>
                  </template>
                </div>
              </td>
            </tr>
          </template>
        </tbody>
      </table>
    </div>
  </section>

  <!-- Drift -->
  <section class="section">
    <div class="section__head">
      <h2>Configuration drift</h2>
      <StatusBadge
        v-if="driftInSync !== null"
        :label="driftInSync ? 'in sync' : 'drifted'"
        :tone="driftInSync ? 'ok' : 'warn'"
      />
    </div>
    <ErrorState v-if="drift.error.value" :error="drift.error.value" @retry="drift.run" />
    <div v-else class="sb-card">
      <p class="sb-muted" v-if="driftInSync === true">
        The on-disk configuration matches what is loaded in memory.
      </p>
      <p class="sb-muted" v-else-if="driftInSync === false">
        The on-disk configuration differs from what is loaded. Reload to apply the on-disk version.
      </p>
      <p class="sb-faint" v-else>Drift state could not be determined from the response.</p>
      <pre class="sb-code" v-if="driftDetail" style="margin-top: 12px">{{ driftDetail }}</pre>
    </div>
  </section>

  <!-- OpenAPI -->
  <section class="section">
    <div class="section__head">
      <h2>OpenAPI surface</h2>
      <button class="sb-btn sb-btn--sm" @click="showRawSpec = !showRawSpec">
        {{ showRawSpec ? "Hide raw JSON" : "View raw JSON" }}
      </button>
    </div>
    <ErrorState v-if="openapi.error.value" :error="openapi.error.value" @retry="openapi.run" />
    <template v-else>
      <div class="sb-card" style="margin-bottom: 16px">
        <div class="meta-row">
          <span><strong>{{ specInfo.title }}</strong></span>
          <span class="sb-faint" v-if="specInfo.version">v{{ specInfo.version }}</span>
          <span class="sb-faint" v-if="specInfo.openapi">OpenAPI {{ specInfo.openapi }}</span>
        </div>
        <div class="origins" v-if="servers.length">
          <span class="sb-eyebrow">Origins</span>
          <div class="tags">
            <span class="tag sb-mono" v-for="s in servers" :key="s">{{ s }}</span>
          </div>
        </div>
      </div>

      <pre class="sb-code" v-if="showRawSpec">{{ rawSpec }}</pre>

      <EmptyState v-else-if="!paths.length" message="No paths in the emitted spec." />
      <div class="table-wrap" v-else>
        <table class="sb-table">
          <thead>
            <tr>
              <th>Path</th>
              <th>Methods</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="p in paths" :key="p.path">
              <td class="sb-mono">{{ p.path }}</td>
              <td>
                <span class="method" v-for="m in p.methods" :key="m">{{ m }}</span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </template>
  </section>

  <!-- Targets -->
  <section class="section">
    <h2>Target health</h2>
    <ErrorState v-if="targetsReq.error.value" :error="targetsReq.error.value" @retry="targetsReq.run" />
    <EmptyState v-else-if="!targets.length" message="No upstream targets reported." />
    <div class="table-wrap" v-else>
      <table class="sb-table">
        <thead>
          <tr>
            <th>Target</th>
            <th>Health</th>
            <th>Breaker</th>
            <th>Latency</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="(t, i) in targets" :key="i">
            <td class="sb-mono">{{ t.name ?? t.target ?? t.url ?? "unknown" }}</td>
            <td><StatusBadge :label="targetHealthy(t)" /></td>
            <td>
              <StatusBadge
                v-if="t.breaker ?? t.breaker_state"
                :label="String(t.breaker ?? t.breaker_state)"
              />
              <span class="sb-faint" v-else>n/a</span>
            </td>
            <td>{{ formatMs(t.latency_ms) }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </section>
</template>

<style scoped>
.section {
  margin-bottom: var(--sb-space-6);
}
.section h2 {
  margin-bottom: var(--sb-space-4);
}
.section__head {
  display: flex;
  align-items: center;
  gap: var(--sb-space-3);
  margin-bottom: var(--sb-space-4);
}
.section__head h2 {
  margin-bottom: 0;
}
.meta-row {
  display: flex;
  gap: var(--sb-space-4);
  align-items: baseline;
  flex-wrap: wrap;
}
.origins {
  margin-top: var(--sb-space-4);
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.tags {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}
.tag {
  font-size: 0.78rem;
  padding: 2px 10px;
  border-radius: var(--sb-radius-pill);
  background: var(--sb-surface-2);
  color: var(--sb-text-muted);
  border: 1px solid var(--sb-border);
}
.table-wrap {
  border: 1px solid var(--sb-border);
  border-radius: var(--sb-radius);
  overflow-x: auto;
}
.history-row {
  cursor: pointer;
}
.history-row:hover {
  background: var(--sb-surface-hover);
}
.history-row--active {
  background: var(--sb-surface-hover);
}
.history-degraded {
  font-size: 0.78rem;
  margin-top: 2px;
}
.history-detail-row td {
  padding: 0;
}
.history-detail {
  padding: var(--sb-space-4);
  border-top: 1px dashed var(--sb-border);
}
.history-detail .sb-code {
  margin-top: var(--sb-space-2);
}
.method {
  display: inline-block;
  font-family: var(--sb-font-mono);
  font-size: 0.72rem;
  font-weight: 600;
  padding: 1px 7px;
  margin-right: 4px;
  border-radius: var(--sb-radius-sm);
  background: var(--sb-accent-tint);
  color: var(--sb-accent);
}
.editor {
  width: 100%;
  min-height: 340px;
  font-family: var(--sb-font-mono);
  font-size: 0.82rem;
  line-height: 1.5;
  resize: vertical;
  white-space: pre;
  overflow-wrap: normal;
  overflow-x: auto;
}
.editor-actions {
  display: flex;
  align-items: center;
  gap: var(--sb-space-3);
  margin-top: var(--sb-space-3);
  flex-wrap: wrap;
}
.banner {
  padding: var(--sb-space-3) var(--sb-space-4);
  border-radius: var(--sb-radius-sm);
  margin-bottom: var(--sb-space-3);
  font-size: 0.9rem;
}
.banner--ok {
  background: var(--sb-accent-tint);
  color: var(--sb-accent);
}
.banner--err {
  background: #fdecea;
  color: #c0392b;
}
.banner--warn {
  background: #fdf3e0;
  color: #8a5a12;
}
.mode-switch {
  display: flex;
  align-items: center;
  gap: var(--sb-space-2);
  margin-bottom: var(--sb-space-3);
  flex-wrap: wrap;
}
.owner-grid {
  display: grid;
  grid-template-columns: auto 1fr;
  gap: var(--sb-space-2) var(--sb-space-4);
  margin: var(--sb-space-3) 0 0;
}
.owner-grid dt {
  color: var(--sb-text-faint);
}
.owner-grid dd {
  margin: 0;
  overflow-wrap: anywhere;
}
.owned-elsewhere {
  margin-top: var(--sb-space-3);
}
.owned-elsewhere summary {
  cursor: pointer;
  color: var(--sb-text-faint);
  font-size: 0.9rem;
}
.owned-elsewhere table {
  width: 100%;
  margin-top: var(--sb-space-2);
  border-collapse: collapse;
  font-size: 0.85rem;
}
.owned-elsewhere td {
  padding: 0.2rem 0.5rem 0.2rem 0;
  vertical-align: top;
}
</style>
