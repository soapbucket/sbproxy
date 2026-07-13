import { computed, onMounted, ref } from "vue";
import {
  api,
  ApiError,
  type ClusterDeploymentAuthority,
  type DeploymentRuntimeStatus,
  type ModelDeployment,
} from "../api";
import { useAsync } from "./useAsync";
import {
  applyDeploymentChange,
  buildDeploymentMutation,
  createDeploymentConflictState,
  deployableCatalogEntries,
  deployableCatalogVariants,
  deploymentMutationMode,
  deploymentRemovalGuard,
  deploymentRows,
  nextClusterRevision,
  type DeploymentChange,
  type DeploymentConflictState,
  type DeploymentFormValue,
  type ModelDeploymentRow,
} from "../lib/model-management";
import { findFamily, histogramAvgByLabel, parsePrometheus } from "../lib/metrics";

export interface ModelDeploymentEditorState {
  originalDeploymentId: string | null;
  initialDeployment: ModelDeployment | null;
}

export function useModelManagement() {
  const statusReq = useAsync(() => api.modelHostStatus());
  const catalogReq = useAsync(() => api.modelHostCatalog());
  const deploymentsReq = useAsync(() => api.modelHostDeployments());
  const clusterStatusReq = useAsync(() => api.clusterStatus());
  const clusterBundleReq = useAsync(() => api.clusterDeployments());
  const metricsReq = useAsync(() => api.metrics());

  const banner = ref<{ tone: "ok" | "warn" | "err"; text: string } | null>(null);
  const lifecycleBusy = ref("");
  const mutationBusy = ref(false);
  const mutationError = ref<string | null>(null);
  const conflict = ref<DeploymentConflictState | null>(null);
  const pendingConflictChange = ref<DeploymentChange | null>(null);
  const editor = ref<ModelDeploymentEditorState | null>(null);

  function refresh() {
    void statusReq.run();
    void catalogReq.run();
    void deploymentsReq.run();
    void clusterStatusReq.run();
    void clusterBundleReq.run();
    void metricsReq.run();
  }

  onMounted(refresh);

  const status = computed(() => statusReq.data.value);
  const catalog = computed(() => catalogReq.data.value);
  const deploymentDocument = computed(() => deploymentsReq.data.value);
  const clusterBundle = computed(() => clusterBundleReq.data.value);
  const clusterAuthority = computed<ClusterDeploymentAuthority | null>(
    () => clusterStatusReq.data.value?.deployment_authority ?? null,
  );
  const runtimeDeployments = computed<DeploymentRuntimeStatus[]>(
    () => status.value?.deployments ?? [],
  );
  const rows = computed(() =>
    deploymentRows(
      deploymentDocument.value?.deployments ?? null,
      runtimeDeployments.value,
    ),
  );
  const readyDeployments = computed(
    () => runtimeDeployments.value.filter((runtime) => runtime.state === "ready").length,
  );
  const reservedMemory = computed(() =>
    runtimeDeployments.value.reduce(
      (total, runtime) => total + (runtime.memory?.total_bytes ?? 0),
      0,
    ),
  );
  const blockers = computed(() =>
    status.value?.local_serving?.ready === false
      ? status.value.local_serving.blockers ?? []
      : [],
  );

  const catalogModels = computed(() =>
    catalog.value ? deployableCatalogEntries(catalog.value) : [],
  );
  const previewOnlyCatalog = computed(
    () =>
      catalogModels.value.length > 0 &&
      catalogModels.value.every(({ entry }) =>
        deployableCatalogVariants(entry).every(
          (variant) => variant.stability === "preview",
        ),
      ),
  );

  const throughputByModel = computed<Record<string, number>>(() => {
    const text = metricsReq.data.value;
    if (!text) return {};
    const values = histogramAvgByLabel(
      findFamily(
        parsePrometheus(text),
        "sbproxy_ai_output_throughput_tokens_per_second",
      ),
      "model",
    );
    return Object.fromEntries(values.map((value) => [value.key, value.value]));
  });

  const mutationMode = computed(() =>
    deploymentDocument.value
      ? deploymentMutationMode(deploymentDocument.value, clusterAuthority.value)
      : "read_only",
  );
  const hasSafeClusterRevision = computed(
    () =>
      mutationMode.value !== "signed_cluster_post" ||
      nextClusterRevision(clusterAuthority.value?.active_revision ?? null) !== null,
  );
  const clusterBundleAllowsPublication = computed(() => {
    if (deploymentDocument.value?.authority !== "cluster_authority") return true;
    if (clusterBundle.value) return !clusterBundle.value.read_only;
    if (clusterBundleReq.error.value?.status === 404) {
      return clusterAuthority.value?.active_revision === null;
    }
    return false;
  });
  const canMutate = computed(
    () =>
      Boolean(deploymentDocument.value) &&
      Boolean(catalog.value) &&
      catalogModels.value.length > 0 &&
      mutationMode.value !== "read_only" &&
      hasSafeClusterRevision.value &&
      clusterBundleAllowsPublication.value,
  );

  const persistentGuidance = computed(() => {
    const document = deploymentDocument.value;
    if (!document) {
      return "Deployment ownership is unavailable. Retry desired state before making persistent changes.";
    }
    if (document.authority === "file_managed") {
      return "Persistent changes are read-only here. Edit proxy.model_host.deployments in sb.yml, then reload SBproxy.";
    }
    if (document.authority === "cluster_authority") {
      if (clusterStatusReq.error.value || !clusterAuthority.value) {
        return "Persistent changes are read-only until this node can verify cluster deployment authority state.";
      }
      if (clusterAuthority.value.read_only || !clusterAuthority.value.configured) {
        return "Persistent changes are read-only on this node. Open this view on the configured authority node to publish a signed deployment revision.";
      }
      if (!clusterBundleAllowsPublication.value) {
        return "Persistent changes are paused until the active signed deployment bundle can be verified on this authority node.";
      }
      if (!hasSafeClusterRevision.value) {
        return "The active cluster revision cannot be advanced safely in this browser. Use an authority workflow that preserves the full revision integer.";
      }
    }
    if (document.read_only) {
      return "Persistent changes are read-only on this node. Use the admin-managed node that owns the deployment store.";
    }
    if (!catalog.value) {
      return "Persistent changes are paused until the active model catalog is available.";
    }
    if (catalogModels.value.length === 0) {
      return "Persistent changes are paused because the active catalog has no exact variants with both engines and accelerators.";
    }
    return null;
  });

  const authorityDescription = computed(() => {
    const document = deploymentDocument.value;
    if (!document) return "Desired-state ownership could not be loaded.";
    if (document.authority === "file_managed") {
      return "SBproxy configuration owns the complete deployment map.";
    }
    if (document.authority === "admin_managed") {
      return "This node's versioned admin store owns the complete deployment map.";
    }
    return clusterAuthority.value?.read_only
      ? "This node verifies signed deployment revisions published by the cluster authority."
      : "This authority node signs and publishes complete deployment revisions.";
  });

  const refreshing = computed(
    () =>
      statusReq.loading.value ||
      catalogReq.loading.value ||
      deploymentsReq.loading.value ||
      clusterStatusReq.loading.value,
  );

  function errorText(error: unknown): string {
    if (error instanceof ApiError) {
      if (error.body) {
        try {
          const body = JSON.parse(error.body) as { error?: unknown };
          if (typeof body.error === "string") return body.error;
        } catch {
          // Fall back to the bounded transport hint.
        }
      }
      return error.hint;
    }
    return error instanceof Error ? error.message : "The operation failed.";
  }

  function currentPersistentRevision(): number | null {
    if (mutationMode.value === "signed_cluster_post") {
      return clusterAuthority.value?.active_revision ?? null;
    }
    return deploymentDocument.value?.revision ?? null;
  }

  async function reloadPersistentState() {
    await Promise.all([
      deploymentsReq.run(),
      clusterStatusReq.run(),
      clusterBundleReq.run(),
    ]);
  }

  async function mutateDesiredState(change: DeploymentChange) {
    if (mutationBusy.value) return;
    const document = deploymentDocument.value;
    const activeCatalog = catalog.value;
    if (!document || !activeCatalog || !canMutate.value) {
      mutationError.value = persistentGuidance.value ?? "Persistent mutation is unavailable.";
      return;
    }

    const attempted = applyDeploymentChange(document.deployments, change);
    const command = buildDeploymentMutation({
      document,
      clusterAuthority: clusterAuthority.value,
      catalogRevision: activeCatalog.catalog_revision,
      deployments: attempted,
    });
    if (command.kind === "read_only") {
      mutationError.value = persistentGuidance.value ?? "Persistent desired state is read-only.";
      return;
    }
    if (command.kind === "unsafe_revision") {
      mutationError.value =
        "The active cluster revision cannot be advanced safely in this browser.";
      return;
    }

    const expectedRevision =
      command.kind === "local_put"
        ? command.request.expected_revision
        : command.draft.revision === 1
          ? null
          : command.draft.revision - 1;
    mutationBusy.value = true;
    mutationError.value = null;
    banner.value = null;
    try {
      if (command.kind === "local_put") {
        await api.replaceModelHostDeployments(command.request);
      } else {
        await api.publishClusterDeployments(command.draft);
      }
      conflict.value = null;
      pendingConflictChange.value = null;
      editor.value = null;
      banner.value = {
        tone: "ok",
        text:
          command.kind === "local_put"
            ? "Desired deployment map saved."
            : "Signed deployment revision published.",
      };
      await Promise.all([
        deploymentsReq.run(),
        statusReq.run(),
        clusterStatusReq.run(),
        clusterBundleReq.run(),
      ]);
    } catch (error) {
      if (error instanceof ApiError && error.status === 409) {
        pendingConflictChange.value = change;
        await reloadPersistentState();
        const current = deploymentDocument.value?.deployments ?? document.deployments;
        conflict.value = createDeploymentConflictState({
          expectedRevision,
          currentRevision: currentPersistentRevision(),
          attemptedDeployments: attempted,
          currentDeployments: current,
        });
        mutationError.value = deploymentsReq.error.value
          ? "A revision conflict occurred. Your draft is preserved, but the current deployment map could not be reloaded. Retry desired state before saving again."
          : "A revision conflict occurred. The current deployment map was reloaded and your draft is preserved for comparison.";
      } else {
        mutationError.value = errorText(error);
      }
    } finally {
      mutationBusy.value = false;
    }
  }

  function openAddDeployment() {
    mutationError.value = null;
    conflict.value = null;
    pendingConflictChange.value = null;
    if (!canMutate.value || !catalog.value) {
      banner.value = {
        tone: "err",
        text: persistentGuidance.value ?? "No deployable catalog entry is available.",
      };
      return;
    }
    editor.value = { originalDeploymentId: null, initialDeployment: null };
  }

  function openEditDeployment(row: ModelDeploymentRow) {
    if (!row.desired || !canMutate.value || !catalog.value) return;
    mutationError.value = null;
    conflict.value = null;
    pendingConflictChange.value = null;
    editor.value = {
      originalDeploymentId: row.deploymentId,
      initialDeployment: row.desired,
    };
  }

  function saveDeployment(value: DeploymentFormValue) {
    const activeEditor = editor.value;
    if (!activeEditor) return;
    void mutateDesiredState({
      kind: "upsert",
      originalDeploymentId: activeEditor.originalDeploymentId,
      deploymentId: value.deploymentId,
      deployment: value.deployment,
    });
  }

  function removeDeployment(row: ModelDeploymentRow) {
    const guard = deploymentRemovalGuard(row.runtime?.state ?? null);
    if (!guard.allowed) {
      banner.value = { tone: "warn", text: guard.reason as string };
      return;
    }
    if (!canMutate.value) {
      banner.value = {
        tone: "err",
        text: persistentGuidance.value ?? "Persistent desired state is read-only.",
      };
      return;
    }
    conflict.value = null;
    pendingConflictChange.value = null;
    void mutateDesiredState({ kind: "remove", deploymentId: row.deploymentId });
  }

  function retryConflict() {
    if (pendingConflictChange.value) {
      void mutateDesiredState(pendingConflictChange.value);
    }
  }

  function dismissConflict() {
    conflict.value = null;
    pendingConflictChange.value = null;
    mutationError.value = null;
  }

  async function runLifecycle(
    action: "load" | "stop" | "reset",
    deploymentId: string,
  ) {
    if (lifecycleBusy.value) return;
    lifecycleBusy.value = `${action}:${deploymentId}`;
    banner.value = null;
    try {
      if (action === "load") await api.modelHostLoad(deploymentId);
      if (action === "stop") await api.modelHostStop(deploymentId);
      if (action === "reset") await api.modelHostReset(deploymentId);
      banner.value = {
        tone: "ok",
        text:
          action === "load"
            ? `Loading ${deploymentId}.`
            : action === "stop"
              ? `Draining and stopping ${deploymentId}.`
              : `Reset ${deploymentId}.`,
      };
      await Promise.all([statusReq.run(), metricsReq.run()]);
    } catch (error) {
      banner.value = { tone: "err", text: errorText(error) };
    } finally {
      lifecycleBusy.value = "";
    }
  }

  function closeEditor() {
    if (mutationBusy.value) return;
    editor.value = null;
    conflict.value = null;
    pendingConflictChange.value = null;
    mutationError.value = null;
  }

  return {
    statusReq,
    catalogReq,
    deploymentsReq,
    clusterStatusReq,
    clusterBundleReq,
    banner,
    lifecycleBusy,
    mutationBusy,
    mutationError,
    conflict,
    editor,
    status,
    catalog,
    deploymentDocument,
    clusterBundle,
    clusterAuthority,
    runtimeDeployments,
    rows,
    readyDeployments,
    reservedMemory,
    blockers,
    catalogModels,
    previewOnlyCatalog,
    throughputByModel,
    canMutate,
    persistentGuidance,
    authorityDescription,
    refreshing,
    refresh,
    openAddDeployment,
    openEditDeployment,
    saveDeployment,
    removeDeployment,
    retryConflict,
    dismissConflict,
    runLifecycle,
    closeEditor,
  };
}
