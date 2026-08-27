import type {
  ExtensionBundleRecord,
  ExtensionHookRecord,
  ExtensionInventorySnapshot,
  ExtensionLoadRecord,
  ExtensionRegistrationSource,
  ExtensionState,
} from "../api";

export type ExtensionStatusTone = "ok" | "warn" | "err" | "info" | "neutral";

export function hooksForBundle(
  snapshot: ExtensionInventorySnapshot,
  bundleId: string,
) {
  return snapshot.hooks.filter((hook) => hook.bundle_id === bundleId);
}

export function sourceLabel(source: ExtensionRegistrationSource): string {
  switch (source) {
    case "link_time":
      return "linked into binary";
    case "directory":
      return "bundle directory";
    case "git":
      return "pinned Git";
  }
}

export function loadLabel(load: ExtensionLoadRecord): string {
  switch (load.status) {
    case "ok":
      return "loaded";
    case "failed":
      return "failed";
    case "degraded":
      return "degraded";
    case "installed":
      return "linked";
    case "unattributed":
      return "not reported";
    default:
      return load.status.replaceAll("_", " ");
  }
}

export function loadTone(load: ExtensionLoadRecord): ExtensionStatusTone {
  return load.status === "ok"
    ? "ok"
    : load.status === "failed" || load.status === "degraded"
      ? "err"
      : "neutral";
}

/**
 * Class list for a bundle's load-evidence paragraph.
 *
 * `/api/extensions` serves a running-mode inventory, and a bundle
 * failure reaches that payload on two separate fields:
 *
 * - `state: "failed"`, which `collect_inventory` derives from a failed
 *   hook (`crates/sbproxy-core/src/extension_inventory.rs`
 *   `derive_bundle_states`, fed by `apply_collision_states` when an
 *   unresolved exclusive collision leaves the match key with no
 *   winner).
 * - `load.status: "degraded"`, which `annotate_inventory`
 *   (`crates/sbproxy-core/src/extension_refresh.rs`) writes on a Git
 *   bundle whose refresh candidate was rejected while the last
 *   verified generation keeps serving.
 *
 * `load.status` alone misses the first and `state` alone misses the
 * second, so the paragraph reads both. Presence of `load.detail` is
 * not a failure signal at all: every Git bundle carries a detail line
 * on every poll, healthy or not (WOR-2684).
 */
export function bundleDetailClass(bundle: ExtensionBundleRecord): string {
  const failed =
    loadTone(bundle.load) === "err" || stateTone(bundle.state) === "err";
  return failed ? "bundle__detail bundle__detail--err" : "bundle__detail";
}

/**
 * Class list for a hook's detail paragraph.
 *
 * A hook carries no load record, so `state` is the whole failure
 * signal: `ExtensionState::Failed` is set by `apply_collision_states`
 * on an unresolved collision and by the loader on a hook that failed
 * to load or validate.
 */
export function hookDetailClass(hook: ExtensionHookRecord): string {
  return stateTone(hook.state) === "err"
    ? "hook__detail hook__detail--err"
    : "hook__detail";
}

export function stateTone(state: ExtensionState): ExtensionStatusTone {
  switch (state) {
    case "active":
      return "ok";
    case "available":
      return "info";
    case "failed":
      return "err";
    case "shadowed":
    case "unconsumed":
      return "warn";
    case "installed":
    case "not_evaluated":
      return "neutral";
  }
}
