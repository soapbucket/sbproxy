import type {
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
