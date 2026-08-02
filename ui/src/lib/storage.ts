/*
 * Pure helpers for the Storage view (WOR-1910): display rows for the
 * verified artifact cache inventory, delete-refusal reasons, and cache
 * GC result text. Kept free of Vue so the row derivation and the
 * error-shaping logic stay unit testable against fixture JSON.
 */

import type { GcReport, ModelHostFilesResponse } from "../api";
import { formatBytes } from "./format";

/** One artifact row the Storage table renders. */
export interface StorageArtifactRow {
  model: string;
  variant: string;
  digest: string;
  digestShort: string;
  sizeBytes: number;
  lastAccessedMs: number;
  resident: boolean;
}

/** Short display form of a content digest, keeping any algorithm prefix. */
export function shortDigest(digest: string): string {
  const separator = digest.indexOf(":");
  if (separator === -1) {
    return digest.length <= 12 ? digest : digest.slice(0, 12);
  }
  const algorithm = digest.slice(0, separator);
  const hex = digest.slice(separator + 1);
  return hex.length <= 12 ? digest : `${algorithm}:${hex.slice(0, 12)}`;
}

/**
 * Stable display rows from GET /admin/model-host/files, sorted by model,
 * then variant, then digest so refreshes never reorder the table.
 */
export function storageRows(
  files: ModelHostFilesResponse | null,
): StorageArtifactRow[] {
  if (!files) return [];
  return files.artifacts
    .map((artifact) => ({
      model: artifact.logical_model,
      variant: artifact.variant_id,
      digest: artifact.artifact_digest,
      digestShort: shortDigest(artifact.artifact_digest),
      sizeBytes: artifact.total_size_bytes,
      lastAccessedMs: artifact.last_accessed_ms,
      resident: artifact.resident,
    }))
    .sort(
      (left, right) =>
        left.model.localeCompare(right.model) ||
        left.variant.localeCompare(right.variant) ||
        left.digest.localeCompare(right.digest),
    );
}

interface AdminErrorBody {
  code?: unknown;
  error?: unknown;
}

function parseErrorBody(body: string): AdminErrorBody | null {
  try {
    const parsed: unknown = JSON.parse(body);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return parsed as AdminErrorBody;
    }
  } catch {
    // Not JSON; the caller falls back to bounded default text.
  }
  return null;
}

/**
 * Human refusal reason from a DELETE /admin/model-host/artifacts 409
 * body. The server fails closed with `{code, error}`; the `error` string
 * is the operator-facing reason. Falls back to bounded text when the
 * body is not the expected shape.
 */
export function deleteRefusalReason(body: string): string {
  const parsed = parseErrorBody(body);
  if (parsed && typeof parsed.error === "string" && parsed.error.length > 0) {
    return parsed.error;
  }
  return "The server refused to delete this artifact.";
}

const NO_BUDGET_FALLBACK =
  "No cache budget is configured (model_host.cache_budget_gib), so GC has nothing to enforce.";

/**
 * Reason cache GC is unavailable when a POST /admin/model-host/gc error
 * reports that no budget is configured. Returns null for every other
 * failure so transient errors do not disable the button.
 */
export function gcUnavailableReason(body: string): string | null {
  const parsed = parseErrorBody(body);
  if (
    parsed &&
    typeof parsed.code === "string" &&
    parsed.code.includes("budget")
  ) {
    return typeof parsed.error === "string" && parsed.error.length > 0
      ? parsed.error
      : NO_BUDGET_FALLBACK;
  }
  return null;
}

/**
 * Reason cache GC is unavailable when the files report itself says no
 * budget is configured (an explicit `cache_budget_bytes: null`). Servers
 * that omit the field report unavailability through the GC route instead.
 */
export function gcBudgetAbsentReason(
  files: ModelHostFilesResponse | null,
): string | null {
  if (
    files &&
    Object.hasOwn(files, "cache_budget_bytes") &&
    files.cache_budget_bytes === null
  ) {
    return NO_BUDGET_FALLBACK;
  }
  return null;
}

/** One-line reclaimed / before / after summary of a GC run. */
export function gcSummary(report: GcReport): string {
  return `Reclaimed ${formatBytes(report.reclaimed_bytes)} (${formatBytes(
    report.before_bytes,
  )} before, ${formatBytes(report.after_bytes)} after).`;
}
