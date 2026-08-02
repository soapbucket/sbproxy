import { afterEach, describe, expect, it, vi } from "vitest";

import { api, type GcReport, type ModelHostFilesResponse } from "../api";
import {
  deleteRefusalReason,
  gcBudgetAbsentReason,
  gcSummary,
  gcUnavailableReason,
  shortDigest,
  storageRows,
} from "../lib/storage";
import filesTable from "./ModelFilesTable.vue?raw";
import storageView from "../views/StorageView.vue?raw";

const QWEN_DIGEST =
  "sha256:a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
const LLAMA_DIGEST =
  "sha256:ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";

const FILES_FIXTURE: ModelHostFilesResponse = {
  schema_version: 1,
  cache_root: "/var/lib/sbproxy/models",
  total_bytes: 5_336_870_912,
  artifacts: [
    {
      logical_model: "qwen2.5-0.5b-instruct",
      variant_id: "q4_k_m",
      artifact_digest: QWEN_DIGEST,
      total_size_bytes: 536_870_912,
      last_accessed_ms: 1_752_800_000_000,
      resident: true,
    },
    {
      logical_model: "llama3.1-8b-instruct",
      variant_id: "q4_0",
      artifact_digest: LLAMA_DIGEST,
      total_size_bytes: 4_800_000_000,
      last_accessed_ms: 1_752_700_000_000,
      resident: false,
    },
  ],
};

const GC_FIXTURE: GcReport = {
  before_bytes: 12_884_901_888,
  after_bytes: 11_274_289_152,
  reclaimed_bytes: 1_610_612_736,
  deleted_artifacts: [LLAMA_DIGEST],
  skipped_artifacts: {
    [QWEN_DIGEST]: "backs the ready replica of deployment local-qwen",
  },
  budget_unsatisfied_bytes: 0,
};

function stubFetch(rawBody: string, status = 200) {
  const fetchMock = vi.fn(
    async (_input: RequestInfo | URL, _init?: RequestInit) =>
      new Response(rawBody, {
        status,
        headers: { "content-type": "application/json" },
      }),
  );
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("storage rows from the files report", () => {
  it("derives sorted display rows from fixture JSON", () => {
    const rows = storageRows(FILES_FIXTURE);

    expect(rows).toHaveLength(2);
    // Sorted by model, so the llama artifact leads despite arriving second.
    expect(rows[0]).toMatchObject({
      model: "llama3.1-8b-instruct",
      variant: "q4_0",
      digest: LLAMA_DIGEST,
      sizeBytes: 4_800_000_000,
      lastAccessedMs: 1_752_700_000_000,
      resident: false,
    });
    expect(rows[1]).toMatchObject({
      model: "qwen2.5-0.5b-instruct",
      variant: "q4_k_m",
      digest: QWEN_DIGEST,
      resident: true,
    });
    expect(rows[1].digestShort).toBe("sha256:a1b2c3d4e5f6");
    expect(storageRows(null)).toEqual([]);
  });

  it("keeps the algorithm prefix in the short digest form", () => {
    expect(shortDigest(QWEN_DIGEST)).toBe("sha256:a1b2c3d4e5f6");
    expect(shortDigest("sha256:abc")).toBe("sha256:abc");
    expect(shortDigest("plainshortid")).toBe("plainshortid");
  });

  it("renders every column with row headers and wrap-safe machine values", () => {
    for (const column of [
      "Model",
      "Variant",
      "Digest",
      "Size",
      "Last accessed",
      "Residency",
      "Actions",
    ]) {
      expect(filesTable).toContain(`<th>${column}</th>`);
    }
    expect(filesTable).toContain('<th scope="row">');
    expect(filesTable).toContain("min-width: 0");
    expect(filesTable).toContain("overflow-wrap: anywhere");
    expect(filesTable).toContain("row.resident ? 'Resident' : 'On disk'");
    expect(storageView).toContain("files.total_bytes");
    expect(storageView).toContain("files.cache_root");
  });
});

describe("artifact delete confirm flow", () => {
  it("issues DELETE against the digest-scoped artifacts route", async () => {
    const fetchMock = stubFetch(
      JSON.stringify({
        artifact_digest: LLAMA_DIGEST,
        removed: true,
        reclaimed_bytes: 4_800_000_000,
        job_id: null,
      }),
    );

    await expect(
      api.deleteModelHostArtifact(LLAMA_DIGEST),
    ).resolves.toMatchObject({ removed: true });
    expect(fetchMock.mock.calls[0]).toEqual([
      `/admin/model-host/artifacts/${encodeURIComponent(LLAMA_DIGEST)}`,
      expect.objectContaining({ method: "DELETE" }),
    ]);
  });

  it("confirms through a modal dialog before deleting", () => {
    expect(filesTable).toContain("$emit('delete', row)");
    expect(storageView).toContain('title="Delete cached artifact"');
    expect(storageView).toContain('@click="confirmDelete"');
    expect(storageView).toContain("api.deleteModelHostArtifact(row.digest)");
    // Cancel must stay possible and the full digest stays copyable.
    expect(storageView).toContain('@click="closeDelete"');
    expect(storageView).toContain('<CopyText :value="pendingDelete.digest" mono />');
  });

  it("renders a 409 refusal reason inline on the row, not as a toast", () => {
    const body = JSON.stringify({
      code: "artifact_resident",
      error:
        "artifact backs the ready replica of deployment local-qwen; stop the deployment first",
    });
    expect(deleteRefusalReason(body)).toBe(
      "artifact backs the ready replica of deployment local-qwen; stop the deployment first",
    );
    expect(deleteRefusalReason("not json")).toBe(
      "The server refused to delete this artifact.",
    );
    expect(storageView).toContain("error.status === 409");
    expect(storageView).toContain("deleteRefusalReason(error.body)");
    expect(filesTable).toContain("refusals");
    expect(filesTable).toContain('role="alert"');
  });
});

describe("cache GC", () => {
  it("issues POST /admin/model-host/gc", async () => {
    const fetchMock = stubFetch(JSON.stringify(GC_FIXTURE));

    await expect(api.modelHostGc()).resolves.toMatchObject({
      reclaimed_bytes: 1_610_612_736,
    });
    expect(fetchMock.mock.calls[0]).toEqual([
      "/admin/model-host/gc",
      expect.objectContaining({ method: "POST" }),
    ]);
  });

  it("renders the reclaimed, before, and after bytes of a GC run", () => {
    expect(gcSummary(GC_FIXTURE)).toBe(
      "Reclaimed 1.5 GB (12.0 GB before, 10.5 GB after).",
    );
    expect(storageView).toContain("gcSummary(gcResult)");
    expect(storageView).toContain("gcResult.deleted_artifacts.length");
    expect(storageView).toContain("skipped_artifacts");
    expect(storageView).toContain("budget_unsatisfied_bytes");
  });

  it("disables GC with an explanation when no budget is configured", () => {
    const refusal = JSON.stringify({
      code: "no_budget_configured",
      error: "model_host.cache_budget_gib is unset, so there is no budget to enforce",
    });
    expect(gcUnavailableReason(refusal)).toBe(
      "model_host.cache_budget_gib is unset, so there is no budget to enforce",
    );
    // Other failures must not latch the button into a disabled state.
    expect(
      gcUnavailableReason(JSON.stringify({ code: "io_error", error: "disk gone" })),
    ).toBeNull();
    expect(
      gcBudgetAbsentReason({ ...FILES_FIXTURE, cache_budget_bytes: null }),
    ).toMatch(/budget/);
    expect(gcBudgetAbsentReason(FILES_FIXTURE)).toBeNull();
    expect(
      gcBudgetAbsentReason({ ...FILES_FIXTURE, cache_budget_bytes: 500 }),
    ).toBeNull();
    expect(storageView).toContain(':title="gcDisabledReason ?? undefined"');
    expect(storageView).toContain("{{ gcDisabledReason }}");
  });
});
