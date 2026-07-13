import { describe, expect, it } from "vitest";
import catalogEvidence from "./ModelCatalogEvidence.vue?raw";
import deploymentModal from "./ModelDeploymentModal.vue?raw";
import deploymentTable from "./ModelDeploymentTable.vue?raw";
import deviceTable from "./ModelDeviceTable.vue?raw";
import errorState from "./ErrorState.vue?raw";
import managementNotices from "./ModelManagementNotices.vue?raw";
import managementOverview from "./ModelManagementOverview.vue?raw";
import modelHostView from "../views/ModelHostView.vue?raw";

const SOURCES: Record<string, string> = {
  "ModelCatalogEvidence.vue": catalogEvidence,
  "ModelDeploymentModal.vue": deploymentModal,
  "ModelDeploymentTable.vue": deploymentTable,
  "ModelDeviceTable.vue": deviceTable,
  "ErrorState.vue": errorState,
  "ModelManagementNotices.vue": managementNotices,
  "ModelManagementOverview.vue": managementOverview,
  "ModelHostView.vue": modelHostView,
};

function source(name: string): string {
  return SOURCES[name];
}

describe("model management component contracts", () => {
  it("announces custom form errors and connects every validated control", () => {
    const modal = source("ModelDeploymentModal.vue");
    const evidence = source("ModelCatalogEvidence.vue");

    expect(modal).toContain('id="deployment-form-errors"');
    expect(modal).toContain('aria-live="assertive"');
    expect(modal).toContain('ref="errorSummary"');
    expect(modal).toContain("focusFirstError");
    for (const field of [
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
    ]) {
      expect(modal).toContain(`describedBy('${field}'`);
    }
    expect(evidence).toContain('id="license-acknowledgement"');
    expect(evidence).toContain(':aria-invalid="Boolean(licenseError)"');
    expect(evidence).toContain('aria-describedby="license-acknowledgement-description license-acknowledgement-error"');
  });

  it("uses row headers and deployment-specific action names", () => {
    const table = source("ModelDeploymentTable.vue");
    expect(table).toContain('<th scope="row">');
    for (const action of ["Edit", "Remove"]) {
      expect(table).toContain(`\`${action} \${row.deploymentId}\``);
    }
    for (const action of ["load", "stop", "reset"]) {
      expect(table).toContain(
        `lifecycleActionLabel('${action}', row.deploymentId)`,
      );
    }
  });

  it("announces initial async failures and lifecycle busy verbs", () => {
    const error = source("ErrorState.vue");
    const table = source("ModelDeploymentTable.vue");
    expect(error).toContain('role="alert"');
    expect(table).toContain("lifecycleActionLabel");
    for (const action of ["Loading", "Stopping", "Resetting"]) {
      expect(table).toContain(`\"${action}\"`);
    }
  });

  it("shows stale exact pins without unrelated evidence and wraps exact variant IDs", () => {
    const modal = source("ModelDeploymentModal.vue");
    const evidence = source("ModelCatalogEvidence.vue");
    expect(modal).toContain("catalogEvidenceSelection");
    expect(modal).toContain(':unavailable-variant="evidenceSelection.unavailableVariant"');
    expect(evidence).toContain("Pinned variant");
    expect(evidence).toContain('class="sb-mono variant-id"');
    expect(evidence).toMatch(
      /\.variant-id\s*\{[^}]*min-width:\s*0;[^}]*overflow-wrap:\s*anywhere;/s,
    );
  });

  it("renders only coherent signer data and gates preview copy on fresh catalog proof", () => {
    const view = source("ModelHostView.vue");
    const notices = source("ModelManagementNotices.vue");
    expect(view).toContain(':cluster-bundle="coherentClusterBundle"');
    expect(notices).toContain(
      'v-else-if="catalogLoaded && previewOnlyCatalog"',
    );
  });

  it("uses canonical desired IDs for modal duplicate validation", () => {
    const view = source("ModelHostView.vue");
    expect(view).toContain(
      ':existing-deployment-ids="Object.keys(canonicalDesiredDeployments ?? {})"',
    );
  });

  it("renders canonical desired count and effective revision evidence", () => {
    const view = source("ModelHostView.vue");
    const overview = source("ModelManagementOverview.vue");
    expect(view).toContain(
      ':desired-deployments="canonicalDesiredDeployments"',
    );
    expect(view).toContain(':desired-revision="effectiveDesiredRevision"');
    expect(view).toContain(
      ':desired-content-digest="effectiveDesiredContentDigest"',
    );
    expect(overview).toContain("Object.keys(desiredDeployments).length");
    expect(overview).toContain(
      'desiredRevision === undefined ? "Unavailable" : desiredRevision ?? "Initial"',
    );
    expect(overview).toContain("desiredContentDigest");
    expect(overview).not.toContain("Object.keys(document.deployments)");
    expect(overview).not.toContain("document.content_digest");
  });

  it("uses stable composite keys and announced dynamic metadata", () => {
    const devices = source("ModelDeviceTable.vue");
    const notices = source("ModelManagementNotices.vue");
    expect(devices).toContain(":key=\"deviceRowKey(device, rowIndex)\"");
    expect(notices).toContain(":key=\"`${blockerIndex}:${blocker}`\"");
    expect(notices).toContain('aria-live="polite"');
    expect(notices).toContain('role="alert"');
  });

  it("wraps long machine values in the modal, evidence, table, and notices", () => {
    for (const component of [
      "ModelDeploymentModal.vue",
      "ModelCatalogEvidence.vue",
      "ModelDeploymentTable.vue",
      "ModelManagementNotices.vue",
    ]) {
      const contents = source(component);
      expect(contents).toContain("min-width: 0");
      expect(contents).toContain("overflow-wrap: anywhere");
    }
  });
});
