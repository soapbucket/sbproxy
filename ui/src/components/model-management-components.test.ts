import { describe, expect, it } from "vitest";
import catalogEvidence from "./ModelCatalogEvidence.vue?raw";
import deploymentModal from "./ModelDeploymentModal.vue?raw";
import deploymentTable from "./ModelDeploymentTable.vue?raw";
import deviceTable from "./ModelDeviceTable.vue?raw";
import managementNotices from "./ModelManagementNotices.vue?raw";

const SOURCES: Record<string, string> = {
  "ModelCatalogEvidence.vue": catalogEvidence,
  "ModelDeploymentModal.vue": deploymentModal,
  "ModelDeploymentTable.vue": deploymentTable,
  "ModelDeviceTable.vue": deviceTable,
  "ModelManagementNotices.vue": managementNotices,
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
    for (const action of ["Load", "Stop", "Reset", "Edit", "Remove"]) {
      expect(table).toContain(`\`${action} \${row.deploymentId}\``);
    }
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
