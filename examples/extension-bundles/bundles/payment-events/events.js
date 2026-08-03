export function inspectPayment(input) {
  if (input.version !== "sbproxy-envelope/v1") {
    throw new Error("unsupported envelope version");
  }
  if (input.event.schema_version !== 1) {
    throw new Error("unsupported payment event version");
  }
  if (Object.prototype.hasOwnProperty.call(input.event, "credential")) {
    throw new Error("payment credentials must stay out of extension events");
  }

  return { version: "sbproxy-envelope/v1", decision: "continue" };
}
