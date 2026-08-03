function release(input, expectedEvent) {
  if (input.version !== "sbproxy-envelope/v1") {
    throw new Error("unsupported envelope version");
  }
  if (input.event.schema_version !== 1 || input.event.event !== expectedEvent) {
    throw new Error("unexpected AI event");
  }
  return { version: "sbproxy-envelope/v1", decision: "release" };
}

export function inspectInput(input) {
  return release(input, "guardrail_input");
}

export function inspectTool(input) {
  return release(input, "tool_call");
}

export function inspectOutput(input) {
  return release(input, "guardrail_output");
}

export function inspectClose(input) {
  return release(input, "close");
}
