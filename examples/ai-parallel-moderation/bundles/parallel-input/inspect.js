function messageText(input) {
  const messages = input.event && input.event.messages;
  if (!Array.isArray(messages) || messages.length === 0) {
    return "";
  }
  const last = messages[messages.length - 1];
  return typeof last.content === "string" ? last.content : "";
}

export function inspect(input) {
  if (input.version !== "sbproxy-envelope/v1") {
    throw new Error("unsupported envelope version");
  }
  if (input.event.schema_version !== 1 || input.event.event !== "guardrail_input") {
    throw new Error("unexpected AI event");
  }
  if (messageText(input).toLowerCase().includes("exfiltrate")) {
    return {
      version: "sbproxy-envelope/v1",
      decision: "block",
      status: 422,
      code: "parallel_moderation",
      message: "prompt refused by parallel inspect",
    };
  }
  return { version: "sbproxy-envelope/v1", decision: "release" };
}
