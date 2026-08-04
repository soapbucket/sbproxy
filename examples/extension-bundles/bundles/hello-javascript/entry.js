export function respond(input) {
  return {
    version: "sbproxy-envelope/v1",
    outcome: "response",
    status: 200,
    headers: [
      ["content-type", "text/plain; charset=utf-8"],
      [input.config.response_header, "javascript"],
    ],
    body_base64: "aGVsbG8gZnJvbSBKYXZhU2NyaXB0Cg==",
  };
}

export function transformResponse() {
  return {
    version: "sbproxy-envelope/v1",
    body_base64: "aGVsbG8gZnJvbSBhIEphdmFTY3JpcHQgdHJhbnNmb3JtCg==",
  };
}
