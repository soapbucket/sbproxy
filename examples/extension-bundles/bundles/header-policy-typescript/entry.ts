type Header = [string, string];

type PolicyInput = {
  version: "sbproxy-envelope/v1";
  config: { header_name: string };
  request: { headers: Header[] };
};

export function requireHeader(input: PolicyInput) {
  const expected = input.config.header_name.toLowerCase();
  const present = input.request.headers.some(
    ([name]) => name.toLowerCase() === expected,
  );

  if (present) {
    return { version: "sbproxy-envelope/v1", decision: "allow" };
  }

  return {
    version: "sbproxy-envelope/v1",
    decision: "deny",
    status: 403,
    message: `missing ${expected}`,
  };
}
