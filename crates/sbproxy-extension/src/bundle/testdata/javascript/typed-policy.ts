type Input = {
    config?: {
        enabled?: boolean;
    };
};

export function run(input: Input) {
    return input.config?.enabled === false
        ? { version: "sbproxy-envelope/v1", decision: "deny", status: 403, message: "disabled" }
        : { version: "sbproxy-envelope/v1", decision: "allow" };
}
