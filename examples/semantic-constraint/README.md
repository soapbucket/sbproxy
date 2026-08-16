# Semantic constraint policy

*Last modified: 2026-08-16*

An LLM-as-judge policy. The `semantic_constraint` policy renders a prompt template against the request envelope (`request.method`, `request.path`, `request.host`, `request.query`), sends the rendered prompt to a configured judge endpoint, and maps the returned verdict (`allow` or `deny`) onto the request. Use it for policy intents that do not factor into a deterministic rule, or as a fast prototype while a deterministic policy is being designed.

The example wires a single `test.sbproxy.dev` origin behind a judge that decides whether the path looks like routine API traffic (allow) or a sensitive admin route (deny). The judge endpoint is a placeholder pointed at `http://127.0.0.1:9999/judge`; in production the operator points it at any frontier-model API or an in-VPC judge service. The bearer token is read from the env var named in `api_key_env` (BYOK).

## Run

```bash
export SBPROXY_JUDGE_API_KEY=sk-your-judge-key
make run CONFIG=examples/semantic-constraint/sb.yml
```

The judge endpoint must be reachable. For a quick local stub that always returns `allow`, run a one-line python server before booting the proxy:

```bash
python3 -c '
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        self.send_response(200); self.send_header("Content-Type","application/json"); self.end_headers()
        self.wfile.write(json.dumps({"verdict":"allow","message":"stub"}).encode())
HTTPServer(("127.0.0.1",9999),H).serve_forever()
'
```

## Try it

A request that the stub allows passes through to the upstream (`/users`
is not a real path on the `test.sbproxy.dev` echo service and 404s from
the upstream itself; use `/get`, which the service does serve):

```bash
$ curl -i -H 'Host: test.sbproxy.dev' http://127.0.0.1:8080/get
HTTP/1.1 200 OK
content-type: application/json
...
```

Swap the stub for one that returns `{"verdict":"deny","message":"..."}` and
the same request comes back as `403 Forbidden` with that `message` string in
the response body (the key is `message`, not `rationale`; `rationale` is
never read). `judge.cache_capacity` caches verdicts by rendered prompt, so
restart the proxy (or query a path you have not requested yet) after
swapping stubs, or the cached `allow` from the first stub answers again
without the new stub ever being called.

## Configuration knobs

- `prompt_template`: Tera-style template rendered against the request. Keep it short; long prompts inflate per-request cost.
- `violations_block`: when `true`, a `deny` verdict short-circuits the request. When `false`, the verdict is recorded as a metric and the request is allowed (useful for shadow rollouts).
- `judge.endpoint`: any HTTPS endpoint that accepts the rendered prompt and returns a JSON `{verdict, message}` envelope (`message` is optional; a `deny` with no `message` falls back to the generic `"denied by judge"` body). An `{choices: [{message: {content}}]}` chat-completions wrapper carrying that same shape in `content` is also accepted.
- `judge.cache_capacity`: bounded LRU cache keyed on the rendered prompt; saves a round-trip on identical requests.
- `judge.budget_tokens`: circuit-breaker that disables the policy after the configured token budget is consumed in a rolling window.

See `docs/policy.md` in this repo for the full schema and behaviour.
