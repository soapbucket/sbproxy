# Loaded by ../sb.yml via `policies[] type: rego`'s `module_path`, and
# tested offline by ./policy_test.yaml (`sbproxy rego test`).
package sbproxy

default allow := false

allow if {
  input.request.trust_tier == "strong"
}

allow if {
  input.request.method == "GET"
  startswith(input.request.path, "/public/")
}
