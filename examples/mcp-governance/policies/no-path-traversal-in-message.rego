# OPA-compatible Rego twin of sb.yml's inline CEL rule
# "no-path-traversal-in-message". Same tool, same predicate, same
# mode: block. Kept as a separate file loaded by `path:` to show the
# other half of the dual-engine story CEL rules already cover
# everywhere else in this config.
#
# `true` is compliant, `false` is a violation, same convention CEL
# argument policies use: input.mcp.arguments.message must not contain
# a path-traversal sequence.
package sbproxy

default allow := false

allow if {
	not contains(input.mcp.arguments.message, "../")
}
