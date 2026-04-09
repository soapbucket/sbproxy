// Package lua provides Lua scripting support for dynamic request/response processing.
package lua

import "strings"

func wrapMatcherScript(script string) string {
	trimmed := strings.TrimSpace(script)
	if strings.Contains(trimmed, "function match_request") {
		return trimmed
	}
	return "function match_request(req, ctx)\nlocal request = req\n" + trimmed + "\nend"
}

func wrapResponseMatcherScript(script string) string {
	trimmed := strings.TrimSpace(script)
	if strings.Contains(trimmed, "function match_response") {
		return trimmed
	}
	return "function match_response(resp, ctx)\nlocal response = resp\n" + trimmed + "\nend"
}

func wrapModifierScript(script string) string {
	trimmed := strings.TrimSpace(script)
	if strings.Contains(trimmed, "function modify_request") {
		return trimmed
	}
	return "function modify_request(req, ctx)\nlocal request = req\n" + trimmed + "\nend"
}

func wrapResponseModifierScript(script string) string {
	trimmed := strings.TrimSpace(script)
	if strings.Contains(trimmed, "function modify_response") {
		return trimmed
	}
	return "function modify_response(resp, ctx)\nlocal response = resp\n" + trimmed + "\nend"
}
