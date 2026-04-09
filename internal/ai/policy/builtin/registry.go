package builtin

import (
	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

// RegisterAll registers all 22 built-in detectors with the given executor.
// Each detector is registered under its type name, which corresponds to the
// GuardrailConfig.Type field used for dispatch.
func RegisterAll(executor *policy.GuardrailExecutor) {
	executor.RegisterDetector("pii", &PIIDetector{})
	executor.RegisterDetector("keyword", &KeywordDetector{})
	executor.RegisterDetector("regex", NewRegexDetector())
	executor.RegisterDetector("length", &LengthDetector{})
	executor.RegisterDetector("language", &LanguageDetector{})
	executor.RegisterDetector("code", &CodeDetector{})
	executor.RegisterDetector("schema", &SchemaDetector{})
	executor.RegisterDetector("url", &URLDetector{})
	executor.RegisterDetector("secret", &SecretDetector{})
	executor.RegisterDetector("injection", &InjectionDetector{})
	executor.RegisterDetector("jwt", &JWTDetector{})
	executor.RegisterDetector("model", &ModelDetector{})
	executor.RegisterDetector("request_type", &RequestTypeDetector{})
	executor.RegisterDetector("metadata", &MetadataDetector{})
	executor.RegisterDetector("params", &ParamsDetector{})
	executor.RegisterDetector("token_estimate", &TokenEstimatorDetector{})
	executor.RegisterDetector("tool_call", &ToolCallDetector{})
	executor.RegisterDetector("response_length", &ResponseLengthDetector{})
	executor.RegisterDetector("budget_gate", &BudgetGateDetector{})
	executor.RegisterDetector("gibberish", &GibberishDetector{})
	executor.RegisterDetector("webhook", NewWebhookDetector(nil))
	executor.RegisterDetector("log", &LogDetector{})
}
