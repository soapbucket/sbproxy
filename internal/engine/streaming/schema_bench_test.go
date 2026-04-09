package streaming

import (
	"testing"
)

func BenchmarkJSONSchemaValidator_Valid(b *testing.B) {
	b.ReportAllocs()

	schemaJSON := []byte(`{
		"type": "object",
		"required": ["event", "timestamp", "data"],
		"properties": {
			"event": {"type": "string"},
			"timestamp": {"type": "number"},
			"data": {
				"type": "object",
				"required": ["id"],
				"properties": {
					"id": {"type": "string"},
					"value": {"type": "number"},
					"tags": {
						"type": "array",
						"items": {"type": "string"}
					}
				}
			}
		}
	}`)

	validator, err := NewJSONSchemaValidator(schemaJSON)
	if err != nil {
		b.Fatalf("failed to create validator: %v", err)
	}

	validPayload := []byte(`{
		"event": "user.created",
		"timestamp": 1709827200,
		"data": {
			"id": "usr_abc123",
			"value": 42.5,
			"tags": ["premium", "active", "verified"]
		}
	}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := validator.Validate(validPayload); err != nil {
			b.Fatalf("validation failed: %v", err)
		}
	}
}

func BenchmarkJSONSchemaValidator_Invalid(b *testing.B) {
	b.ReportAllocs()

	schemaJSON := []byte(`{
		"type": "object",
		"required": ["event", "timestamp", "data"],
		"properties": {
			"event": {"type": "string"},
			"timestamp": {"type": "number"},
			"data": {
				"type": "object",
				"required": ["id"],
				"properties": {
					"id": {"type": "string"},
					"value": {"type": "number"}
				}
			}
		}
	}`)

	validator, err := NewJSONSchemaValidator(schemaJSON)
	if err != nil {
		b.Fatalf("failed to create validator: %v", err)
	}

	// Missing required "data" field
	invalidPayload := []byte(`{
		"event": "user.created",
		"timestamp": 1709827200
	}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = validator.Validate(invalidPayload)
	}
}
