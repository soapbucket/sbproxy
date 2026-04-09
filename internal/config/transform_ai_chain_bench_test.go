package config

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

// BenchmarkTransformChain_Single benchmarks a single transform in isolation.
func BenchmarkTransformChain_Single(b *testing.B) {
	body := makeOpenAIResponse(500, 200)
	cfgData, _ := json.Marshal(map[string]string{"type": "token_count", "provider": "openai"})
	cfg, err := NewTokenCountTransform(cfgData)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp := benchResponse(body, "application/json")
		cfg.Apply(resp)
		io.ReadAll(resp.Body)
	}
}

// BenchmarkTransformChain_Two benchmarks two transforms chained.
func BenchmarkTransformChain_Two(b *testing.B) {
	body := makeOpenAIResponse(500, 200)

	tokenCfg, _ := json.Marshal(map[string]string{"type": "token_count", "provider": "openai"})
	costCfg, _ := json.Marshal(map[string]string{"type": "cost_estimate", "provider": "openai"})

	t1, err := NewTokenCountTransform(tokenCfg)
	if err != nil {
		b.Fatal(err)
	}
	t2, err := NewCostEstimateTransform(costCfg)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp := benchResponse(body, "application/json")
		t1.Apply(resp)
		t2.Apply(resp)
		io.ReadAll(resp.Body)
	}
}

// BenchmarkTransformChain_Four benchmarks four transforms chained.
func BenchmarkTransformChain_Four(b *testing.B) {
	body := makeOpenAIResponse(500, 200)

	schemaCfg, _ := json.Marshal(map[string]interface{}{
		"type": "ai_schema", "provider": "openai", "action": "warn",
	})
	tokenCfg, _ := json.Marshal(map[string]string{
		"type": "token_count", "provider": "openai",
	})
	costCfg, _ := json.Marshal(map[string]string{
		"type": "cost_estimate", "provider": "openai",
	})
	projCfg, _ := json.Marshal(map[string]interface{}{
		"type":    "json_projection",
		"include": []string{"id", "model", "choices"},
	})

	t1, err := NewAISchemaTransform(schemaCfg)
	if err != nil {
		b.Fatal(err)
	}
	t2, err := NewTokenCountTransform(tokenCfg)
	if err != nil {
		b.Fatal(err)
	}
	t3, err := NewCostEstimateTransform(costCfg)
	if err != nil {
		b.Fatal(err)
	}
	t4, err := NewJSONProjectionTransform(projCfg)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp := benchResponse(body, "application/json")
		t1.Apply(resp)
		t2.Apply(resp)
		t3.Apply(resp)
		t4.Apply(resp)
		io.ReadAll(resp.Body)
	}
}

// BenchmarkTransformChain_Parallel benchmarks four transforms chained with parallelism.
func BenchmarkTransformChain_Parallel(b *testing.B) {
	body := makeOpenAIResponse(500, 200)

	schemaCfg, _ := json.Marshal(map[string]interface{}{
		"type": "ai_schema", "provider": "openai", "action": "warn",
	})
	tokenCfg, _ := json.Marshal(map[string]string{
		"type": "token_count", "provider": "openai",
	})
	costCfg, _ := json.Marshal(map[string]string{
		"type": "cost_estimate", "provider": "openai",
	})
	projCfg, _ := json.Marshal(map[string]interface{}{
		"type":    "json_projection",
		"include": []string{"id", "model", "choices"},
	})

	t1, _ := NewAISchemaTransform(schemaCfg)
	t2, _ := NewTokenCountTransform(tokenCfg)
	t3, _ := NewCostEstimateTransform(costCfg)
	t4, _ := NewJSONProjectionTransform(projCfg)

	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			resp := &http.Response{
				StatusCode: 200,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(bytes.NewReader(body)),
			}
			t1.Apply(resp)
			t2.Apply(resp)
			t3.Apply(resp)
			t4.Apply(resp)
			io.ReadAll(resp.Body)
		}
	})
}
