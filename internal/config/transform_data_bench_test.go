package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

func makeJSONBody(size int) []byte {
	base := `{"id":1,"name":"Test User","email":"test@example.com","score":42,"active":true,"tags":["a","b","c"]}`
	reps := size / len(base)
	if reps < 1 {
		reps = 1
	}
	parts := make([]string, reps)
	for i := range parts {
		parts[i] = base
	}
	return []byte("[" + strings.Join(parts, ",") + "]")
}

func makeCSVBody(rows int) []byte {
	var buf bytes.Buffer
	buf.WriteString("id,name,email\n")
	for i := 0; i < rows; i++ {
		fmt.Fprintf(&buf, "%d,User %d,user%d@example.com\n", i, i, i)
	}
	return buf.Bytes()
}

func makeXMLBody(elements int) []byte {
	var buf bytes.Buffer
	buf.WriteString("<root>")
	for i := 0; i < elements; i++ {
		fmt.Fprintf(&buf, "<item><id>%d</id><name>User %d</name></item>", i, i)
	}
	buf.WriteString("</root>")
	return buf.Bytes()
}

func benchResponse(body []byte, ct string) *http.Response {
	return &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{ct}},
		Body:       io.NopCloser(bytes.NewReader(body)),
	}
}

func BenchmarkJSONProjection_Include(b *testing.B) {
	sizes := []int{1024, 5 * 1024, 50 * 1024}
	for _, size := range sizes {
		body := makeJSONBody(size)
		cfgData, _ := json.Marshal(map[string]interface{}{
			"type":    "json_projection",
			"include": []string{"id", "name"},
		})

		b.Run(fmt.Sprintf("size=%dKB", size/1024), func(b *testing.B) {
			cfg, err := NewJSONProjectionTransform(cfgData)
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
		})
	}
}

func BenchmarkJSONProjection_Exclude(b *testing.B) {
	body := makeJSONBody(5 * 1024)
	cfgData, _ := json.Marshal(map[string]interface{}{
		"type":    "json_projection",
		"exclude": []string{"email", "tags"},
	})
	cfg, err := NewJSONProjectionTransform(cfgData)
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

func BenchmarkPayloadLimit_ContentLength(b *testing.B) {
	body := makeJSONBody(5 * 1024)
	cfgData, _ := json.Marshal(map[string]interface{}{
		"type":     "payload_limit",
		"max_size": 1024 * 1024,
		"action":   "reject",
	})
	cfg, err := NewPayloadLimitTransform(cfgData)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp := benchResponse(body, "application/json")
		resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
		cfg.Apply(resp)
		io.ReadAll(resp.Body)
	}
}

func BenchmarkPayloadLimit_NoContentLength(b *testing.B) {
	body := makeJSONBody(5 * 1024)
	cfgData, _ := json.Marshal(map[string]interface{}{
		"type":     "payload_limit",
		"max_size": 1024 * 1024,
		"action":   "reject",
	})
	cfg, err := NewPayloadLimitTransform(cfgData)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp := benchResponse(body, "application/json")
		resp.Header.Del("Content-Length")
		cfg.Apply(resp)
		io.ReadAll(resp.Body)
	}
}

func BenchmarkFormatConvert_CSV(b *testing.B) {
	sizes := []int{10, 100, 500}
	for _, rows := range sizes {
		body := makeCSVBody(rows)
		cfgData, _ := json.Marshal(map[string]interface{}{
			"type": "format_convert",
			"from": "csv",
			"to":   "json",
		})

		b.Run(fmt.Sprintf("rows=%d", rows), func(b *testing.B) {
			cfg, err := NewFormatConvertTransform(cfgData)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.SetBytes(int64(len(body)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				resp := benchResponse(body, "text/csv")
				cfg.Apply(resp)
				io.ReadAll(resp.Body)
			}
		})
	}
}

func BenchmarkFormatConvert_XML(b *testing.B) {
	sizes := []int{10, 100, 500}
	for _, elems := range sizes {
		body := makeXMLBody(elems)
		cfgData, _ := json.Marshal(map[string]interface{}{
			"type": "format_convert",
			"from": "xml",
			"to":   "json",
		})

		b.Run(fmt.Sprintf("elements=%d", elems), func(b *testing.B) {
			cfg, err := NewFormatConvertTransform(cfgData)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.SetBytes(int64(len(body)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				resp := benchResponse(body, "application/xml")
				cfg.Apply(resp)
				io.ReadAll(resp.Body)
			}
		})
	}
}

func BenchmarkClassify(b *testing.B) {
	body := makeJSONBody(5 * 1024)
	cfgData, _ := json.Marshal(map[string]interface{}{
		"type":        "classify",
		"header_name": "X-Content-Class",
		"rules": []map[string]string{
			{"name": "has_email", "pattern": `\w+@\w+\.\w+`},
			{"name": "has_name", "json_path": "name"},
		},
	})
	cfg, err := NewClassifyTransform(cfgData)
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
