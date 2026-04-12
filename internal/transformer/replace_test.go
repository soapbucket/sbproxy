package transformer_test

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/soapbucket/sbproxy/internal/transformer"
)

func TestReplaceString(t *testing.T) {
	const expected = `<html><body><p>this is a test</p><p>Hello nobody</p><p>Hello nobody</p><p>Hello nobody</p></body></html>`
	rdr := io.NopCloser(strings.NewReader(`<html><body><p>Hello World</p><p>Hello nobody</p><p>Hello nobody</p><p>Hello nobody</p></body></html>`))

	resp := &http.Response{
		Header: http.Header{"Content-Type": []string{"text/html"}},
		Body:   rdr,
	}

	tr := transformer.StringReplacement("Hello World", "this is a test")
	if err := tr.Modify(resp); err != nil {
		t.Fatal(err)
	}

	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if string(data) != expected {
		t.Errorf("Expected %s, got %s", expected, data)
	}

}

func TestReplaceString2(t *testing.T) {
	rdr := io.NopCloser(strings.NewReader(`<html></html>`))

	resp := &http.Response{
		Header: http.Header{"Content-Type": []string{"text/html"}},
		Body:   rdr,
	}

	tr := transformer.StringReplacement("This is a really long string", "this is a test")
	if err := tr.Modify(resp); err != nil {
		t.Fatal(err)
	}

	_, err := io.ReadAll(resp.Body)
	resp.Body.Close()

	if err != nil {
		t.Fatalf("Error reading response body: %s", err)
	}

}

func TestReplaceString3(t *testing.T) {
	const jsonString = `
		{
			"hello": "world"
		}
	`
	const jsonString2 = `
		{
			"goodbye": "world"
		}
	`
	rdr := io.NopCloser(strings.NewReader(jsonString))

	resp := &http.Response{
		Header: http.Header{"Content-Type": []string{"application/json"}},
		Body:   rdr,
	}

	tr := transformer.StringReplacement(`"hello"`, `"goodbye"`)
	if err := tr.Modify(resp); err != nil {
		t.Fatal(err)
	}

	data, err := io.ReadAll(resp.Body)
	resp.Body.Close()

	if err != nil {
		t.Fatalf("Error reading response body: %s", err)
	}
	if string(data) != jsonString2 {
		t.Errorf("Expected %s, got %s", jsonString2, data)
	}

}

func TestMultiStringReplacement(t *testing.T) {
	const input = `<html><body><p>Hello World</p><p>Goodbye Universe</p><p>Hello World again</p></body></html>`
	const expected = `<html><body><p>Hi Earth</p><p>Farewell Cosmos</p><p>Hi Earth again</p></body></html>`

	rdr := io.NopCloser(strings.NewReader(input))

	resp := &http.Response{
		Header: http.Header{"Content-Type": []string{"text/html"}},
		Body:   rdr,
	}

	replacements := []transformer.Replacement{
		{Src: "Hello World", Dest: "Hi Earth"},
		{Src: "Goodbye Universe", Dest: "Farewell Cosmos"},
	}

	tr := transformer.MultiStringReplacement(replacements)
	if err := tr.Modify(resp); err != nil {
		t.Fatal(err)
	}

	data, err := io.ReadAll(resp.Body)
	resp.Body.Close()

	if err != nil {
		t.Fatalf("Error reading response body: %s", err)
	}

	if string(data) != expected {
		t.Errorf("Expected %s, got %s", expected, string(data))
	}
}

func TestMultiStringReplacementOverlapping(t *testing.T) {
	const input = `<html><body><p>abc def abc xyz</p></body></html>`
	rdr := io.NopCloser(strings.NewReader(input))

	resp := &http.Response{
		Header: http.Header{"Content-Type": []string{"text/html"}},
		Body:   rdr,
	}

	replacements := []transformer.Replacement{
		{Src: "abc", Dest: "123"},
		{Src: "def", Dest: "456"},
	}

	tr := transformer.MultiStringReplacement(replacements)
	if err := tr.Modify(resp); err != nil {
		t.Fatal(err)
	}

	data, err := io.ReadAll(resp.Body)
	resp.Body.Close()

	if err != nil {
		t.Fatalf("Error reading response body: %s", err)
	}

	// Note: The first "abc" should be replaced first (earliest match wins)
	// Then the algorithm continues and finds the next "abc"
	result := string(data)
	if !strings.Contains(result, "123") {
		t.Errorf("Expected result to contain '123', got %s", result)
	}
}

func TestMultiStringReplacementEmpty(t *testing.T) {
	const input = `<html><body><p>Hello World</p></body></html>`

	rdr := io.NopCloser(strings.NewReader(input))

	resp := &http.Response{
		Header: http.Header{"Content-Type": []string{"text/html"}},
		Body:   rdr,
	}

	replacements := []transformer.Replacement{}

	tr := transformer.MultiStringReplacement(replacements)
	if err := tr.Modify(resp); err != nil {
		t.Fatal(err)
	}

	data, err := io.ReadAll(resp.Body)
	resp.Body.Close()

	if err != nil {
		t.Fatalf("Error reading response body: %s", err)
	}

	// With no replacements, output should match input
	if string(data) != input {
		t.Errorf("Expected %s, got %s", input, string(data))
	}
}
