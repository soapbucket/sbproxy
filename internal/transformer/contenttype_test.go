package transformer_test

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"os"
	"testing"

	"github.com/soapbucket/sbproxy/internal/transformer"

	"golang.org/x/net/html/charset"
)

func TestContentType(t *testing.T) {

	data, _ := os.ReadFile("fixtures/blank.gif")

	resp := &http.Response{
		Header: http.Header{
			"Content-Type": []string{"application/octet-stream"},
		},
		Body: io.NopCloser(bytes.NewBuffer(data)),
		Request: &http.Request{
			URL: &url.URL{},
		},
	}

	tr := transformer.FixContentType()

	if err := tr.Modify(resp); err != nil {
		t.Errorf("Error: %s", err)
	}

	if resp.Header.Get("Content-Type") != "image/gif" {
		t.Errorf("Expected image/gif, got %s", resp.Header.Get("Content-Type"))
	}
}

func TestEncoding(t *testing.T) {

	text := "\xa35 for Pepp\xe9"

	resp := &http.Response{
		Header: http.Header{
			"Content-Type": []string{"text/plain; charset=latin1"},
		},
		Body: io.NopCloser(bytes.NewBufferString(text)),
		Request: &http.Request{
			URL: &url.URL{},
		},
	}

	tr := transformer.FixContentType()

	if err := tr.Modify(resp); err != nil {
		t.Errorf("Error: %s", err)
	}

	if resp.Header.Get("Content-Type") != "text/plain; charset=utf-8" {
		t.Errorf("Expected text/plain, got %s", resp.Header.Get("Content-Type"))
	}

	data, _ := io.ReadAll(resp.Body)
	if string(data) != "£5 for Peppé" {
		t.Errorf("Expected %s, got %s", text, string(data))
	}

	_, name, _ := charset.DetermineEncoding(data, "text/plain")
	if name != "utf-8" {
		t.Errorf("Expected utf-8, got %s", name)
	}
}

func TestEncoding2(t *testing.T) {

	text := "\xa35 for Pepp\xe9"

	resp := &http.Response{
		Header: http.Header{
			"Content-Type": []string{"text/plain"},
		},
		Body: io.NopCloser(bytes.NewBufferString(text)),
		Request: &http.Request{
			URL: &url.URL{},
		},
	}

	tr := transformer.FixContentType()
	if err := tr.Modify(resp); err != nil {
		t.Errorf("Error: %s", err)
	}

	if resp.Header.Get("Content-Type") != "text/plain; charset=utf-8" {
		t.Errorf("Expected text/plain; charset=utf-8, got %s", resp.Header.Get("Content-Type"))
	}

	data, _ := io.ReadAll(resp.Body)
	if string(data) != "£5 for Peppé" {
		t.Errorf("Expected %s, got %s", text, string(data))
	}

	_, name, _ := charset.DetermineEncoding(data, "text/plain")
	if name != "utf-8" {
		t.Errorf("Expected utf-8, got %s", name)
	}
}
