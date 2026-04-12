package transformer_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"os"
	"testing"

	"github.com/soapbucket/sbproxy/internal/transformer"
)

type urlManager map[string][]byte

func (u urlManager) Get(_ context.Context, key string) ([]byte, error) {
	if val, ok := u[key]; ok {
		return val, nil
	}
	return nil, nil
}

var manager urlManager

func init() {
	manager = make(urlManager)
	manager["http://test.com/test.png"] = []byte(`{"url":"http://test2.com/test2.png","Integrity":"sha256-test"}`)
}

func TestRewriteURL(t *testing.T) {
	data, _ := os.ReadFile("fixtures/test.html")
	req := &http.Request{
		URL: &url.URL{
			Scheme: "http",
			Host:   "test.com",
			Path:   "/asdf",
		},
	}
	resp := &http.Response{
		Header: http.Header{
			"Content-Type": []string{"text/html"},
		},
		Body:    io.NopCloser(bytes.NewBuffer(data)),
		Request: req,
	}

	tr := transformer.ModifyHTML(transformer.RewriteURL(req, manager))
	if err := tr.Modify(resp); err != nil {
		t.Error(err)
	}

	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()

	// Test completed successfully
}
