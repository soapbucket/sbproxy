package transformer

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNoop(t *testing.T) {
	input := "Hello World"
	resp := &http.Response{
		Body:   io.NopCloser(strings.NewReader(input)),
		Header: make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/plain")

	err := Noop.Modify(resp)
	require.NoError(t, err)

	// Body should be unchanged
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, input, string(body))

	// Headers should be unchanged
	assert.Equal(t, "text/plain", resp.Header.Get("Content-Type"))
}

