package transformer

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDiscard(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		n        int
		expected string
	}{
		{
			name:     "discard 0 bytes",
			input:    "Hello World",
			n:        0,
			expected: "Hello World", // When discarding 0 bytes, everything remains
		},
		{
			name:     "discard 5 bytes",
			input:    "Hello World",
			n:        5,
			expected: " World",
		},
		{
			name:     "discard all bytes",
			input:    "Hello World",
			n:        100,
			expected: "", // Will get EOF if trying to read after discarding all
		},
		{
			name:     "discard negative",
			input:    "Hello World",
			n:        -1,
			expected: "Hello World", // Negative values should do nothing
		},
		{
			name:     "discard exact length",
			input:    "Hello",
			n:        5,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				Body: io.NopCloser(strings.NewReader(tt.input)),
			}

			transform := Discard(tt.n)
			err := transform.Modify(resp)
			// EOF from Modify is acceptable when discarding more than available
			if tt.n > len(tt.input) && err == io.EOF {
				// Expected behavior - body is empty, verify by reading
				body, _ := io.ReadAll(resp.Body)
				assert.Empty(t, body)
			} else {
				require.NoError(t, err)

				body, readErr := io.ReadAll(resp.Body)
				if tt.n >= len(tt.input) {
					// When discarding all or more, body will be empty
					assert.Empty(t, body)
					if readErr != nil && readErr != io.EOF {
						require.NoError(t, readErr)
					}
				} else {
					require.NoError(t, readErr)
					assert.Equal(t, tt.expected, string(body))
				}
			}
		})
	}
}

func TestDiscard_EmptyBody(t *testing.T) {
	resp := &http.Response{
		Body: io.NopCloser(strings.NewReader("")),
	}

	transform := Discard(10)
	err := transform.Modify(resp)
	// EOF is acceptable when discarding from empty body
	if err == io.EOF {
		// Expected behavior - body is empty, verify by reading
		body, _ := io.ReadAll(resp.Body)
		assert.Empty(t, body)
	} else {
		require.NoError(t, err)
		body, readErr := io.ReadAll(resp.Body)
		// For empty body with discard, EOF is acceptable
		assert.Empty(t, body)
		if readErr != nil && readErr != io.EOF {
			require.NoError(t, readErr)
		}
	}
}
