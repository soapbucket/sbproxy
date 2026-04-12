package transport_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/soapbucket/sbproxy/internal/engine/transport"
)

var ErrTest = errors.New("test error")
var ErrTransport = transport.Wrap(transport.Null, func(*http.Response) error {
	return errors.New("asdf")
})

var WrappedErrTransport = transport.WrapError(ErrTransport, ErrTest)

func TestWrap(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com", nil)
	if _, err := WrappedErrTransport.RoundTrip(req); err != nil {
		if err != ErrTest {
			t.Errorf("expected %v, got %v", ErrTest, err)
		}
	}

}
