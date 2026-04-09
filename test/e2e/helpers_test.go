package e2e

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// Test environment configuration
var (
	proxyHTTPURL  string
	proxyHTTPSURL string
	testServerURL string
	httpClient    *http.Client
	tlsClient     *http.Client
)

func init() {
	proxyHTTPURL = getEnv("E2E_PROXY_HTTP_URL", "http://localhost:8080")
	proxyHTTPSURL = getEnv("E2E_PROXY_HTTPS_URL", "https://localhost:8443")
	testServerURL = getEnv("E2E_TEST_SERVER_URL", "http://localhost:8090")

	httpClient = &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Do not follow redirects
		},
	}

	tlsClient = &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

// ProxyResponse wraps the HTTP response with helper methods for assertions.
type ProxyResponse struct {
	*http.Response
	Body    []byte
	BodyStr string
}

// JSONBody parses the response body as JSON into the given target.
func (r *ProxyResponse) JSONBody(target interface{}) error {
	return json.Unmarshal(r.Body, target)
}

// JSONMap parses the response body as a map[string]interface{}.
func (r *ProxyResponse) JSONMap() (map[string]interface{}, error) {
	var m map[string]interface{}
	err := json.Unmarshal(r.Body, &m)
	return m, err
}

// proxyGet sends a GET request through the proxy with the specified Host header.
func proxyGet(t *testing.T, host, path string, headers ...string) *ProxyResponse {
	t.Helper()
	return proxyRequest(t, "GET", host, path, "", headers...)
}

// proxyPost sends a POST request through the proxy with the specified Host header.
func proxyPost(t *testing.T, host, path, body string, headers ...string) *ProxyResponse {
	t.Helper()
	return proxyRequest(t, "POST", host, path, body, headers...)
}

// proxyRequest sends an HTTP request through the proxy.
// headers should be provided as key-value pairs: "Header-Name", "Header-Value", ...
func proxyRequest(t *testing.T, method, host, path, body string, headers ...string) *ProxyResponse {
	t.Helper()

	url := proxyHTTPURL + path

	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	req.Host = host
	req.Header.Set("Host", host)

	// Apply additional headers
	if len(headers)%2 != 0 {
		t.Fatalf("Headers must be provided as key-value pairs, got odd number: %d", len(headers))
	}
	for i := 0; i < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	return &ProxyResponse{
		Response: resp,
		Body:     respBody,
		BodyStr:  string(respBody),
	}
}

// proxyHTTPS sends an HTTPS request through the proxy.
func proxyHTTPS(t *testing.T, method, host, path string, headers ...string) *ProxyResponse {
	t.Helper()

	url := proxyHTTPSURL + path

	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	req.Host = host
	req.Header.Set("Host", host)

	for i := 0; i < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}

	resp, err := tlsClient.Do(req)
	if err != nil {
		t.Fatalf("HTTPS request failed: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	return &ProxyResponse{
		Response: resp,
		Body:     respBody,
		BodyStr:  string(respBody),
	}
}

// proxyWebSocket dials the proxy as a websocket origin by connecting to the proxy address
// while preserving the requested origin Host in the websocket URL.
func proxyWebSocket(t *testing.T, host, path string, headers http.Header, subprotocols ...string) (*websocket.Conn, *http.Response) {
	t.Helper()

	proxyURL, err := url.Parse(proxyHTTPURL)
	if err != nil {
		t.Fatalf("Failed to parse proxy URL: %v", err)
	}

	wsURL := url.URL{
		Scheme: "ws",
		Host:   host,
		Path:   path,
	}

	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
		Subprotocols:     subprotocols,
		NetDialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, proxyURL.Host)
		},
	}

	conn, resp, err := dialer.Dial(wsURL.String(), headers)
	if err != nil {
		if resp != nil {
			return nil, resp
		}
		t.Fatalf("WebSocket dial failed: %v", err)
	}

	return conn, resp
}

// directGet sends a GET request directly to the e2e test server (bypassing the proxy).
func directGet(t *testing.T, path string) *ProxyResponse {
	t.Helper()

	url := testServerURL + path
	resp, err := httpClient.Get(url)
	if err != nil {
		t.Fatalf("Direct request failed: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	return &ProxyResponse{
		Response: resp,
		Body:     respBody,
		BodyStr:  string(respBody),
	}
}

// assertStatus asserts the response has the expected status code.
func assertStatus(t *testing.T, resp *ProxyResponse, expected int) {
	t.Helper()
	if resp.StatusCode != expected {
		t.Errorf("Expected status %d, got %d. Body: %s", expected, resp.StatusCode, truncate(resp.BodyStr, 500))
	}
}

// assertHeader asserts the response has a specific header with the expected value.
func assertHeader(t *testing.T, resp *ProxyResponse, header, expected string) {
	t.Helper()
	actual := resp.Header.Get(header)
	if actual != expected {
		t.Errorf("Expected header %s=%q, got %q", header, expected, actual)
	}
}

// assertHeaderExists asserts the response has a specific header (any value).
func assertHeaderExists(t *testing.T, resp *ProxyResponse, header string) {
	t.Helper()
	if resp.Header.Get(header) == "" {
		t.Errorf("Expected header %s to exist, but it was not present", header)
	}
}

// assertHeaderContains asserts the response header contains the expected substring.
func assertHeaderContains(t *testing.T, resp *ProxyResponse, header, substring string) {
	t.Helper()
	actual := resp.Header.Get(header)
	if !strings.Contains(actual, substring) {
		t.Errorf("Expected header %s to contain %q, got %q", header, substring, actual)
	}
}

// assertHeaderAbsent asserts the response does not have a specific header.
func assertHeaderAbsent(t *testing.T, resp *ProxyResponse, header string) {
	t.Helper()
	if val := resp.Header.Get(header); val != "" {
		t.Errorf("Expected header %s to be absent, but got %q", header, val)
	}
}

// assertBodyContains asserts the response body contains the expected substring.
func assertBodyContains(t *testing.T, resp *ProxyResponse, substring string) {
	t.Helper()
	if !strings.Contains(resp.BodyStr, substring) {
		t.Errorf("Expected body to contain %q, got: %s", substring, truncate(resp.BodyStr, 500))
	}
}

// assertBodyNotContains asserts the response body does not contain the expected substring.
func assertBodyNotContains(t *testing.T, resp *ProxyResponse, substring string) {
	t.Helper()
	if strings.Contains(resp.BodyStr, substring) {
		t.Errorf("Expected body NOT to contain %q, got: %s", substring, truncate(resp.BodyStr, 500))
	}
}

// assertContentType asserts the Content-Type header matches or contains the expected value.
func assertContentType(t *testing.T, resp *ProxyResponse, expected string) {
	t.Helper()
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, expected) {
		t.Errorf("Expected Content-Type to contain %q, got %q", expected, ct)
	}
}

// assertJSON asserts the response body is valid JSON and calls the checker function.
func assertJSON(t *testing.T, resp *ProxyResponse, checker func(t *testing.T, data map[string]interface{})) {
	t.Helper()
	data, err := resp.JSONMap()
	if err != nil {
		t.Fatalf("Failed to parse JSON body: %v. Body: %s", err, truncate(resp.BodyStr, 500))
	}
	checker(t, data)
}

// assertRedirect asserts that the response is a redirect to the expected URL.
func assertRedirect(t *testing.T, resp *ProxyResponse, expectedStatus int, locationContains string) {
	t.Helper()
	assertStatus(t, resp, expectedStatus)
	location := resp.Header.Get("Location")
	if location == "" {
		t.Errorf("Expected redirect but no Location header found")
		return
	}
	if !strings.Contains(location, locationContains) {
		t.Errorf("Expected Location header to contain %q, got %q", locationContains, location)
	}
}

// checkProxyReachable verifies the proxy is responding before running tests.
// Uses the global skipAll flag set in TestMain for fast skipping.
func checkProxyReachable(t *testing.T) {
	t.Helper()
	if skipAll {
		t.Skipf("Skipping: %s", skipReason)
	}
}

// checkTestServerReachable verifies the e2e test server is responding.
// Uses the global skipAll flag set in TestMain for fast skipping.
func checkTestServerReachable(t *testing.T) {
	t.Helper()
	if skipAll {
		t.Skipf("Skipping: %s", skipReason)
	}
}

// truncate shortens a string to maxLen for display in error messages.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + fmt.Sprintf("... (%d bytes total)", len(s))
}

// waitForCondition polls a condition function until it returns true or the timeout is reached.
func waitForCondition(t *testing.T, timeout time.Duration, interval time.Duration, description string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(interval)
	}
	t.Fatalf("Timed out waiting for: %s", description)
}
