package e2e

import (
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"
)

// skipAll is set to true if the test infrastructure is not available.
// This prevents each individual test from waiting for the 5-second timeout.
var skipAll bool
var skipReason string

func TestMain(m *testing.M) {
	// Check if the proxy and test server are reachable before running any tests.
	// This avoids each test waiting 5 seconds for the timeout.
	client := &http.Client{Timeout: 5 * time.Second}

	telemetryURL := getEnv("E2E_PROXY_TELEMETRY_URL", "http://localhost:8888")
	resp, err := client.Get(telemetryURL + "/metrics")
	if err != nil {
		skipAll = true
		skipReason = fmt.Sprintf("Proxy not reachable at %s/metrics: %v", telemetryURL, err)
		fmt.Fprintf(os.Stderr, "WARNING: %s\n", skipReason)
		fmt.Fprintf(os.Stderr, "All E2E tests will be skipped.\n\n")
	} else {
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			skipAll = true
			skipReason = fmt.Sprintf("Proxy returned status %d at %s/metrics", resp.StatusCode, telemetryURL)
		}
	}

	if !skipAll {
		testURL := getEnv("E2E_TEST_SERVER_URL", "http://localhost:8090")
		resp, err = client.Get(testURL + "/health")
		if err != nil {
			skipAll = true
			skipReason = fmt.Sprintf("E2E test server not reachable at %s/health: %v", testURL, err)
			fmt.Fprintf(os.Stderr, "WARNING: %s\n", skipReason)
			fmt.Fprintf(os.Stderr, "All E2E tests will be skipped.\n\n")
		} else {
			resp.Body.Close()
		}
	}

	os.Exit(m.Run())
}
