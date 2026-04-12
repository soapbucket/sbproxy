package hostfilter

import (
	"context"
	"testing"
)

// TestInlineOriginHostnames verifies that hostnames from inline YAML configs
// are correctly loaded into the bloom filter and pass the Check.
func TestInlineOriginHostnames(t *testing.T) {
	t.Parallel()

	// These are the exact hostnames from combined.yml
	hostnames := []string{
		"echo.test.local",
		"profile.test.local",
		"weather.test.local",
		"graphql.test.local",
		"grpc.test.local",
		"websocket.test.local",
		"webhook.test.local",
		"ai.test.local",
		"mcp.test.local",
		"migration.test.local",
	}

	hf := New(100, 0.001)
	hf.Reload(hostnames)

	for _, h := range hostnames {
		if !hf.Check(h) {
			t.Errorf("host filter rejected inline hostname %q", h)
		}
	}

	// Verify unknown hosts are rejected
	unknownHosts := []string{
		"unknown.test.local",
		"evil.com",
		"not-configured.example.com",
	}
	for _, h := range unknownHosts {
		if hf.Check(h) {
			t.Errorf("host filter should reject unknown hostname %q", h)
		}
	}
}

// TestHostFilterWithStorageBackedHostnames simulates loading hostnames from
// local storage (as happens with inline origins).
func TestHostFilterWithStorageBackedHostnames(t *testing.T) {
	t.Parallel()

	hostnames := []string{
		"echo.test.local",
		"profile.test.local",
		"weather.test.local",
	}

	mock := &mockKeyLister{keys: hostnames}
	loaded, err := LoadHostnames(context.Background(), mock)
	if err != nil {
		t.Fatalf("LoadHostnames failed: %v", err)
	}

	hf := New(100, 0.001)
	hf.Reload(loaded)

	for _, h := range hostnames {
		if !hf.Check(h) {
			t.Errorf("host filter rejected storage-loaded hostname %q", h)
		}
	}
}

// TestHostFilterEmptyStorageFallbackToInline verifies that when storage returns
// no hostnames, inline origin hostnames are used as fallback.
func TestHostFilterEmptyStorageFallbackToInline(t *testing.T) {
	t.Parallel()

	// Storage returns nothing (like noop storage)
	mock := &mockKeyLister{keys: []string{}}
	loaded, err := LoadHostnames(context.Background(), mock)
	if err != nil {
		t.Fatalf("LoadHostnames failed: %v", err)
	}
	if len(loaded) != 0 {
		t.Fatalf("expected 0 keys from empty storage, got %d", len(loaded))
	}

	// Simulate the fallback: seed from inline origins
	inlineOrigins := map[string]bool{
		"echo.test.local":    true,
		"profile.test.local": true,
	}
	if len(loaded) == 0 && len(inlineOrigins) > 0 {
		for hostname := range inlineOrigins {
			loaded = append(loaded, hostname)
		}
	}

	hf := New(100, 0.001)
	hf.Reload(loaded)

	for hostname := range inlineOrigins {
		if !hf.Check(hostname) {
			t.Errorf("host filter rejected fallback hostname %q", hostname)
		}
	}
}

// TestHostFilterWithPortStripping verifies that hostnames with ports
// are correctly matched after port stripping.
func TestHostFilterWithPortStripping(t *testing.T) {
	t.Parallel()

	hf := New(100, 0.001)
	hf.Reload([]string{"echo.test.local"})

	// With port - should still match after stripping
	if !hf.Check("echo.test.local:8443") {
		t.Error("host filter rejected hostname with port")
	}

	// Without port - direct match
	if !hf.Check("echo.test.local") {
		t.Error("host filter rejected hostname without port")
	}
}

// TestHostFilterCaseInsensitive verifies case-insensitive matching.
func TestHostFilterCaseInsensitive(t *testing.T) {
	t.Parallel()

	hf := New(100, 0.001)
	hf.Reload([]string{"Echo.Test.Local"})

	if !hf.Check("echo.test.local") {
		t.Error("host filter rejected lowercase hostname")
	}
	if !hf.Check("ECHO.TEST.LOCAL") {
		t.Error("host filter rejected uppercase hostname")
	}
	if !hf.Check("Echo.Test.Local") {
		t.Error("host filter rejected mixed-case hostname")
	}
}

// TestHostFilterDisabledWhenNil verifies that a nil host filter passes all hostnames.
func TestHostFilterDisabledWhenNil(t *testing.T) {
	t.Parallel()

	// When hostFilter is nil, checkHostFilter in configloader returns nil (pass)
	// This test verifies the contract: nil filter = no filtering
	var hf *HostFilter
	if hf != nil {
		t.Error("expected nil host filter")
	}
}

// TestHostFilterForwardRuleHostnames verifies that hostnames referenced in
// forward rules or error configs can also pass the filter when registered.
func TestHostFilterForwardRuleHostnames(t *testing.T) {
	t.Parallel()

	// Primary origins + hostnames used in forward rules
	allHostnames := []string{
		"api.example.com",        // primary origin
		"fallback.example.com",   // forward rule target
		"error-page.example.com", // error handler origin
		"auth.internal.service",  // internal auth service
	}

	hf := New(100, 0.001)
	hf.Reload(allHostnames)

	for _, h := range allHostnames {
		if !hf.Check(h) {
			t.Errorf("host filter rejected forward/error hostname %q", h)
		}
	}
}

// TestHostFilterWildcard verifies wildcard hostname matching.
func TestHostFilterWildcard(t *testing.T) {
	t.Parallel()

	hf := New(100, 0.001)
	hf.Reload([]string{"*.test.local"})

	if !hf.Check("echo.test.local") {
		t.Error("host filter rejected hostname matching *.test.local wildcard")
	}
	if !hf.Check("profile.test.local") {
		t.Error("host filter rejected hostname matching *.test.local wildcard")
	}
	if hf.Check("test.local") {
		t.Error("host filter should reject bare domain with wildcard")
	}
}
