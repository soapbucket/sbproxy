package config

import (
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
)

// makeTestTargets creates n compiledTargets with weight 1 each.
func makeTestTargets(n int) []*compiledTarget {
	targets := make([]*compiledTarget, n)
	for i := range targets {
		targets[i] = &compiledTarget{
			Config: &Target{Weight: 1},
			URL:    &url.URL{Scheme: "http", Host: "backend" + string(rune('0'+i))},
		}
	}
	return targets
}

// makeTestLB builds a minimal loadBalancerTransport for testing.
func makeTestLB(algorithm string, targets []*compiledTarget, hashKey string) *loadBalancerTransport {
	return &loadBalancerTransport{
		targets:   targets,
		algorithm: algorithm,
		hashKey:   hashKey,
		random:    rand.New(rand.NewSource(42)),
	}
}

// makeReq builds a minimal *http.Request with the given remote addr.
func makeReq(remoteAddr string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = remoteAddr
	return req
}

// markUnhealthy marks a target as unhealthy.
func markUnhealthy(t *compiledTarget) {
	t.health = &healthStatus{}
	t.health.healthy.Store(false)
}

// TestIPHashConsistency verifies that the same IP (with different ports) always maps to the same target.
func TestIPHashConsistency(t *testing.T) {
	lb := makeTestLB(AlgorithmIPHash, makeTestTargets(5), "")

	req1 := makeReq("192.168.1.1:1234")
	req2 := makeReq("192.168.1.1:9999")
	req3 := makeReq("192.168.1.1:80")

	idx1 := lb.selectIPHashHealthy(req1)
	idx2 := lb.selectIPHashHealthy(req2)
	idx3 := lb.selectIPHashHealthy(req3)

	if idx1 < 0 {
		t.Fatal("expected valid target index, got -1")
	}
	if idx1 != idx2 || idx1 != idx3 {
		t.Errorf("same IP should always hash to same target: got %d, %d, %d", idx1, idx2, idx3)
	}
}

// TestIPHashDifferentIPs verifies that different IPs distribute across targets.
func TestIPHashDifferentIPs(t *testing.T) {
	lb := makeTestLB(AlgorithmIPHash, makeTestTargets(5), "")

	seen := make(map[int]bool)
	ips := []string{
		"10.0.0.1:1", "10.0.0.2:1", "10.0.0.3:1", "10.0.0.4:1", "10.0.0.5:1",
		"192.168.1.1:1", "172.16.0.1:1", "8.8.8.8:1", "1.1.1.1:1", "10.10.10.10:1",
	}
	for _, ip := range ips {
		req := makeReq(ip)
		idx := lb.selectIPHashHealthy(req)
		if idx < 0 {
			t.Fatalf("unexpected -1 for ip %s", ip)
		}
		seen[idx] = true
	}
	if len(seen) < 2 {
		t.Errorf("expected IPs to spread across multiple targets, only saw %d distinct targets", len(seen))
	}
}

// TestIPHashSkipsUnhealthy verifies that ip_hash probes forward when the hashed target is unhealthy.
func TestIPHashSkipsUnhealthy(t *testing.T) {
	targets := makeTestTargets(3)
	lb := makeTestLB(AlgorithmIPHash, targets, "")

	req := makeReq("192.168.1.1:1234")
	primary := lb.selectIPHashHealthy(req)
	if primary < 0 {
		t.Fatal("expected valid primary index")
	}

	// Mark that target unhealthy and re-select
	markUnhealthy(targets[primary])
	fallback := lb.selectIPHashHealthy(req)
	if fallback < 0 {
		t.Fatal("expected fallback target to be selected")
	}
	if fallback == primary {
		t.Errorf("expected fallback to differ from unhealthy primary %d", primary)
	}
}

// TestURIHashConsistency verifies that the same path (different methods) always maps to the same target.
func TestURIHashConsistency(t *testing.T) {
	lb := makeTestLB(AlgorithmURIHash, makeTestTargets(5), "")

	newReqWithPath := func(method, path string) *http.Request {
		req := httptest.NewRequest(method, path, nil)
		req.RemoteAddr = "1.2.3.4:1234"
		return req
	}

	path := "/api/v1/users"
	idx1 := lb.selectURIHashHealthy(newReqWithPath(http.MethodGet, path))
	idx2 := lb.selectURIHashHealthy(newReqWithPath(http.MethodPost, path))
	idx3 := lb.selectURIHashHealthy(newReqWithPath(http.MethodDelete, path))

	if idx1 < 0 {
		t.Fatal("expected valid target index")
	}
	if idx1 != idx2 || idx1 != idx3 {
		t.Errorf("same path should always hash to same target: got %d, %d, %d", idx1, idx2, idx3)
	}
}

// TestURIHashDifferentPaths verifies that different paths spread across targets.
func TestURIHashDifferentPaths(t *testing.T) {
	lb := makeTestLB(AlgorithmURIHash, makeTestTargets(5), "")

	paths := []string{"/a", "/b", "/c", "/d", "/e", "/f", "/api/users", "/api/orders", "/health", "/metrics"}
	seen := make(map[int]bool)
	for _, p := range paths {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		req.RemoteAddr = "1.2.3.4:1"
		idx := lb.selectURIHashHealthy(req)
		if idx < 0 {
			t.Fatalf("unexpected -1 for path %s", p)
		}
		seen[idx] = true
	}
	if len(seen) < 2 {
		t.Errorf("expected paths to spread across multiple targets, only saw %d distinct targets", len(seen))
	}
}

// TestHeaderHashConsistency verifies that the same header value always routes consistently.
func TestHeaderHashConsistency(t *testing.T) {
	lb := makeTestLB(AlgorithmHeaderHash, makeTestTargets(5), "X-User-ID")

	makeHeaderReq := func(headerVal string) *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "1.2.3.4:1234"
		req.Header.Set("X-User-ID", headerVal)
		return req
	}

	val := "user-abc"
	idx1 := lb.selectHeaderHashHealthy(makeHeaderReq(val))
	idx2 := lb.selectHeaderHashHealthy(makeHeaderReq(val))
	idx3 := lb.selectHeaderHashHealthy(makeHeaderReq(val))

	if idx1 < 0 {
		t.Fatal("expected valid target index")
	}
	if idx1 != idx2 || idx1 != idx3 {
		t.Errorf("same header value should always hash to same target: got %d, %d, %d", idx1, idx2, idx3)
	}
}

// TestHeaderHashMissingHeader verifies that header_hash falls back gracefully when the header is absent.
func TestHeaderHashMissingHeader(t *testing.T) {
	lb := makeTestLB(AlgorithmHeaderHash, makeTestTargets(3), "X-User-ID")

	// Request without the header - should fall back to RemoteAddr hash
	req := makeReq("10.0.0.1:9999")
	idx1 := lb.selectHeaderHashHealthy(req)
	idx2 := lb.selectHeaderHashHealthy(req)

	if idx1 < 0 {
		t.Fatal("expected valid target even when header is missing")
	}
	if idx1 != idx2 {
		t.Errorf("same fallback (RemoteAddr) should hash consistently: got %d and %d", idx1, idx2)
	}
}

// TestCookieHashConsistency verifies that the same cookie value routes consistently.
func TestCookieHashConsistency(t *testing.T) {
	lb := makeTestLB(AlgorithmCookieHash, makeTestTargets(5), "session_id")

	makeCookieReq := func(cookieVal string) *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "1.2.3.4:1234"
		req.AddCookie(&http.Cookie{Name: "session_id", Value: cookieVal})
		return req
	}

	val := "sess-xyz-123"
	idx1 := lb.selectCookieHashHealthy(makeCookieReq(val))
	idx2 := lb.selectCookieHashHealthy(makeCookieReq(val))

	if idx1 < 0 {
		t.Fatal("expected valid target index")
	}
	if idx1 != idx2 {
		t.Errorf("same cookie value should hash to same target: got %d and %d", idx1, idx2)
	}
}

// TestCookieHashMissingCookie verifies that cookie_hash falls back to RemoteAddr when cookie is absent.
func TestCookieHashMissingCookie(t *testing.T) {
	lb := makeTestLB(AlgorithmCookieHash, makeTestTargets(3), "session_id")

	req := makeReq("10.0.0.2:8080")
	idx1 := lb.selectCookieHashHealthy(req)
	idx2 := lb.selectCookieHashHealthy(req)

	if idx1 < 0 {
		t.Fatal("expected valid target even when cookie is missing")
	}
	if idx1 != idx2 {
		t.Errorf("same fallback (RemoteAddr) should hash consistently: got %d and %d", idx1, idx2)
	}
}

// TestRandomDistribution verifies that random roughly distributes across all targets.
func TestRandomDistribution(t *testing.T) {
	targets := makeTestTargets(4)
	lb := &loadBalancerTransport{
		targets:   targets,
		algorithm: AlgorithmRandom,
		random:    rand.New(rand.NewSource(12345)),
	}

	counts := make(map[int]int)
	const iterations = 1000
	for i := 0; i < iterations; i++ {
		idx := lb.selectRandomHealthy()
		if idx < 0 {
			t.Fatalf("unexpected -1 from selectRandomHealthy")
		}
		counts[idx]++
	}

	// Each target should receive roughly 25% (250/1000). Allow wide tolerance for randomness.
	for i, count := range counts {
		if count < 150 || count > 400 {
			t.Errorf("target %d received %d/%d selections - distribution seems off", i, count, iterations)
		}
	}
}

// TestRandomDistributionConcurrent verifies thread-safety of the random algorithm.
func TestRandomDistributionConcurrent(t *testing.T) {
	targets := makeTestTargets(3)
	lb := &loadBalancerTransport{
		targets:   targets,
		algorithm: AlgorithmRandom,
		random:    rand.New(rand.NewSource(99)),
	}

	var wg sync.WaitGroup
	errs := make(chan error, 100)
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				idx := lb.selectRandomHealthy()
				if idx < 0 {
					errs <- nil // signal unexpected -1 via nil sentinel
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	if len(errs) > 0 {
		t.Errorf("got %d unexpected -1 results from concurrent selectRandomHealthy", len(errs))
	}
}

// TestFirstSelectsFirst verifies that first always picks index 0 when all targets are healthy.
func TestFirstSelectsFirst(t *testing.T) {
	lb := makeTestLB(AlgorithmFirst, makeTestTargets(4), "")

	for i := 0; i < 10; i++ {
		idx := lb.selectFirstHealthy()
		if idx != 0 {
			t.Errorf("expected index 0, got %d", idx)
		}
	}
}

// TestFirstSkipsUnhealthy verifies that first skips unhealthy targets and picks the next healthy one.
func TestFirstSkipsUnhealthy(t *testing.T) {
	targets := makeTestTargets(3)
	lb := makeTestLB(AlgorithmFirst, targets, "")

	// Mark target 0 unhealthy
	markUnhealthy(targets[0])

	idx := lb.selectFirstHealthy()
	if idx != 1 {
		t.Errorf("expected index 1 (first healthy), got %d", idx)
	}
}

// TestFirstAllUnhealthy verifies that first returns -1 when all targets are unhealthy.
func TestFirstAllUnhealthy(t *testing.T) {
	targets := makeTestTargets(3)
	lb := makeTestLB(AlgorithmFirst, targets, "")

	for _, target := range targets {
		markUnhealthy(target)
	}

	idx := lb.selectFirstHealthy()
	if idx != -1 {
		t.Errorf("expected -1 when all targets unhealthy, got %d", idx)
	}
}

// TestIPHashEmptyTargets verifies all hash algorithms return -1 with no targets.
func TestIPHashEmptyTargets(t *testing.T) {
	lb := makeTestLB(AlgorithmIPHash, []*compiledTarget{}, "")
	req := makeReq("1.2.3.4:1234")

	if lb.selectIPHashHealthy(req) != -1 {
		t.Error("expected -1 for empty targets (ip_hash)")
	}
	if lb.selectURIHashHealthy(req) != -1 {
		t.Error("expected -1 for empty targets (uri_hash)")
	}
	if lb.selectHeaderHashHealthy(req) != -1 {
		t.Error("expected -1 for empty targets (header_hash)")
	}
	if lb.selectCookieHashHealthy(req) != -1 {
		t.Error("expected -1 for empty targets (cookie_hash)")
	}
	if lb.selectRandomHealthy() != -1 {
		t.Error("expected -1 for empty targets (random)")
	}
	if lb.selectFirstHealthy() != -1 {
		t.Error("expected -1 for empty targets (first)")
	}
}
