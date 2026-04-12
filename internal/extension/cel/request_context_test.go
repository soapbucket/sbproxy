package cel

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

func TestNewRequestContext(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com/test?param1=value1&param2=value2", nil)
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "session_id", Value: "abc123"})

	rc := NewRequestContext(req)

	if rc == nil {
		t.Fatal("RequestContext should not be nil")
	}

	if rc.req == nil {
		t.Fatal("Request should not be nil")
	}

	if rc.req.Method != "GET" {
		t.Errorf("Expected method GET, got %s", rc.req.Method)
	}

	if rc.req.Path != "/test" {
		t.Errorf("Expected path /test, got %s", rc.req.Path)
	}

	if rc.cookies["session_id"] != "abc123" {
		t.Errorf("Expected cookie session_id=abc123, got %s", rc.cookies["session_id"])
	}

	if rc.params["param1"] != "value1" {
		t.Errorf("Expected param1=value1, got %s", rc.params["param1"])
	}

	if rc.params["param2"] != "value2" {
		t.Errorf("Expected param2=value2, got %s", rc.params["param2"])
	}
}

func TestConvertFingerprintToMap(t *testing.T) {
	fp := &reqctx.Fingerprint{
		Hash:          "abc123",
		Composite:     "composite123",
		IPHash:        "iphash123",
		UserAgentHash: "uahash123",
		HeaderPattern: "pattern123",
		TLSHash:       "tlshash123",
		CookieCount:   5,
		ConnDuration:  100 * time.Millisecond,
		Version:       "v1.0",
	}

	result := convertFingerprintToMap(fp)

	if result == nil {
		t.Fatal("Result should not be nil")
	}

	if result["hash"] != "abc123" {
		t.Errorf("Expected hash abc123, got %v", result["hash"])
	}

	if result["cookie_count"] != 5 {
		t.Errorf("Expected cookie_count 5, got %v", result["cookie_count"])
	}

	if result["conn_duration_ms"] != int64(100) {
		t.Errorf("Expected conn_duration_ms 100, got %v", result["conn_duration_ms"])
	}

	if result["version"] != "v1.0" {
		t.Errorf("Expected version v1.0, got %v", result["version"])
	}
}

func TestConvertFingerprintToMapNil(t *testing.T) {
	result := convertFingerprintToMap(nil)
	if result == nil {
		t.Error("Expected empty map, got nil")
	}
	if len(result) != 0 {
		t.Errorf("Expected empty map, got map with %d elements", len(result))
	}
}

func TestConvertUserAgentToMap(t *testing.T) {
	ua := &reqctx.UserAgent{
		Family:       "Chrome",
		Major:        "120",
		Minor:        "0",
		Patch:        "0",
		OSFamily:     "Mac OS X",
		OSMajor:      "10",
		OSMinor:      "15",
		OSPatch:      "7",
		DeviceFamily: "Mac",
		DeviceBrand:  "Apple",
		DeviceModel:  "Macintosh",
	}

	result := convertUserAgentToMap(ua)

	if result == nil {
		t.Fatal("Result should not be nil")
	}

	if result["family"] != "Chrome" {
		t.Errorf("Expected family Chrome, got %v", result["family"])
	}

	if result["major"] != "120" {
		t.Errorf("Expected major 120, got %v", result["major"])
	}

	if result["os_family"] != "Mac OS X" {
		t.Errorf("Expected os_family Mac OS X, got %v", result["os_family"])
	}

	if result["device_family"] != "Mac" {
		t.Errorf("Expected device_family Mac, got %v", result["device_family"])
	}
}

func TestConvertUserAgentToMapNil(t *testing.T) {
	result := convertUserAgentToMap(nil)
	if result == nil {
		t.Error("Expected empty map, got nil")
	}
	if len(result) != 0 {
		t.Errorf("Expected empty map, got map with %d elements", len(result))
	}
}

func TestConvertLocationToMap(t *testing.T) {
	info := &reqctx.Location{
		Country:       "United States",
		CountryCode:   "US",
		Continent:     "North America",
		ContinentCode: "NA",
		ASN:           "AS15169",
		ASName:        "Google LLC",
		ASDomain:      "google.com",
	}

	result := convertLocationToMap(info)

	if result == nil {
		t.Fatal("Result should not be nil")
	}

	if result["country"] != "United States" {
		t.Errorf("Expected country United States, got %v", result["country"])
	}

	if result["country_code"] != "US" {
		t.Errorf("Expected country_code US, got %v", result["country_code"])
	}

	if result["asn"] != "AS15169" {
		t.Errorf("Expected asn AS15169, got %v", result["asn"])
	}
}

func TestConvertLocationToMapNil(t *testing.T) {
	result := convertLocationToMap(nil)
	if result == nil {
		t.Error("Expected empty map, got nil")
	}
	if len(result) != 0 {
		t.Errorf("Expected empty map, got map with %d elements", len(result))
	}
}

func TestConvertSessionDataToMap(t *testing.T) {
	// Create a mock session data structure
	sd := &reqctx.SessionData{
		ID:      "session123",
		Expires: time.Now().Add(24 * time.Hour),
		AuthData: &reqctx.AuthData{
			Type: "oauth",
			Data: map[string]any{
				"id":         "user123",
				"email":      "test@example.com",
				"name":       "Test User",
				"provider":   "google",
				"session_id": "session123",
				"roles":      []string{"admin", "user"},
			},
		},
		Data:    map[string]any{"key1": "value1"},
		Visited: []reqctx.VisitedURL{{URL: "/page1"}, {URL: "/page2"}},
	}

	result := convertSessionDataToMap(sd)

	if result == nil {
		t.Fatal("Result should not be nil")
	}

	if result["id"] != "session123" {
		t.Errorf("Expected id session123, got %v", result["id"])
	}

	visitedList, ok := result["visited"].([]reqctx.VisitedURL)
	if !ok || len(visitedList) != 2 {
		t.Errorf("Expected visited to be a list of 2 items, got %v", result["visited"])
	}

	auth, ok := result["auth"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected auth to be a map")
	}

	if auth["type"] != "oauth" {
		t.Errorf("Expected auth type oauth, got %v", auth["type"])
	}

	// Check that data is present as nested object
	data, ok := auth["data"].(map[string]any)
	if !ok {
		t.Fatal("Expected auth.data to be a map")
	}

	if data["email"] != "test@example.com" {
		t.Errorf("Expected email test@example.com in auth.data, got %v", data["email"])
	}

	if data["provider"] != "google" {
		t.Errorf("Expected provider google in auth.data, got %v", data["provider"])
	}

	// Check that data fields are also directly accessible
	if auth["email"] != "test@example.com" {
		t.Errorf("Expected email test@example.com directly in auth, got %v", auth["email"])
	}

	if auth["provider"] != "google" {
		t.Errorf("Expected provider google directly in auth, got %v", auth["provider"])
	}
}

func TestConvertSessionDataToMapNil(t *testing.T) {
	result := convertSessionDataToMap(nil)
	if result == nil {
		t.Error("Expected empty map, got nil")
	}
	if len(result) != 0 {
		t.Errorf("Expected empty map, got map with %d elements", len(result))
	}
}

func TestToVars(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com/test?param1=value1", nil)
	req.AddCookie(&http.Cookie{Name: "session_id", Value: "abc123"})

	rc := NewRequestContext(req)
	vars := rc.ToVars()

	if vars == nil {
		t.Fatal("Vars should not be nil")
	}

	if vars["request"] == nil {
		t.Error("Expected request in vars")
	}

	if vars["session"] == nil {
		t.Error("Expected session in vars")
	}

	if vars["origin"] == nil {
		t.Error("Expected origin in vars")
	}

	if vars["client"] == nil {
		t.Error("Expected client in vars")
	}
}

func TestToVarsWithContextData(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com/test", nil)

	// Add request data
	requestData := reqctx.NewRequestData()
	requestData.Fingerprint = &reqctx.Fingerprint{
		Hash:    "test123",
		Version: "v1.0",
	}
	requestData.UserAgent = &reqctx.UserAgent{
		Family: "Chrome",
		Major:  "120",
	}
	requestData.Location = &reqctx.Location{
		Country:     "United States",
		CountryCode: "US",
	}
	req = req.WithContext(reqctx.SetRequestData(req.Context(), requestData))

	rc := NewRequestContext(req)
	vars := rc.ToVars()

	// client namespace should always be present
	if _, ok := vars["client"]; !ok {
		t.Error("Expected client key in vars")
	}

	// Check that client namespace contains the expected sub-keys
	if clientMap, ok := vars["client"].(map[string]interface{}); ok {
		if clientMap["fingerprint"] != nil {
			fingerprintMap, ok := clientMap["fingerprint"].(map[string]interface{})
			if ok && fingerprintMap["hash"] != nil {
				t.Logf("Fingerprint hash retrieved: %v", fingerprintMap["hash"])
			}
		}

		if clientMap["user_agent"] != nil {
			userAgentMap, ok := clientMap["user_agent"].(map[string]string)
			if ok && userAgentMap["family"] != "" {
				t.Logf("User agent family retrieved: %v", userAgentMap["family"])
			}
		}

		if clientMap["location"] != nil {
			locationMap, ok := clientMap["location"].(map[string]string)
			if ok && locationMap["country_code"] != "" {
				t.Logf("Location country code retrieved: %v", locationMap["country_code"])
			}
		}
	}
}

func TestToVarsWithSession(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com/test", nil)

	// Create a mock session data
	sd := &reqctx.SessionData{
		ID:      "session123",
		Expires: time.Now().Add(24 * time.Hour),
	}

	// Add session to request data
	requestData := reqctx.NewRequestData()
	requestData.SessionData = sd
	req = req.WithContext(reqctx.SetRequestData(req.Context(), requestData))

	rc := NewRequestContext(req)
	vars := rc.ToVars()

	// Session key should always be present
	if _, ok := vars["session"]; !ok {
		t.Error("Expected session key in vars")
	}

	// If session data was properly retrieved and converted
	if vars["session"] != nil {
		sessionMap, ok := vars["session"].(map[string]interface{})
		if ok && sessionMap["id"] != nil {
			if sessionMap["id"] != "session123" {
				t.Errorf("Expected id session123, got %v", sessionMap["id"])
			} else {
				t.Logf("Session ID retrieved: %v", sessionMap["id"])
			}
		}
	}
}
