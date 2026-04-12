package cel

import (
	"net/http/httptest"
	"testing"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

func TestNewModifier(t *testing.T) {
	tests := []struct {
		name    string
		expr    string
		wantErr bool
	}{
		{
			name: "add headers",
			expr: `{
				"add_headers": {
					"X-Custom": "value"
				}
			}`,
			wantErr: false,
		},
		{
			name: "set headers",
			expr: `{
				"set_headers": {
					"X-Custom": "value"
				}
			}`,
			wantErr: false,
		},
		{
			name: "delete headers",
			expr: `{
				"delete_headers": ["X-Old-Header"]
			}`,
			wantErr: false,
		},
		{
			name: "modify path",
			expr: `{
				"path": "/new/path"
			}`,
			wantErr: false,
		},
		{
			name: "modify method",
			expr: `{
				"method": "POST"
			}`,
			wantErr: false,
		},
		{
			name: "add query params",
			expr: `{
				"add_query": {
					"param": "value"
				}
			}`,
			wantErr: false,
		},
		{
			name: "delete query params",
			expr: `{
				"delete_query": ["old_param"]
			}`,
			wantErr: false,
		},
		{
			name:    "syntax error",
			expr:    `{`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewModifier(tt.expr)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewModifier() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestModifierAddHeaders(t *testing.T) {
	expr := `{
		"add_headers": {
			"X-Custom-1": "value1",
			"X-Custom-2": "value2"
		}
	}`

	modifier, err := NewModifier(expr)
	if err != nil {
		t.Fatalf("NewModifier() error = %v", err)
	}

	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	modifiedReq, err := modifier.Modify(req)
	if err != nil {
		t.Fatalf("Modify() error = %v", err)
	}

	if modifiedReq.Header.Get("X-Custom-1") != "value1" {
		t.Errorf("Expected X-Custom-1 = value1, got %s", modifiedReq.Header.Get("X-Custom-1"))
	}

	if modifiedReq.Header.Get("X-Custom-2") != "value2" {
		t.Errorf("Expected X-Custom-2 = value2, got %s", modifiedReq.Header.Get("X-Custom-2"))
	}
}

func TestModifierSetHeaders(t *testing.T) {
	expr := `{
		"set_headers": {
			"Content-Type": "application/json"
		}
	}`

	modifier, err := NewModifier(expr)
	if err != nil {
		t.Fatalf("NewModifier() error = %v", err)
	}

	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	req.Header.Set("Content-Type", "text/html")

	modifiedReq, err := modifier.Modify(req)
	if err != nil {
		t.Fatalf("Modify() error = %v", err)
	}

	if modifiedReq.Header.Get("Content-Type") != "application/json" {
		t.Errorf("Expected Content-Type = application/json, got %s", modifiedReq.Header.Get("Content-Type"))
	}
}

func TestModifierDeleteHeaders(t *testing.T) {
	expr := `{
		"delete_headers": ["X-Remove-Me"]
	}`

	modifier, err := NewModifier(expr)
	if err != nil {
		t.Fatalf("NewModifier() error = %v", err)
	}

	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	req.Header.Set("X-Remove-Me", "value")
	req.Header.Set("X-Keep-Me", "value")

	modifiedReq, err := modifier.Modify(req)
	if err != nil {
		t.Fatalf("Modify() error = %v", err)
	}

	if modifiedReq.Header.Get("X-Remove-Me") != "" {
		t.Errorf("Expected X-Remove-Me to be deleted")
	}

	if modifiedReq.Header.Get("X-Keep-Me") != "value" {
		t.Errorf("Expected X-Keep-Me to remain")
	}
}

func TestModifierPath(t *testing.T) {
	expr := `{
		"path": "/new/path"
	}`

	modifier, err := NewModifier(expr)
	if err != nil {
		t.Fatalf("NewModifier() error = %v", err)
	}

	req := httptest.NewRequest("GET", "http://example.com/old/path", nil)
	modifiedReq, err := modifier.Modify(req)
	if err != nil {
		t.Fatalf("Modify() error = %v", err)
	}

	if modifiedReq.URL.Path != "/new/path" {
		t.Errorf("Expected path = /new/path, got %s", modifiedReq.URL.Path)
	}
}

func TestModifierMethod(t *testing.T) {
	expr := `{
		"method": "POST"
	}`

	modifier, err := NewModifier(expr)
	if err != nil {
		t.Fatalf("NewModifier() error = %v", err)
	}

	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	modifiedReq, err := modifier.Modify(req)
	if err != nil {
		t.Fatalf("Modify() error = %v", err)
	}

	if modifiedReq.Method != "POST" {
		t.Errorf("Expected method = POST, got %s", modifiedReq.Method)
	}
}

func TestModifierAddQuery(t *testing.T) {
	expr := `{
		"add_query": {
			"new_param": "new_value"
		}
	}`

	modifier, err := NewModifier(expr)
	if err != nil {
		t.Fatalf("NewModifier() error = %v", err)
	}

	req := httptest.NewRequest("GET", "http://example.com/test?existing=value", nil)
	modifiedReq, err := modifier.Modify(req)
	if err != nil {
		t.Fatalf("Modify() error = %v", err)
	}

	if modifiedReq.URL.Query().Get("new_param") != "new_value" {
		t.Errorf("Expected new_param = new_value, got %s", modifiedReq.URL.Query().Get("new_param"))
	}

	if modifiedReq.URL.Query().Get("existing") != "value" {
		t.Errorf("Expected existing param to remain")
	}
}

func TestModifierDeleteQuery(t *testing.T) {
	expr := `{
		"delete_query": ["remove_me"]
	}`

	modifier, err := NewModifier(expr)
	if err != nil {
		t.Fatalf("NewModifier() error = %v", err)
	}

	req := httptest.NewRequest("GET", "http://example.com/test?remove_me=value&keep_me=value", nil)
	modifiedReq, err := modifier.Modify(req)
	if err != nil {
		t.Fatalf("Modify() error = %v", err)
	}

	if modifiedReq.URL.Query().Get("remove_me") != "" {
		t.Errorf("Expected remove_me param to be deleted")
	}

	if modifiedReq.URL.Query().Get("keep_me") != "value" {
		t.Errorf("Expected keep_me param to remain")
	}
}

func TestModifierWithLocation(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	requestData := reqctx.NewRequestData()
	req = req.WithContext(reqctx.SetRequestData(req.Context(), requestData))

	requestData.ClientCtx = &reqctx.ClientContext{
		IP: "192.168.1.1",
		Location: &reqctx.Location{
			CountryCode:   "US",
			ContinentCode: "NA",
		},
	}

	expr := `{
		"add_headers": {
			"X-Country": size(client.location) > 0 ? client.location['country_code'] : "UNKNOWN",
			"X-Continent": size(client.location) > 0 ? client.location['continent_code'] : "UNKNOWN"
		}
	}`

	modifier, err := NewModifier(expr)
	if err != nil {
		t.Fatalf("NewModifier() error = %v", err)
	}

	modifiedReq, err := modifier.Modify(req)
	if err != nil {
		t.Fatalf("Modify() error = %v", err)
	}

	if modifiedReq.Header.Get("X-Country") != "US" {
		t.Errorf("Expected X-Country = US, got %s", modifiedReq.Header.Get("X-Country"))
	}

	if modifiedReq.Header.Get("X-Continent") != "NA" {
		t.Errorf("Expected X-Continent = NA, got %s", modifiedReq.Header.Get("X-Continent"))
	}
}

func TestModifierWithUserAgent(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	requestData := reqctx.NewRequestData()
	req = req.WithContext(reqctx.SetRequestData(req.Context(), requestData))

	requestData.ClientCtx = &reqctx.ClientContext{
		IP: "192.168.1.1",
		UserAgent: &reqctx.UserAgent{
			Family:   "Chrome",
			OSFamily: "Mac OS X",
		},
	}

	expr := `{
		"add_headers": {
			"X-Browser": size(client.user_agent) > 0 ? client.user_agent['family'] : "UNKNOWN",
			"X-OS": size(client.user_agent) > 0 ? client.user_agent['os_family'] : "UNKNOWN"
		}
	}`

	modifier, err := NewModifier(expr)
	if err != nil {
		t.Fatalf("NewModifier() error = %v", err)
	}

	modifiedReq, err := modifier.Modify(req)
	if err != nil {
		t.Fatalf("Modify() error = %v", err)
	}

	if modifiedReq.Header.Get("X-Browser") != "Chrome" {
		t.Errorf("Expected X-Browser = Chrome, got %s", modifiedReq.Header.Get("X-Browser"))
	}

	if modifiedReq.Header.Get("X-OS") != "Mac OS X" {
		t.Errorf("Expected X-OS = Mac OS X, got %s", modifiedReq.Header.Get("X-OS"))
	}
}

func TestModifierWithFingerprint(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	requestData := reqctx.NewRequestData()
	req = req.WithContext(reqctx.SetRequestData(req.Context(), requestData))

	requestData.ClientCtx = &reqctx.ClientContext{
		IP: "192.168.1.1",
		Fingerprint: &reqctx.Fingerprint{
			Hash:    "abc123",
			Version: "v1.0",
		},
	}

	expr := `{
		"add_headers": {
			"X-Fingerprint": size(client.fingerprint) > 0 ? client.fingerprint['hash'] : "NONE",
			"X-FP-Version": size(client.fingerprint) > 0 ? client.fingerprint['version'] : "NONE"
		}
	}`

	modifier, err := NewModifier(expr)
	if err != nil {
		t.Fatalf("NewModifier() error = %v", err)
	}

	modifiedReq, err := modifier.Modify(req)
	if err != nil {
		t.Fatalf("Modify() error = %v", err)
	}

	if modifiedReq.Header.Get("X-Fingerprint") != "abc123" {
		t.Errorf("Expected X-Fingerprint = abc123, got %s", modifiedReq.Header.Get("X-Fingerprint"))
	}

	if modifiedReq.Header.Get("X-FP-Version") != "v1.0" {
		t.Errorf("Expected X-FP-Version = v1.0, got %s", modifiedReq.Header.Get("X-FP-Version"))
	}
}

func TestModifierWithNullContext(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com/test", nil)

	expr := `{
		"add_headers": {
			"X-Country": size(client.location) > 0 ? client.location['country_code'] : "UNKNOWN",
			"X-Browser": size(client.user_agent) > 0 ? client.user_agent['family'] : "UNKNOWN"
		}
	}`

	modifier, err := NewModifier(expr)
	if err != nil {
		t.Fatalf("NewModifier() error = %v", err)
	}

	modifiedReq, err := modifier.Modify(req)
	if err != nil {
		t.Fatalf("Modify() error = %v", err)
	}

	if modifiedReq.Header.Get("X-Country") != "UNKNOWN" {
		t.Errorf("Expected X-Country = UNKNOWN, got %s", modifiedReq.Header.Get("X-Country"))
	}

	if modifiedReq.Header.Get("X-Browser") != "UNKNOWN" {
		t.Errorf("Expected X-Browser = UNKNOWN, got %s", modifiedReq.Header.Get("X-Browser"))
	}
}

func TestModifierConditionalPath(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	requestData := reqctx.NewRequestData()
	req = req.WithContext(reqctx.SetRequestData(req.Context(), requestData))

	requestData.ClientCtx = &reqctx.ClientContext{
		IP: "192.168.1.1",
		UserAgent: &reqctx.UserAgent{
			DeviceFamily: "iPhone",
		},
	}

	expr := `{
		"path": size(client.user_agent) > 0 && client.user_agent['device_family'] == 'iPhone' ? "/mobile" + request.path : request.path
	}`

	modifier, err := NewModifier(expr)
	if err != nil {
		t.Fatalf("NewModifier() error = %v", err)
	}

	modifiedReq, err := modifier.Modify(req)
	if err != nil {
		t.Fatalf("Modify() error = %v", err)
	}

	if modifiedReq.URL.Path != "/mobile/test" {
		t.Errorf("Expected path = /mobile/test, got %s", modifiedReq.URL.Path)
	}
}

func TestModifierCombined(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com/test?old_param=value", nil)
	requestData := reqctx.NewRequestData()
	req = req.WithContext(reqctx.SetRequestData(req.Context(), requestData))
	req.Header.Set("X-Old-Header", "old_value")

	requestData.ClientCtx = &reqctx.ClientContext{
		IP: "192.168.1.1",
		Location: &reqctx.Location{
			CountryCode: "US",
		},
	}

	expr := `{
		"add_headers": {
			"X-Country": size(client.location) > 0 ? client.location['country_code'] : "UNKNOWN"
		},
		"set_headers": {
			"Content-Type": "application/json"
		},
		"delete_headers": ["X-Old-Header"],
		"path": "/api/v2/test",
		"method": "POST",
		"add_query": {
			"new_param": "new_value"
		},
		"delete_query": ["old_param"]
	}`

	modifier, err := NewModifier(expr)
	if err != nil {
		t.Fatalf("NewModifier() error = %v", err)
	}

	modifiedReq, err := modifier.Modify(req)
	if err != nil {
		t.Fatalf("Modify() error = %v", err)
	}

	// Check headers
	if modifiedReq.Header.Get("X-Country") != "US" {
		t.Errorf("Expected X-Country = US")
	}
	if modifiedReq.Header.Get("Content-Type") != "application/json" {
		t.Errorf("Expected Content-Type = application/json")
	}
	if modifiedReq.Header.Get("X-Old-Header") != "" {
		t.Errorf("Expected X-Old-Header to be deleted")
	}

	// Check path and method
	if modifiedReq.URL.Path != "/api/v2/test" {
		t.Errorf("Expected path = /api/v2/test")
	}
	if modifiedReq.Method != "POST" {
		t.Errorf("Expected method = POST")
	}

	// Check query params
	if modifiedReq.URL.Query().Get("new_param") != "new_value" {
		t.Errorf("Expected new_param = new_value")
	}
	if modifiedReq.URL.Query().Get("old_param") != "" {
		t.Errorf("Expected old_param to be deleted")
	}
}
