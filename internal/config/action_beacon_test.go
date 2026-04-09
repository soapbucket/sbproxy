package config

import (
	"io"
	"net/http"
	"testing"
)

func TestLoadBeaconConfig(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
	}{
		{
			name: "basic beacon config",
			input: `{
				"type": "beacon",
				"status_code": 204
			}`,
			expectError: false,
		},
		{
			name: "beacon config with body",
			input: `{
				"type": "beacon",
				"status_code": 200,
				"content_type": "image/gif",
				"body_base64": "R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"
			}`,
			expectError: false,
		},
		{
			name: "invalid json",
			input: `{
				"type": "beacon",
				"status_code": "invalid"
			}`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := LoadBeaconConfig([]byte(tt.input))
			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if cfg == nil {
				t.Fatal("expected config but got nil")
			}

			if cfg.GetType() != TypeBeacon {
				t.Errorf("expected type %s, got %s", TypeBeacon, cfg.GetType())
			}

			// Test transport is set
			if cfg.Transport() == nil {
				t.Error("expected transport to be set")
			}
		})
	}
}

func TestBeaconConfig_Integration(t *testing.T) {
	// Beacon is essentially a static config, so we test it works the same way
	config := &BeaconActionConfig{}
	config.StaticConfig = StaticConfig{
		BaseAction: BaseAction{
			ActionType: TypeBeacon,
		},
		StatusCode:  204,
		ContentType: "application/octet-stream",
	}

	transportFn := StaticTransportFn(&config.StaticConfig)
	req, err := http.NewRequest("GET", "http://example.com/beacon", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	resp, err := transportFn(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.StatusCode != 204 {
		t.Errorf("expected status code 204, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read body: %v", err)
	}
	resp.Body.Close()

	if len(body) != 0 {
		t.Errorf("expected empty body for 204 response, got %d bytes", len(body))
	}
}

func TestBeaconConfig_WithPixel(t *testing.T) {
	// Test with a 1x1 transparent GIF (common tracking pixel)
	config := &BeaconActionConfig{}
	config.StaticConfig = StaticConfig{
		BaseAction: BaseAction{
			ActionType: TypeBeacon,
		},
		StatusCode:  200,
		ContentType: "image/gif",
		// 1x1 transparent GIF base64 encoded
		BodyBase64: "R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7",
	}

	transportFn := StaticTransportFn(&config.StaticConfig)
	req, err := http.NewRequest("GET", "http://example.com/pixel.gif", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	resp, err := transportFn(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Errorf("expected status code 200, got %d", resp.StatusCode)
	}

	if resp.Header.Get("Content-Type") != "image/gif" {
		t.Errorf("expected content type image/gif, got %s", resp.Header.Get("Content-Type"))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read body: %v", err)
	}
	resp.Body.Close()

	// GIF should start with "GIF89a" or "GIF87a"
	if len(body) < 6 {
		t.Errorf("expected GIF data, got %d bytes", len(body))
	} else if string(body[0:3]) != "GIF" {
		t.Errorf("expected GIF header, got %q", string(body[0:3]))
	}
}

func TestBeaconConfig_EmptyGIF(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
		checkBody   bool
	}{
		{
			name: "beacon with empty_gif true",
			input: `{
				"type": "beacon",
				"empty_gif": true
			}`,
			expectError: false,
			checkBody:   true,
		},
		{
			name: "beacon with empty_gif false",
			input: `{
				"type": "beacon",
				"empty_gif": false
			}`,
			expectError: false,
			checkBody:   false,
		},
		{
			name: "beacon with empty_gif and custom status",
			input: `{
				"type": "beacon",
				"empty_gif": true,
				"status_code": 201
			}`,
			expectError: false,
			checkBody:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := LoadBeaconConfig([]byte(tt.input))
			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if cfg == nil {
				t.Fatal("expected config but got nil")
			}

			beaconCfg, ok := cfg.(*BeaconActionConfig)
			if !ok {
				t.Fatal("expected BeaconActionConfig")
			}

			if tt.checkBody {
				// Verify that EmptyGIF sets the correct defaults
				if beaconCfg.BodyBase64 == "" {
					t.Error("expected BodyBase64 to be set when EmptyGIF is true")
				}
				if beaconCfg.BodyBase64 != EmptyGIF1x1 {
					t.Errorf("expected BodyBase64 to be %s, got %s", EmptyGIF1x1, beaconCfg.BodyBase64)
				}
				if beaconCfg.ContentType != "image/gif" {
					t.Errorf("expected ContentType to be image/gif, got %s", beaconCfg.ContentType)
				}
			}

			// Test that transport works
			transportFn := beaconCfg.Transport()
			if transportFn == nil {
				t.Fatal("expected transport to be set")
			}

			req, err := http.NewRequest("GET", "http://example.com/beacon", nil)
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}

			resp, err := transportFn(req)
			if err != nil {
				t.Fatalf("unexpected error from transport: %v", err)
			}

			if tt.checkBody {
				if resp.Header.Get("Content-Type") != "image/gif" {
					t.Errorf("expected Content-Type image/gif, got %s", resp.Header.Get("Content-Type"))
				}

				body, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatalf("failed to read body: %v", err)
				}
				resp.Body.Close()

				// Verify it's a valid GIF
				if len(body) < 6 {
					t.Errorf("expected GIF data, got %d bytes", len(body))
				} else if string(body[0:3]) != "GIF" {
					t.Errorf("expected GIF header, got %q", string(body[0:3]))
				}
			}
		})
	}
}

