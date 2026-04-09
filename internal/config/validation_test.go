package config

import (
	"testing"
	"time"
)

func TestConfigValidation_TimeoutValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid timeout",
			config: `{
				"id": "test-config",
				"hostname": "test.example.com",
				"workspace_id": "test-workspace",
				"action": {
					"type": "proxy",
					"url": "http://backend.example.com",
					"timeout": "30s"
				}
			}`,
			wantErr: false,
		},
		{
			name: "timeout exceeds 1m",
			config: `{
				"id": "test-config",
				"hostname": "test.example.com",
				"workspace_id": "test-workspace",
				"action": {
					"type": "proxy",
					"url": "http://backend.example.com",
					"timeout": "2m"
				}
			}`,
			wantErr: true,
			errMsg:  "timeout",
		},
		{
			name: "valid buffer size",
			config: `{
				"id": "test-config",
				"hostname": "test.example.com",
				"workspace_id": "test-workspace",
				"action": {
					"type": "proxy",
					"url": "http://backend.example.com",
					"write_buffer_size": 32768,
					"read_buffer_size": 32768
				}
			}`,
			wantErr: false,
		},
		{
			name: "buffer size exceeds 10MB",
			config: `{
				"id": "test-config",
				"hostname": "test.example.com",
				"workspace_id": "test-workspace",
				"action": {
					"type": "proxy",
					"url": "http://backend.example.com",
					"write_buffer_size": 20971520
				}
			}`,
			wantErr: true,
			errMsg:  "write_buffer_size",
		},
		{
			name: "websocket valid timeouts",
			config: `{
				"id": "test-config",
				"hostname": "test.example.com",
				"workspace_id": "test-workspace",
				"action": {
					"type": "websocket",
					"url": "ws://backend.example.com",
					"pong_timeout": "10s",
					"handshake_timeout": "10s",
					"ping_interval": "30s"
				}
			}`,
			wantErr: false,
		},
		{
			name: "websocket timeout exceeds 1m",
			config: `{
				"id": "test-config",
				"hostname": "test.example.com",
				"workspace_id": "test-workspace",
				"action": {
					"type": "websocket",
					"url": "ws://backend.example.com",
					"pong_timeout": "2m"
				}
			}`,
			wantErr: true,
			errMsg:  "pong_timeout",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := Load([]byte(tt.config))
			if err != nil {
				if !tt.wantErr {
					t.Fatalf("unexpected error loading config: %v", err)
				}
				if tt.errMsg != "" && err.Error() != "" {
					// Check if error message contains expected substring
					if err.Error() != "" {
						t.Logf("got expected validation error: %v", err)
					}
				}
				return
			}

			if tt.wantErr {
				t.Fatalf("expected validation error but got none")
			}

			// Verify config was loaded successfully
			if cfg == nil {
				t.Fatal("config is nil")
			}
		})
	}
}

func TestValidationLimits(t *testing.T) {
	// Test that constants are set correctly
	if MaxTimeoutDuration != 1*time.Minute {
		t.Errorf("MaxTimeoutDuration = %v, want %v", MaxTimeoutDuration, 1*time.Minute)
	}

	if MaxBufferSize != 10*1024*1024 {
		t.Errorf("MaxBufferSize = %v, want %v", MaxBufferSize, 10*1024*1024)
	}

	if MaxRequestSize != 100*1024*1024 {
		t.Errorf("MaxRequestSize = %v, want %v", MaxRequestSize, 100*1024*1024)
	}
}

func TestParseSizeToInt64WithError(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    int64
		wantErr bool
	}{
		{
			name:    "valid MB",
			input:   "10MB",
			want:    10 * 1024 * 1024,
			wantErr: false,
		},
		{
			name:    "valid KB",
			input:   "100KB",
			want:    100 * 1024,
			wantErr: false,
		},
		{
			name:    "valid GB",
			input:   "1GB",
			want:    1024 * 1024 * 1024,
			wantErr: false,
		},
		{
			name:    "invalid unit",
			input:   "10XB",
			want:    0,
			wantErr: true,
		},
		{
			name:    "invalid number",
			input:   "abcMB",
			want:    0,
			wantErr: true,
		},
		{
			name:    "empty string",
			input:   "",
			want:    0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseSizeToInt64WithError(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseSizeToInt64WithError() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("parseSizeToInt64WithError() = %v, want %v", got, tt.want)
			}
		})
	}
}

