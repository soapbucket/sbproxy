package config

import (
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"
)

func TestLoadGRPCAction(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid grpc config",
			input: `{
				"type": "grpc",
				"url": "grpc://backend.example.com:50051"
			}`,
			expectError: false,
		},
		{
			name: "grpc with https scheme",
			input: `{
				"type": "grpc",
				"url": "https://backend.example.com:50051"
			}`,
			expectError: false,
		},
		{
			name: "grpc with strip base path",
			input: `{
				"type": "grpc",
				"url": "grpc://backend.example.com:50051",
				"strip_base_path": true
			}`,
			expectError: false,
		},
		{
			name: "grpc with preserve query",
			input: `{
				"type": "grpc",
				"url": "grpc://backend.example.com:50051",
				"preserve_query": true
			}`,
			expectError: false,
		},
		{
			name: "grpc with grpc-web enabled",
			input: `{
				"type": "grpc",
				"url": "https://backend.example.com:50051",
				"enable_grpc_web": true
			}`,
			expectError: false,
		},
		{
			name: "grpc with message size limits",
			input: `{
				"type": "grpc",
				"url": "grpc://backend.example.com:50051",
				"max_call_recv_msg_size": 10485760,
				"max_call_send_msg_size": 10485760
			}`,
			expectError: false,
		},
		{
			name: "grpc with connection settings",
			input: `{
				"type": "grpc",
				"url": "grpc://backend.example.com:50051",
				"skip_tls_verify_host": true,
				"timeout": 30000000000
			}`,
			expectError: false,
		},
		{
			name: "grpc with http11_only disabled automatically",
			input: `{
				"type": "grpc",
				"url": "grpc://backend.example.com:50051",
				"http11_only": true
			}`,
			expectError: false,
		},
		{
			name: "invalid url",
			input: `{
				"type": "grpc",
				"url": "not a valid url"
			}`,
			expectError: true,
			errorMsg:    "scheme",
		},
		{
			name: "missing url",
			input: `{
				"type": "grpc"
			}`,
			expectError: true,
			errorMsg:    "url is required",
		},
		{
			name: "invalid scheme",
			input: `{
				"type": "grpc",
				"url": "ftp://backend.example.com:50051"
			}`,
			expectError: true,
			errorMsg:    "scheme",
		},
		{
			name: "invalid json",
			input: `{
				"type": "grpc",
				"url": 12345
			}`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := NewGRPCAction([]byte(tt.input))
			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				} else if tt.errorMsg != "" && !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tt.errorMsg)) {
					t.Errorf("expected error containing %q, got %q", tt.errorMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if cfg == nil {
				t.Fatal("expected config but got nil")
			}

			if cfg.GetType() != TypeGRPC {
				t.Errorf("expected type %s, got %s", TypeGRPC, cfg.GetType())
			}

			// Test transport is set
			if cfg.Transport() == nil {
				t.Error("expected transport to be set")
			}

			// Test rewrite is set
			if cfg.Rewrite() == nil {
				t.Error("expected rewrite to be set")
			}

			// Test IsProxy returns true
			if !cfg.IsProxy() {
				t.Error("expected IsProxy() to return true")
			}
		})
	}
}

func TestGRPCActionDefaults(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		expectStripBasePath  bool
		expectPreserveQuery bool
		expectForwardMetadata bool
		expectMaxRecvSize int
		expectMaxSendSize int
	}{
		{
			name: "defaults applied",
			input: `{
				"type": "grpc",
				"url": "grpc://backend.example.com:50051"
			}`,
			expectStripBasePath:  true,
			expectPreserveQuery:  true,
			expectForwardMetadata: true,
			expectMaxRecvSize:    DefaultGRPCMaxRecvMsgSize,
			expectMaxSendSize:    DefaultGRPCMaxSendMsgSize,
		},
		{
			name: "explicit false values",
			input: `{
				"type": "grpc",
				"url": "grpc://backend.example.com:50051",
				"strip_base_path": false,
				"preserve_query": false,
				"forward_metadata": false
			}`,
			expectStripBasePath:  false,
			expectPreserveQuery:  false,
			expectForwardMetadata: false,
			expectMaxRecvSize:    DefaultGRPCMaxRecvMsgSize,
			expectMaxSendSize:    DefaultGRPCMaxSendMsgSize,
		},
		{
			name: "custom message sizes",
			input: `{
				"type": "grpc",
				"url": "grpc://backend.example.com:50051",
				"max_call_recv_msg_size": 10485760,
				"max_call_send_msg_size": 20971520
			}`,
			expectStripBasePath:  true,
			expectPreserveQuery:  true,
			expectForwardMetadata: true,
			expectMaxRecvSize:    10485760,
			expectMaxSendSize:    20971520,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := NewGRPCAction([]byte(tt.input))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			grpcAction, ok := cfg.(*GRPCAction)
			if !ok {
				t.Fatalf("expected *GRPCAction, got %T", cfg)
			}

			if grpcAction.StripBasePath != tt.expectStripBasePath {
				t.Errorf("expected StripBasePath %v, got %v", tt.expectStripBasePath, grpcAction.StripBasePath)
			}

			if grpcAction.PreserveQuery != tt.expectPreserveQuery {
				t.Errorf("expected PreserveQuery %v, got %v", tt.expectPreserveQuery, grpcAction.PreserveQuery)
			}

			if grpcAction.ForwardMetadata != tt.expectForwardMetadata {
				t.Errorf("expected ForwardMetadata %v, got %v", tt.expectForwardMetadata, grpcAction.ForwardMetadata)
			}

			if grpcAction.MaxCallRecvMsgSize != tt.expectMaxRecvSize {
				t.Errorf("expected MaxCallRecvMsgSize %d, got %d", tt.expectMaxRecvSize, grpcAction.MaxCallRecvMsgSize)
			}

			if grpcAction.MaxCallSendMsgSize != tt.expectMaxSendSize {
				t.Errorf("expected MaxCallSendMsgSize %d, got %d", tt.expectMaxSendSize, grpcAction.MaxCallSendMsgSize)
			}
		})
	}
}

func TestGRPCActionRewrite(t *testing.T) {
	tests := []struct {
		name                string
		grpcURL             string
		stripBasePath        bool
		preserveQuery       bool
		forwardMetadata     bool
		enableGRPCWeb       bool
		requestURL          string
		requestHeaders      map[string]string
		expectedURL         string
		expectedHost        string
		expectedContentType string
		expectTETrailers    bool
		expectMetadata       bool
	}{
		{
			name:                "basic grpc rewrite",
			grpcURL:             "grpc://backend.example.com:50051",
			requestURL:          "http://frontend.com/helloworld.Greeter/SayHello",
			requestHeaders:      map[string]string{"Content-Type": "application/grpc"},
			expectedURL:         "https://backend.example.com:50051/helloworld.Greeter/SayHello",
			expectedHost:        "backend.example.com:50051",
			expectedContentType: "application/grpc",
			expectTETrailers:    true,
			expectMetadata:       false,
		},
		{
			name:                "grpc with strip base path",
			grpcURL:             "grpc://backend.example.com:50051",
			stripBasePath:        true,
			requestURL:          "http://frontend.com/helloworld.Greeter/SayHello",
			requestHeaders:      map[string]string{"Content-Type": "application/grpc"},
			expectedURL:         "https://backend.example.com:50051/helloworld.Greeter/SayHello",
			expectedHost:        "backend.example.com:50051",
			expectedContentType: "application/grpc",
			expectTETrailers:    true,
		},
		{
			name:                "grpc with query string",
			grpcURL:             "grpc://backend.example.com:50051",
			preserveQuery:       true,
			requestURL:          "http://frontend.com/helloworld.Greeter/SayHello?foo=bar",
			requestHeaders:      map[string]string{"Content-Type": "application/grpc"},
			expectedURL:         "https://backend.example.com:50051/helloworld.Greeter/SayHello?foo=bar",
			expectedHost:        "backend.example.com:50051",
			expectedContentType: "application/grpc",
			expectTETrailers:    true,
		},
		{
			name:                "grpc-web rewrite",
			grpcURL:             "https://backend.example.com:50051",
			enableGRPCWeb:       true,
			requestURL:          "http://frontend.com/helloworld.Greeter/SayHello",
			requestHeaders:      map[string]string{"Content-Type": "application/grpc-web+proto"},
			expectedURL:         "https://backend.example.com:50051/helloworld.Greeter/SayHello",
			expectedHost:        "backend.example.com:50051",
			expectedContentType: "application/grpc-web+proto",
			expectTETrailers:    true,
		},
		{
			name:                "grpc with metadata forwarding",
			grpcURL:             "grpc://backend.example.com:50051",
			forwardMetadata:     true,
			requestURL:          "http://frontend.com/helloworld.Greeter/SayHello",
			requestHeaders: map[string]string{
				"Content-Type":      "application/grpc",
				"grpc-metadata-key":  "value",
				"grpc-status":        "0",
			},
			expectedURL:         "https://backend.example.com:50051/helloworld.Greeter/SayHello",
			expectedHost:        "backend.example.com:50051",
			expectedContentType: "application/grpc",
			expectTETrailers:    true,
			expectMetadata:       true,
		},
		{
			name:                "grpc without content-type sets default",
			grpcURL:             "grpc://backend.example.com:50051",
			requestURL:          "http://frontend.com/helloworld.Greeter/SayHello",
			requestHeaders:      map[string]string{},
			expectedURL:         "https://backend.example.com:50051/helloworld.Greeter/SayHello",
			expectedHost:        "backend.example.com:50051",
			expectedContentType: "application/grpc",
			expectTETrailers:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			grpcAction := &GRPCAction{
				GRPCConfig: GRPCConfig{
					URL:            tt.grpcURL,
					StripBasePath:   tt.stripBasePath,
					PreserveQuery:  tt.preserveQuery,
					ForwardMetadata: tt.forwardMetadata,
					EnableGRPCWeb:  tt.enableGRPCWeb,
				},
			}

			// Parse the target URL
			var err error
			grpcAction.targetURL, err = url.Parse(tt.grpcURL)
			if err != nil {
				t.Fatalf("failed to parse grpc URL: %v", err)
			}

			// Normalize scheme
			if grpcAction.targetURL.Scheme == "grpc" || grpcAction.targetURL.Scheme == "grpcs" {
				grpcAction.targetURL.Scheme = "https"
			}

			reqIn := httptest.NewRequest("POST", tt.requestURL, nil)
			for k, v := range tt.requestHeaders {
				reqIn.Header.Set(k, v)
			}

			// Create a fresh outgoing request
			reqOut, err := http.NewRequest("POST", tt.grpcURL, nil)
			if err != nil {
				t.Fatalf("failed to create out request: %v", err)
			}
			reqOut.Header = reqIn.Header.Clone()

			rewriteFn := grpcAction.Rewrite()
			pr := &httputil.ProxyRequest{
				In:  reqIn,
				Out: reqOut,
			}
			rewriteFn(pr)

			// Compare URL components
			expectedURL, err := url.Parse(tt.expectedURL)
			if err != nil {
				t.Fatalf("failed to parse expected URL: %v", err)
			}

			if pr.Out.URL.Scheme != expectedURL.Scheme {
				t.Errorf("expected scheme %q, got %q", expectedURL.Scheme, pr.Out.URL.Scheme)
			}
			if pr.Out.URL.Host != expectedURL.Host {
				t.Errorf("expected host %q, got %q", expectedURL.Host, pr.Out.URL.Host)
			}
			// Normalize paths (remove trailing slashes for comparison)
			expectedPath := strings.TrimSuffix(expectedURL.Path, "/")
			actualPath := strings.TrimSuffix(pr.Out.URL.Path, "/")
			if actualPath != expectedPath {
				t.Errorf("expected path %q, got %q", expectedPath, actualPath)
			}

			// Compare query parameters
			expectedQuery := expectedURL.Query()
			actualQuery := pr.Out.URL.Query()
			for k, expectedVals := range expectedQuery {
				actualVals, ok := actualQuery[k]
				if !ok {
					t.Errorf("expected query param %q not found", k)
					continue
				}
				if len(actualVals) != len(expectedVals) {
					t.Errorf("query param %q: expected %d values, got %d", k, len(expectedVals), len(actualVals))
				}
				for i, expectedVal := range expectedVals {
					if i < len(actualVals) && actualVals[i] != expectedVal {
						t.Errorf("query param %q[%d]: expected %q, got %q", k, i, expectedVal, actualVals[i])
					}
				}
			}

			if pr.Out.Host != tt.expectedHost {
				t.Errorf("expected Host %q, got %q", tt.expectedHost, pr.Out.Host)
			}

			if pr.Out.Header.Get("Host") != tt.expectedHost {
				t.Errorf("expected Host header %q, got %q", tt.expectedHost, pr.Out.Header.Get("Host"))
			}

			// Check Content-Type
			contentType := pr.Out.Header.Get("Content-Type")
			if contentType != tt.expectedContentType {
				t.Errorf("expected Content-Type %q, got %q", tt.expectedContentType, contentType)
			}

			// Check TE: trailers header
			teHeader := pr.Out.Header.Get("TE")
			if tt.expectTETrailers && teHeader != "trailers" {
				t.Errorf("expected TE header to be 'trailers', got %q", teHeader)
			}

			// Check metadata forwarding
			if tt.expectMetadata {
				metadataHeader := pr.Out.Header.Get("grpc-metadata-key")
				if metadataHeader == "" {
					t.Error("expected grpc-metadata-key header to be forwarded")
				}
			}
		})
	}
}

func TestGRPCActionSchemeNormalization(t *testing.T) {
	tests := []struct {
		name        string
		inputURL    string
		expectedScheme string
	}{
		{
			name:        "grpc:// normalized to https://",
			inputURL:    "grpc://backend.example.com:50051",
			expectedScheme: "https",
		},
		{
			name:        "grpcs:// normalized to https://",
			inputURL:    "grpcs://backend.example.com:50051",
			expectedScheme: "https",
		},
		{
			name:        "https:// stays https://",
			inputURL:    "https://backend.example.com:50051",
			expectedScheme: "https",
		},
		{
			name:        "http:// stays http://",
			inputURL:    "http://backend.example.com:50051",
			expectedScheme: "http",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := `{
				"type": "grpc",
				"url": "` + tt.inputURL + `"
			}`

			cfg, err := NewGRPCAction([]byte(input))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			grpcAction, ok := cfg.(*GRPCAction)
			if !ok {
				t.Fatalf("expected *GRPCAction, got %T", cfg)
			}

			if grpcAction.targetURL.Scheme != tt.expectedScheme {
				t.Errorf("expected scheme %q, got %q", tt.expectedScheme, grpcAction.targetURL.Scheme)
			}
		})
	}
}

func TestGRPCActionHTTP11OnlyWarning(t *testing.T) {
	input := `{
		"type": "grpc",
		"url": "grpc://backend.example.com:50051",
		"http11_only": true
	}`

	cfg, err := NewGRPCAction([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	grpcAction, ok := cfg.(*GRPCAction)
	if !ok {
		t.Fatalf("expected *GRPCAction, got %T", cfg)
	}

	// HTTP/1.1 only should be disabled for gRPC
	if grpcAction.HTTP11Only {
		t.Error("expected HTTP11Only to be false for gRPC (requires HTTP/2)")
	}
}

