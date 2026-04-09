package rule

import (
	"net/http"
	"testing"
)

func TestRequestRule_Protocol_Matching(t *testing.T) {
	tests := []struct {
		name     string
		rule     RequestRule
		req      *http.Request
		expected bool
	}{
		{
			name: "WebSocket upgrade request matches websocket protocol",
			rule: RequestRule{
				Protocol: "websocket",
			},
			req: &http.Request{
				Method: "GET",
				Header: http.Header{
					"Connection": []string{"Upgrade"},
					"Upgrade":    []string{"websocket"},
				},
			},
			expected: true,
		},
		{
			name: "HTTP request does not match websocket protocol",
			rule: RequestRule{
				Protocol: "websocket",
			},
			req: &http.Request{
				Method: "GET",
				Header: http.Header{},
			},
			expected: false,
		},
		{
			name: "HTTP request matches http protocol",
			rule: RequestRule{
				Protocol: "http",
			},
			req: &http.Request{
				Method: "GET",
				Header: http.Header{},
			},
			expected: true,
		},
		{
			name: "WebSocket upgrade request does not match http protocol",
			rule: RequestRule{
				Protocol: "http",
			},
			req: &http.Request{
				Method: "GET",
				Header: http.Header{
					"Connection": []string{"Upgrade"},
					"Upgrade":    []string{"websocket"},
				},
			},
			expected: false,
		},
		{
			name: "Empty protocol matches both HTTP and WebSocket",
			rule: RequestRule{
				// Protocol not specified
			},
			req: &http.Request{
				Method: "GET",
				Header: http.Header{
					"Connection": []string{"Upgrade"},
					"Upgrade":    []string{"websocket"},
				},
			},
			expected: true,
		},
		{
			name: "Protocol matching is case-insensitive",
			rule: RequestRule{
				Protocol: "WebSocket",
			},
			req: &http.Request{
				Method: "GET",
				Header: http.Header{
					"Connection": []string{"Upgrade"},
					"Upgrade":    []string{"websocket"},
				},
			},
			expected: true,
		},
		{
			name: "WebSocket does not require GET method in protocol detection",
			rule: RequestRule{
				Protocol: "websocket",
			},
			req: &http.Request{
				Method: "POST",
				Header: http.Header{
					"Connection": []string{"Upgrade"},
					"Upgrade":    []string{"websocket"},
				},
			},
			expected: true, // Protocol detection doesn't check method
		},
		{
			name: "Connection header can have multiple values",
			rule: RequestRule{
				Protocol: "websocket",
			},
			req: &http.Request{
				Method: "GET",
				Header: http.Header{
					"Connection": []string{"keep-alive, Upgrade"},
					"Upgrade":    []string{"websocket"},
				},
			},
			expected: true,
		},
		{
			name: "Protocol with path matching",
			rule: RequestRule{
				Protocol: "websocket",
				Path: &PathConditions{
					Exact: "/ws",
				},
			},
			req: func() *http.Request {
				req, _ := http.NewRequest("GET", "/ws", nil)
				req.Header.Set("Connection", "Upgrade")
				req.Header.Set("Upgrade", "websocket")
				return req
			}(),
			expected: true,
		},
		{
			name: "Protocol with method matching",
			rule: RequestRule{
				Protocol: "websocket",
				Methods:  []string{"GET"},
			},
			req: &http.Request{
				Method: "GET",
				Header: http.Header{
					"Connection": []string{"Upgrade"},
					"Upgrade":    []string{"websocket"},
				},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.rule.Match(tt.req)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestIsWebSocketRequest(t *testing.T) {
	tests := []struct {
		name     string
		req      *http.Request
		expected bool
	}{
		{
			name: "Valid WebSocket upgrade request",
			req: &http.Request{
				Method: "GET",
				Header: http.Header{
					"Connection": []string{"Upgrade"},
					"Upgrade":    []string{"websocket"},
				},
			},
			expected: true,
		},
		{
			name: "Missing Connection header",
			req: &http.Request{
				Method: "GET",
				Header: http.Header{
					"Upgrade": []string{"websocket"},
				},
			},
			expected: false,
		},
		{
			name: "Missing Upgrade header",
			req: &http.Request{
				Method: "GET",
				Header: http.Header{
					"Connection": []string{"Upgrade"},
				},
			},
			expected: false,
		},
		{
			name: "POST method with WebSocket headers (protocol detection doesn't check method)",
			req: &http.Request{
				Method: "POST",
				Header: http.Header{
					"Connection": []string{"Upgrade"},
					"Upgrade":    []string{"websocket"},
				},
			},
			expected: true, // Protocol detection doesn't require GET method
		},
		{
			name: "Case-sensitive Upgrade header (WEBSOCKET uppercase does not match)",
			req: &http.Request{
				Method: "GET",
				Header: http.Header{
					"Connection": []string{"UPGRADE"},
					"Upgrade":    []string{"WEBSOCKET"},
				},
			},
			expected: false, // Upgrade header value must be lowercase "websocket"
		},
		{
			name: "Connection with multiple values",
			req: &http.Request{
				Method: "GET",
				Header: http.Header{
					"Connection": []string{"keep-alive, upgrade"},
					"Upgrade":    []string{"websocket"},
				},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test protocol detection instead
			detectedProtocol := detectProtocol(tt.req)
			result := detectedProtocol == "websocket"
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

