package config

import (
	"net/http"
	"testing"
)

func TestApplyClientHintsHeaders_Enabled(t *testing.T) {
	cfg := &ClientHintsConfig{
		Enable:   true,
		AcceptCH: []string{"Sec-CH-UA", "Sec-CH-UA-Mobile", "DPR"},
		CriticalCH: []string{"Sec-CH-UA"},
		Lifetime: 86400,
	}

	resp := &http.Response{Header: make(http.Header)}
	applyClientHintsHeaders(resp, cfg)

	if got := resp.Header.Get("Accept-CH"); got != "Sec-CH-UA, Sec-CH-UA-Mobile, DPR" {
		t.Errorf("Accept-CH = %q, want %q", got, "Sec-CH-UA, Sec-CH-UA-Mobile, DPR")
	}
	if got := resp.Header.Get("Critical-CH"); got != "Sec-CH-UA" {
		t.Errorf("Critical-CH = %q, want %q", got, "Sec-CH-UA")
	}
	if got := resp.Header.Get("Accept-CH-Lifetime"); got != "86400" {
		t.Errorf("Accept-CH-Lifetime = %q, want %q", got, "86400")
	}
}

func TestApplyClientHintsHeaders_Disabled(t *testing.T) {
	resp := &http.Response{Header: make(http.Header)}

	applyClientHintsHeaders(resp, nil)
	if resp.Header.Get("Accept-CH") != "" {
		t.Error("should not set Accept-CH when config is nil")
	}

	applyClientHintsHeaders(resp, &ClientHintsConfig{Enable: false})
	if resp.Header.Get("Accept-CH") != "" {
		t.Error("should not set Accept-CH when disabled")
	}
}

func TestApplyClientHintsHeaders_NoLifetime(t *testing.T) {
	cfg := &ClientHintsConfig{
		Enable:   true,
		AcceptCH: []string{"DPR"},
	}

	resp := &http.Response{Header: make(http.Header)}
	applyClientHintsHeaders(resp, cfg)

	if resp.Header.Get("Accept-CH-Lifetime") != "" {
		t.Error("should not set Accept-CH-Lifetime when Lifetime is 0")
	}
}

func TestApplyClientHintsHeaders_NoCritical(t *testing.T) {
	cfg := &ClientHintsConfig{
		Enable:   true,
		AcceptCH: []string{"DPR", "Viewport-Width"},
	}

	resp := &http.Response{Header: make(http.Header)}
	applyClientHintsHeaders(resp, cfg)

	if resp.Header.Get("Critical-CH") != "" {
		t.Error("should not set Critical-CH when CriticalCH is empty")
	}
	if got := resp.Header.Get("Accept-CH"); got != "DPR, Viewport-Width" {
		t.Errorf("Accept-CH = %q, want %q", got, "DPR, Viewport-Width")
	}
}

func TestForwardClientHints_ExplicitList(t *testing.T) {
	cfg := &ClientHintsConfig{
		Enable:   true,
		AcceptCH: []string{"Sec-CH-UA", "DPR", "Save-Data"},
	}

	clientReq := &http.Request{
		Header: http.Header{
			"Sec-Ch-Ua": []string{`"Chromium";v="110"`},
			"Dpr":       []string{"2.0"},
			"Ect":       []string{"4g"}, // Not in AcceptCH, should not be forwarded
		},
	}
	outReq := &http.Request{Header: make(http.Header)}

	forwardClientHints(outReq, clientReq, cfg)

	if got := outReq.Header.Get("Sec-CH-UA"); got != `"Chromium";v="110"` {
		t.Errorf("Sec-CH-UA = %q, want %q", got, `"Chromium";v="110"`)
	}
	if got := outReq.Header.Get("DPR"); got != "2.0" {
		t.Errorf("DPR = %q, want %q", got, "2.0")
	}
	if outReq.Header.Get("ECT") != "" {
		t.Error("should not forward ECT when not in AcceptCH list")
	}
	// Save-Data was not sent by client, so it should not appear in the outgoing request
}

func TestForwardClientHints_AllStandard(t *testing.T) {
	cfg := &ClientHintsConfig{
		Enable: true,
		// No AcceptCH - forward all standard hints
	}

	clientReq := &http.Request{
		Header: http.Header{
			"Sec-Ch-Ua":        []string{`"Chromium";v="110"`},
			"Sec-Ch-Ua-Mobile": []string{"?0"},
			"Dpr":              []string{"1.5"},
			"Ect":              []string{"4g"},
			"Save-Data":        []string{"on"},
		},
	}
	outReq := &http.Request{Header: make(http.Header)}

	forwardClientHints(outReq, clientReq, cfg)

	if outReq.Header.Get("Sec-CH-UA") != `"Chromium";v="110"` {
		t.Error("should forward Sec-CH-UA")
	}
	if outReq.Header.Get("Sec-CH-UA-Mobile") != "?0" {
		t.Error("should forward Sec-CH-UA-Mobile")
	}
	if outReq.Header.Get("DPR") != "1.5" {
		t.Error("should forward DPR")
	}
	if outReq.Header.Get("ECT") != "4g" {
		t.Error("should forward ECT")
	}
	if outReq.Header.Get("Save-Data") != "on" {
		t.Error("should forward Save-Data")
	}
}

func TestForwardClientHints_Disabled(t *testing.T) {
	clientReq := &http.Request{
		Header: http.Header{
			"Sec-Ch-Ua": []string{`"Chromium";v="110"`},
		},
	}
	outReq := &http.Request{Header: make(http.Header)}

	forwardClientHints(outReq, clientReq, nil)
	if outReq.Header.Get("Sec-CH-UA") != "" {
		t.Error("should not forward when config is nil")
	}

	forwardClientHints(outReq, clientReq, &ClientHintsConfig{Enable: false})
	if outReq.Header.Get("Sec-CH-UA") != "" {
		t.Error("should not forward when disabled")
	}
}

func TestFormatInt(t *testing.T) {
	tests := []struct {
		input int
		want  string
	}{
		{0, "0"},
		{1, "1"},
		{86400, "86400"},
		{-5, "-5"},
		{999999, "999999"},
	}
	for _, tt := range tests {
		got := formatInt(tt.input)
		if got != tt.want {
			t.Errorf("formatInt(%d) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
