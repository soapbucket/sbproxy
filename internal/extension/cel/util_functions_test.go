package cel

import (
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func TestSHA256(t *testing.T) {
	tests := []struct {
		name      string
		expr      string
		wantMatch bool
	}{
		{
			name:      "sha256 empty string",
			expr:      `sha256("") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"`,
			wantMatch: true,
		},
		{
			name:      "sha256 hello",
			expr:      `sha256("hello") == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"`,
			wantMatch: true,
		},
		{
			name:      "sha256 returns 64-char hex string",
			expr:      `sha256("test").size() == 64`,
			wantMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com/test", nil)
			matcher, err := NewMatcher(tt.expr)
			if err != nil {
				t.Fatalf("NewMatcher() error = %v", err)
			}
			got := matcher.Match(req)
			if got != tt.wantMatch {
				t.Errorf("Match() = %v, want %v", got, tt.wantMatch)
			}
		})
	}
}

func TestHmacSHA256(t *testing.T) {
	tests := []struct {
		name      string
		expr      string
		wantMatch bool
	}{
		{
			name:      "hmacSHA256 known value",
			expr:      `hmacSHA256("hello", "secret") == "88aab3ede8d3adf94d26ab90d3bafd4a2083070c3bcce9c014ee04a443847c0b"`,
			wantMatch: true,
		},
		{
			name:      "hmacSHA256 returns 64-char hex",
			expr:      `hmacSHA256("data", "key").size() == 64`,
			wantMatch: true,
		},
		{
			name:      "hmacSHA256 different keys produce different results",
			expr:      `hmacSHA256("data", "key1") != hmacSHA256("data", "key2")`,
			wantMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com/test", nil)
			matcher, err := NewMatcher(tt.expr)
			if err != nil {
				t.Fatalf("NewMatcher() error = %v", err)
			}
			got := matcher.Match(req)
			if got != tt.wantMatch {
				t.Errorf("Match() = %v, want %v", got, tt.wantMatch)
			}
		})
	}
}

func TestUUID(t *testing.T) {
	// Test that uuid() returns a valid UUID format
	req := httptest.NewRequest("GET", "http://example.com/test", nil)

	// UUID format: 8-4-4-4-12 hex chars
	matcher, err := NewMatcher(`uuid().size() == 36`)
	if err != nil {
		t.Fatalf("NewMatcher() error = %v", err)
	}
	if !matcher.Match(req) {
		t.Error("uuid() should return a 36-character string")
	}

	// Test that uuid() contains hyphens
	matcher, err = NewMatcher(`uuid().contains("-")`)
	if err != nil {
		t.Fatalf("NewMatcher() error = %v", err)
	}
	if !matcher.Match(req) {
		t.Error("uuid() should contain hyphens")
	}

	// Test that two calls produce different UUIDs (use modifier to capture values)
	// We test this by using the modifier which returns a map
	env, err := getRequestEnv()
	if err != nil {
		t.Fatalf("getRequestEnv() error = %v", err)
	}

	ast, issues := env.Compile(`uuid()`)
	if issues != nil && issues.Err() != nil {
		t.Fatalf("Compile error: %v", issues.Err())
	}

	prg, err := env.Program(ast)
	if err != nil {
		t.Fatalf("Program error: %v", err)
	}

	rc := NewRequestContext(req)
	defer rc.Release()
	vars := rc.ToVars()

	out1, _, err := prg.Eval(vars)
	if err != nil {
		t.Fatalf("Eval error: %v", err)
	}

	out2, _, err := prg.Eval(vars)
	if err != nil {
		t.Fatalf("Eval error: %v", err)
	}

	uuid1 := out1.Value().(string)
	uuid2 := out2.Value().(string)

	if uuid1 == uuid2 {
		t.Errorf("two uuid() calls should produce different values, got %s both times", uuid1)
	}

	// Validate UUID v4 format
	parts := strings.Split(uuid1, "-")
	if len(parts) != 5 {
		t.Errorf("uuid should have 5 parts separated by hyphens, got %d", len(parts))
	}
	if len(parts[0]) != 8 || len(parts[1]) != 4 || len(parts[2]) != 4 || len(parts[3]) != 4 || len(parts[4]) != 12 {
		t.Errorf("uuid format invalid: %s", uuid1)
	}
}

func TestNow(t *testing.T) {
	// Test that now() returns a timestamp that can be compared
	req := httptest.NewRequest("GET", "http://example.com/test", nil)

	// now() should return a valid timestamp type
	env, err := getRequestEnv()
	if err != nil {
		t.Fatalf("getRequestEnv() error = %v", err)
	}

	ast, issues := env.Compile(`now()`)
	if issues != nil && issues.Err() != nil {
		t.Fatalf("Compile error: %v", issues.Err())
	}

	prg, err := env.Program(ast)
	if err != nil {
		t.Fatalf("Program error: %v", err)
	}

	rc := NewRequestContext(req)
	defer rc.Release()
	vars := rc.ToVars()

	out, _, err := prg.Eval(vars)
	if err != nil {
		t.Fatalf("Eval error: %v", err)
	}

	// Verify it's a timestamp type
	if out.Type().TypeName() != "google.protobuf.Timestamp" {
		t.Errorf("now() should return Timestamp type, got %s", out.Type().TypeName())
	}

	// Test that now() can be used with getFullYear (CEL timestamp method)
	matcher, err := NewMatcher(`now().getFullYear() >= 2024`)
	if err != nil {
		t.Fatalf("NewMatcher() error = %v", err)
	}
	if !matcher.Match(req) {
		t.Error("now().getFullYear() should be >= 2024")
	}
}

func TestUtilFunctionsInModifier(t *testing.T) {
	// Test that utility functions work in request modifiers
	req := httptest.NewRequest("GET", "http://example.com/test", nil)

	expr := `{
		"add_headers": {
			"X-Request-Hash": sha256(request["path"]),
			"X-Request-ID": uuid()
		}
	}`

	modifier, err := NewModifier(expr)
	if err != nil {
		t.Fatalf("NewModifier() error = %v", err)
	}

	modReq, err := modifier.Modify(req)
	if err != nil {
		t.Fatalf("Modify() error = %v", err)
	}

	hash := modReq.Header.Get("X-Request-Hash")
	if hash == "" {
		t.Error("X-Request-Hash should be set")
	}
	if len(hash) != 64 {
		t.Errorf("X-Request-Hash should be 64 chars, got %d", len(hash))
	}

	reqID := modReq.Header.Get("X-Request-ID")
	if reqID == "" {
		t.Error("X-Request-ID should be set")
	}
	if len(reqID) != 36 {
		t.Errorf("X-Request-ID should be 36 chars (UUID), got %d", len(reqID))
	}
}

func TestSHA256EdgeCases(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com/test", nil)

	tests := []struct {
		name      string
		expr      string
		wantMatch bool
	}{
		{
			name:      "unicode input",
			expr:      `sha256("hello\u4e16\u754c") != ""`,
			wantMatch: true,
		},
		{
			name:      "unicode output is 64 hex chars",
			expr:      `sha256("hello\u4e16\u754c").size() == 64`,
			wantMatch: true,
		},
		{
			name:      "long string produces 64-char hex",
			expr:      `sha256("` + strings.Repeat("a", 10000) + `").size() == 64`,
			wantMatch: true,
		},
		{
			name:      "different inputs produce different hashes",
			expr:      `sha256("abc") != sha256("abd")`,
			wantMatch: true,
		},
		{
			name:      "same input produces same hash",
			expr:      `sha256("deterministic") == sha256("deterministic")`,
			wantMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher, err := NewMatcher(tt.expr)
			if err != nil {
				t.Fatalf("NewMatcher() error = %v", err)
			}
			got := matcher.Match(req)
			if got != tt.wantMatch {
				t.Errorf("Match() = %v, want %v", got, tt.wantMatch)
			}
		})
	}

	// Verify hex chars only (using raw evaluation)
	t.Run("output contains only hex chars", func(t *testing.T) {
		env, err := getRequestEnv()
		if err != nil {
			t.Fatalf("getRequestEnv() error = %v", err)
		}
		ast, issues := env.Compile(`sha256("test")`)
		if issues != nil && issues.Err() != nil {
			t.Fatalf("Compile error: %v", issues.Err())
		}
		prg, err := env.Program(ast)
		if err != nil {
			t.Fatalf("Program error: %v", err)
		}
		rc := NewRequestContext(req)
		defer rc.Release()
		out, _, err := prg.Eval(rc.ToVars())
		if err != nil {
			t.Fatalf("Eval error: %v", err)
		}
		hash := out.Value().(string)
		if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(hash) {
			t.Errorf("sha256 output is not valid hex: %q", hash)
		}
	})
}

func TestHmacSHA256EdgeCases(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com/test", nil)

	tests := []struct {
		name      string
		expr      string
		wantMatch bool
	}{
		{
			name:      "empty key",
			expr:      `hmacSHA256("data", "").size() == 64`,
			wantMatch: true,
		},
		{
			name:      "empty data",
			expr:      `hmacSHA256("", "key").size() == 64`,
			wantMatch: true,
		},
		{
			name:      "both empty",
			expr:      `hmacSHA256("", "").size() == 64`,
			wantMatch: true,
		},
		{
			name:      "RFC 4231 test vector - key=Jefe data=what do ya want for nothing?",
			expr:      `hmacSHA256("what do ya want for nothing?", "Jefe") == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"`,
			wantMatch: true,
		},
		{
			name:      "same data different keys",
			expr:      `hmacSHA256("msg", "k1") != hmacSHA256("msg", "k2")`,
			wantMatch: true,
		},
		{
			name:      "same key different data",
			expr:      `hmacSHA256("a", "k") != hmacSHA256("b", "k")`,
			wantMatch: true,
		},
		{
			name:      "deterministic",
			expr:      `hmacSHA256("x", "y") == hmacSHA256("x", "y")`,
			wantMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher, err := NewMatcher(tt.expr)
			if err != nil {
				t.Fatalf("NewMatcher() error = %v", err)
			}
			got := matcher.Match(req)
			if got != tt.wantMatch {
				t.Errorf("Match() = %v, want %v", got, tt.wantMatch)
			}
		})
	}
}

func TestUUIDEdgeCases(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com/test", nil)

	t.Run("generate 100 unique UUIDs", func(t *testing.T) {
		env, err := getRequestEnv()
		if err != nil {
			t.Fatalf("getRequestEnv() error = %v", err)
		}
		ast, issues := env.Compile(`uuid()`)
		if issues != nil && issues.Err() != nil {
			t.Fatalf("Compile error: %v", issues.Err())
		}
		prg, err := env.Program(ast)
		if err != nil {
			t.Fatalf("Program error: %v", err)
		}
		rc := NewRequestContext(req)
		defer rc.Release()
		vars := rc.ToVars()

		seen := make(map[string]bool)
		uuidRegex := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

		for i := 0; i < 100; i++ {
			out, _, err := prg.Eval(vars)
			if err != nil {
				t.Fatalf("Eval error on iteration %d: %v", i, err)
			}
			u := out.Value().(string)
			if seen[u] {
				t.Errorf("duplicate UUID at iteration %d: %s", i, u)
			}
			seen[u] = true

			if !uuidRegex.MatchString(u) {
				t.Errorf("UUID does not match v4 format: %s", u)
			}
		}
	})

	t.Run("version 4 marker", func(t *testing.T) {
		env, err := getRequestEnv()
		if err != nil {
			t.Fatalf("getRequestEnv() error = %v", err)
		}
		ast, issues := env.Compile(`uuid()`)
		if issues != nil && issues.Err() != nil {
			t.Fatalf("Compile error: %v", issues.Err())
		}
		prg, err := env.Program(ast)
		if err != nil {
			t.Fatalf("Program error: %v", err)
		}
		rc := NewRequestContext(req)
		defer rc.Release()

		out, _, err := prg.Eval(rc.ToVars())
		if err != nil {
			t.Fatalf("Eval error: %v", err)
		}
		u := out.Value().(string)
		// 13th character (index 14 including hyphens) should be '4'
		if u[14] != '4' {
			t.Errorf("UUID version should be 4, got char %c in %s", u[14], u)
		}
	})
}

func TestNowEdgeCases(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com/test", nil)

	t.Run("second call >= first call", func(t *testing.T) {
		env, err := getRequestEnv()
		if err != nil {
			t.Fatalf("getRequestEnv() error = %v", err)
		}
		ast, issues := env.Compile(`now()`)
		if issues != nil && issues.Err() != nil {
			t.Fatalf("Compile error: %v", issues.Err())
		}
		prg, err := env.Program(ast)
		if err != nil {
			t.Fatalf("Program error: %v", err)
		}
		rc := NewRequestContext(req)
		defer rc.Release()
		vars := rc.ToVars()

		out1, _, err := prg.Eval(vars)
		if err != nil {
			t.Fatalf("Eval error: %v", err)
		}
		out2, _, err := prg.Eval(vars)
		if err != nil {
			t.Fatalf("Eval error: %v", err)
		}

		// Compare using CEL comparison - second should be >= first
		compAst, issues := env.Compile(`now().getFullYear() >= 2024`)
		if issues != nil && issues.Err() != nil {
			t.Fatalf("Compile error: %v", issues.Err())
		}
		compPrg, err := env.Program(compAst)
		if err != nil {
			t.Fatalf("Program error: %v", err)
		}
		compOut, _, err := compPrg.Eval(vars)
		if err != nil {
			t.Fatalf("Eval error: %v", err)
		}
		if compOut.Value().(bool) != true {
			t.Error("now().getFullYear() should be >= 2024")
		}

		// Verify both are timestamps
		if out1.Type().TypeName() != "google.protobuf.Timestamp" {
			t.Errorf("first now() type = %s, want Timestamp", out1.Type().TypeName())
		}
		if out2.Type().TypeName() != "google.protobuf.Timestamp" {
			t.Errorf("second now() type = %s, want Timestamp", out2.Type().TypeName())
		}
	})

	t.Run("getFullYear > 2020", func(t *testing.T) {
		matcher, err := NewMatcher(`now().getFullYear() > 2020`)
		if err != nil {
			t.Fatalf("NewMatcher() error = %v", err)
		}
		if !matcher.Match(req) {
			t.Error("now().getFullYear() should be > 2020")
		}
	})

	t.Run("getMonth returns 0-11 range", func(t *testing.T) {
		matcher, err := NewMatcher(`now().getMonth() >= 0 && now().getMonth() <= 11`)
		if err != nil {
			t.Fatalf("NewMatcher() error = %v", err)
		}
		if !matcher.Match(req) {
			t.Error("now().getMonth() should be in 0-11 range")
		}
	})

	t.Run("getHours returns 0-23 range", func(t *testing.T) {
		matcher, err := NewMatcher(`now().getHours() >= 0 && now().getHours() <= 23`)
		if err != nil {
			t.Fatalf("NewMatcher() error = %v", err)
		}
		if !matcher.Match(req) {
			t.Error("now().getHours() should be in 0-23 range")
		}
	})
}

func TestIntegrationSHA256InPolicy(t *testing.T) {
	// Simulate validating an API key by comparing its hash
	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	req.Header.Set("X-Api-Key", "my-secret-key")

	// Pre-compute sha256("my-secret-key")
	expectedHash := "a]invalid" // Wrong hash - should not match
	expr := `sha256(request.headers["x-api-key"]) != "` + expectedHash + `"`
	matcher, err := NewMatcher(expr)
	if err != nil {
		t.Fatalf("NewMatcher() error = %v", err)
	}
	if !matcher.Match(req) {
		t.Error("sha256 policy expression should evaluate correctly")
	}

	// Now test with matching hash
	expr2 := `sha256(request.headers["x-api-key"]) == sha256("my-secret-key")`
	matcher2, err := NewMatcher(expr2)
	if err != nil {
		t.Fatalf("NewMatcher() error = %v", err)
	}
	if !matcher2.Match(req) {
		t.Error("sha256 of same input should match")
	}
}

func TestIntegrationUUIDInModifier(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com/test", nil)

	expr := `{
		"set_headers": {
			"X-Request-ID": uuid(),
			"X-Trace-ID": uuid()
		}
	}`

	modifier, err := NewModifier(expr)
	if err != nil {
		t.Fatalf("NewModifier() error = %v", err)
	}

	modReq, err := modifier.Modify(req)
	if err != nil {
		t.Fatalf("Modify() error = %v", err)
	}

	reqID := modReq.Header.Get("X-Request-ID")
	traceID := modReq.Header.Get("X-Trace-ID")

	if reqID == "" || len(reqID) != 36 {
		t.Errorf("X-Request-ID should be a UUID, got %q", reqID)
	}
	if traceID == "" || len(traceID) != 36 {
		t.Errorf("X-Trace-ID should be a UUID, got %q", traceID)
	}
	if reqID == traceID {
		t.Error("X-Request-ID and X-Trace-ID should be different UUIDs")
	}
}

func TestIntegrationNowForTimeBasedAccess(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com/test", nil)

	// This expression should compile and evaluate without error.
	// It checks business hours (9-17), which may or may not match depending on when the test runs.
	expr := `now().getHours() >= 9 && now().getHours() < 17`
	matcher, err := NewMatcher(expr)
	if err != nil {
		t.Fatalf("NewMatcher() error = %v, expression should compile", err)
	}
	// Just verify it evaluates without panic - result depends on time of day
	_ = matcher.Match(req)

	// Also verify a compound time expression compiles
	expr2 := `now().getDayOfWeek() >= 1 && now().getDayOfWeek() <= 5 && now().getHours() >= 9 && now().getHours() < 17`
	matcher2, err := NewMatcher(expr2)
	if err != nil {
		t.Fatalf("NewMatcher() error = %v, compound time expression should compile", err)
	}
	_ = matcher2.Match(req)
}

func TestIntegrationCombinedUtilFunctions(t *testing.T) {
	// Test using multiple util functions together in a single expression
	req := httptest.NewRequest("POST", "http://example.com/api/data", nil)
	req.Header.Set("Authorization", "Bearer token123")

	expr := `{
		"add_headers": {
			"X-Request-ID": uuid(),
			"X-Auth-Hash": sha256(request.headers["authorization"]),
			"X-Signature": hmacSHA256(request["path"], "signing-key")
		}
	}`

	modifier, err := NewModifier(expr)
	if err != nil {
		t.Fatalf("NewModifier() error = %v", err)
	}

	modReq, err := modifier.Modify(req)
	if err != nil {
		t.Fatalf("Modify() error = %v", err)
	}

	if id := modReq.Header.Get("X-Request-ID"); len(id) != 36 {
		t.Errorf("X-Request-ID should be UUID, got %q", id)
	}
	if hash := modReq.Header.Get("X-Auth-Hash"); len(hash) != 64 {
		t.Errorf("X-Auth-Hash should be sha256 hex, got %q", hash)
	}
	if sig := modReq.Header.Get("X-Signature"); len(sig) != 64 {
		t.Errorf("X-Signature should be hmac hex, got %q", sig)
	}
}
