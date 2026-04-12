package lua

import (
	"net/http"
	"regexp"
	"strings"
	"testing"

	lua "github.com/yuin/gopher-lua"
)

func newTestState() *lua.LState {
	L := newSandboxedState()
	return L
}

func TestLuaBase64Encode(t *testing.T) {
	L := newTestState()
	defer L.Close()

	if err := L.DoString(`result = sb.base64.encode("hello")`); err != nil {
		t.Fatalf("DoString error: %v", err)
	}
	result := L.GetGlobal("result")
	if result.String() != "aGVsbG8=" {
		t.Errorf("base64.encode('hello') = %q, want %q", result.String(), "aGVsbG8=")
	}
}

func TestLuaBase64Decode(t *testing.T) {
	L := newTestState()
	defer L.Close()

	if err := L.DoString(`result = sb.base64.decode("aGVsbG8=")`); err != nil {
		t.Fatalf("DoString error: %v", err)
	}
	result := L.GetGlobal("result")
	if result.String() != "hello" {
		t.Errorf("base64.decode('aGVsbG8=') = %q, want %q", result.String(), "hello")
	}
}

func TestLuaBase64DecodeInvalid(t *testing.T) {
	L := newTestState()
	defer L.Close()

	if err := L.DoString(`result, err_msg = sb.base64.decode("not-valid-base64!!!")`); err != nil {
		t.Fatalf("DoString error: %v", err)
	}
	result := L.GetGlobal("result")
	if result != lua.LNil {
		t.Errorf("expected nil result for invalid base64, got %v", result)
	}
	errMsg := L.GetGlobal("err_msg")
	if errMsg == lua.LNil || errMsg.String() == "" {
		t.Error("expected error message for invalid base64")
	}
}

func TestLuaBase64Roundtrip(t *testing.T) {
	L := newTestState()
	defer L.Close()

	if err := L.DoString(`
		local encoded = sb.base64.encode("test data 123!")
		result = sb.base64.decode(encoded)
	`); err != nil {
		t.Fatalf("DoString error: %v", err)
	}
	result := L.GetGlobal("result")
	if result.String() != "test data 123!" {
		t.Errorf("base64 roundtrip failed, got %q", result.String())
	}
}

func TestLuaJSONEncode(t *testing.T) {
	L := newTestState()
	defer L.Close()

	if err := L.DoString(`result = sb.json.encode({name = "alice", active = true})`); err != nil {
		t.Fatalf("DoString error: %v", err)
	}
	result := L.GetGlobal("result")
	s := result.String()
	if !strings.Contains(s, `"name"`) || !strings.Contains(s, `"alice"`) {
		t.Errorf("json.encode did not produce expected output, got %q", s)
	}
	if !strings.Contains(s, `"active"`) || !strings.Contains(s, "true") {
		t.Errorf("json.encode did not include boolean field, got %q", s)
	}
}

func TestLuaJSONDecode(t *testing.T) {
	L := newTestState()
	defer L.Close()

	if err := L.DoString(`
		local data = sb.json.decode('{"name":"bob","age":25}')
		result_name = data.name
		result_age = data.age
	`); err != nil {
		t.Fatalf("DoString error: %v", err)
	}
	name := L.GetGlobal("result_name")
	if name.String() != "bob" {
		t.Errorf("json.decode name = %q, want %q", name.String(), "bob")
	}
	age := L.GetGlobal("result_age")
	if age.String() != "25" {
		t.Errorf("json.decode age = %q, want %q", age.String(), "25")
	}
}

func TestLuaJSONDecodeInvalid(t *testing.T) {
	L := newTestState()
	defer L.Close()

	if err := L.DoString(`result, err_msg = sb.json.decode("not json")`); err != nil {
		t.Fatalf("DoString error: %v", err)
	}
	result := L.GetGlobal("result")
	if result != lua.LNil {
		t.Errorf("expected nil result for invalid JSON, got %v", result)
	}
}

func TestLuaJSONRoundtrip(t *testing.T) {
	L := newTestState()
	defer L.Close()

	if err := L.DoString(`
		local original = {name = "test", items = {1, 2, 3}}
		local encoded = sb.json.encode(original)
		local decoded = sb.json.decode(encoded)
		result_name = decoded.name
	`); err != nil {
		t.Fatalf("DoString error: %v", err)
	}
	name := L.GetGlobal("result_name")
	if name.String() != "test" {
		t.Errorf("JSON roundtrip name = %q, want %q", name.String(), "test")
	}
}

func TestLuaSHA256(t *testing.T) {
	L := newTestState()
	defer L.Close()

	if err := L.DoString(`result = sb.crypto.sha256("hello")`); err != nil {
		t.Fatalf("DoString error: %v", err)
	}
	result := L.GetGlobal("result")
	expected := "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if result.String() != expected {
		t.Errorf("sha256('hello') = %q, want %q", result.String(), expected)
	}
}

func TestLuaSHA256Empty(t *testing.T) {
	L := newTestState()
	defer L.Close()

	if err := L.DoString(`result = sb.crypto.sha256("")`); err != nil {
		t.Fatalf("DoString error: %v", err)
	}
	result := L.GetGlobal("result")
	expected := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if result.String() != expected {
		t.Errorf("sha256('') = %q, want %q", result.String(), expected)
	}
}

func TestLuaHmacSHA256(t *testing.T) {
	L := newTestState()
	defer L.Close()

	if err := L.DoString(`result = sb.crypto.hmac_sha256("hello", "secret")`); err != nil {
		t.Fatalf("DoString error: %v", err)
	}
	result := L.GetGlobal("result")
	expected := "88aab3ede8d3adf94d26ab90d3bafd4a2083070c3bcce9c014ee04a443847c0b"
	if result.String() != expected {
		t.Errorf("hmac_sha256('hello','secret') = %q, want %q", result.String(), expected)
	}
}

func TestLuaUUID(t *testing.T) {
	L := newTestState()
	defer L.Close()

	if err := L.DoString(`result = sb.uuid()`); err != nil {
		t.Fatalf("DoString error: %v", err)
	}
	result := L.GetGlobal("result")
	s := result.String()

	// Validate UUID format: 8-4-4-4-12
	parts := strings.Split(s, "-")
	if len(parts) != 5 {
		t.Errorf("UUID should have 5 parts, got %d: %q", len(parts), s)
	}
	if len(s) != 36 {
		t.Errorf("UUID should be 36 chars, got %d: %q", len(s), s)
	}
}

func TestLuaUUIDUnique(t *testing.T) {
	L := newTestState()
	defer L.Close()

	if err := L.DoString(`
		uuid1 = sb.uuid()
		uuid2 = sb.uuid()
	`); err != nil {
		t.Fatalf("DoString error: %v", err)
	}
	uuid1 := L.GetGlobal("uuid1").String()
	uuid2 := L.GetGlobal("uuid2").String()

	if uuid1 == uuid2 {
		t.Errorf("two uuid() calls should produce different values, both got %q", uuid1)
	}
}

func TestLuaTimeNow(t *testing.T) {
	L := newTestState()
	defer L.Close()

	if err := L.DoString(`result = sb.time.now()`); err != nil {
		t.Fatalf("DoString error: %v", err)
	}
	result := L.GetGlobal("result")
	num, ok := result.(lua.LNumber)
	if !ok {
		t.Fatalf("time.now() should return a number, got %T", result)
	}
	// Should be a reasonable Unix timestamp (after 2024)
	if float64(num) < 1700000000 {
		t.Errorf("time.now() returned %v, expected a recent Unix timestamp", num)
	}
}

func TestLuaTimeUnix(t *testing.T) {
	L := newTestState()
	defer L.Close()

	if err := L.DoString(`result = sb.time.unix()`); err != nil {
		t.Fatalf("DoString error: %v", err)
	}
	result := L.GetGlobal("result")
	num, ok := result.(lua.LNumber)
	if !ok {
		t.Fatalf("time.unix() should return a number, got %T", result)
	}
	if float64(num) < 1700000000 {
		t.Errorf("time.unix() returned %v, expected a recent Unix timestamp", num)
	}
}

func TestLuaTimeFormat(t *testing.T) {
	L := newTestState()
	defer L.Close()

	// Format a known timestamp
	if err := L.DoString(`result = sb.time.format(1712345678, "2006-01-02")`); err != nil {
		t.Fatalf("DoString error: %v", err)
	}
	result := L.GetGlobal("result")
	if result.String() != "2024-04-05" {
		t.Errorf("time.format(1712345678, '2006-01-02') = %q, want %q", result.String(), "2024-04-05")
	}
}

func TestLuaTimeFormatNoTimestamp(t *testing.T) {
	L := newTestState()
	defer L.Close()

	// Format current time
	if err := L.DoString(`result = sb.time.format("2006")`); err != nil {
		t.Fatalf("DoString error: %v", err)
	}
	result := L.GetGlobal("result")
	// Should be the current year
	if len(result.String()) != 4 {
		t.Errorf("time.format('2006') should return a 4-digit year, got %q", result.String())
	}
}

func TestLuaLogDoesNotPanic(t *testing.T) {
	L := newTestState()
	defer L.Close()

	// Just verify these don't panic or error
	scripts := []string{
		`sb.log.info("test message")`,
		`sb.log.warn("warning message")`,
		`sb.log.error("error message")`,
		`sb.log.debug("debug message")`,
		`sb.log.info("with attrs", {key = "value", num = 42})`,
	}

	for _, script := range scripts {
		if err := L.DoString(script); err != nil {
			t.Errorf("log function failed: %v (script: %s)", err, script)
		}
	}
}

func TestLuaUtilInMatcher(t *testing.T) {
	// Test that utility functions work inside a matcher script
	script := `function match_request(req, ctx)
		local hash = sb.crypto.sha256(req.path)
		return hash ~= ""
	end`

	matcher, err := NewMatcher(script)
	if err != nil {
		t.Fatalf("NewMatcher() error = %v", err)
	}

	req, _ := http.NewRequest("GET", "http://example.com/test", nil)
	if !matcher.Match(req) {
		t.Error("matcher with sha256 should return true")
	}
}

func TestLuaUtilInModifier(t *testing.T) {
	// Test that utility functions work inside a modifier script
	script := `function modify_request(req, ctx)
		return {
			set_headers = {
				["X-Request-Hash"] = sb.crypto.sha256(req.path),
				["X-Request-ID"] = sb.uuid()
			}
		}
	end`

	modifier, err := NewModifier(script)
	if err != nil {
		t.Fatalf("NewModifier() error = %v", err)
	}

	req, _ := http.NewRequest("GET", "http://example.com/test", nil)
	modReq, err := modifier.Modify(req)
	if err != nil {
		t.Fatalf("Modify() error = %v", err)
	}

	hash := modReq.Header.Get("X-Request-Hash")
	if hash == "" || len(hash) != 64 {
		t.Errorf("X-Request-Hash should be a 64-char hex string, got %q", hash)
	}

	reqID := modReq.Header.Get("X-Request-ID")
	if reqID == "" || len(reqID) != 36 {
		t.Errorf("X-Request-ID should be a 36-char UUID, got %q", reqID)
	}
}

// --- Base64 edge cases ---

func TestLuaBase64EncodeEmpty(t *testing.T) {
	L := newTestState()
	defer L.Close()

	if err := L.DoString(`result = sb.base64.encode("")`); err != nil {
		t.Fatalf("DoString error: %v", err)
	}
	result := L.GetGlobal("result")
	if result.String() != "" {
		t.Errorf("base64.encode('') = %q, want %q", result.String(), "")
	}
}

func TestLuaBase64DecodeEmpty(t *testing.T) {
	L := newTestState()
	defer L.Close()

	if err := L.DoString(`result = sb.base64.decode("")`); err != nil {
		t.Fatalf("DoString error: %v", err)
	}
	result := L.GetGlobal("result")
	if result.String() != "" {
		t.Errorf("base64.decode('') = %q, want %q", result.String(), "")
	}
}

func TestLuaBase64BinaryData(t *testing.T) {
	L := newTestState()
	defer L.Close()

	// Build a string with all byte values 0-255
	if err := L.DoString(`
		local bytes = {}
		for i = 0, 255 do
			bytes[#bytes + 1] = string.char(i)
		end
		local input = table.concat(bytes)
		local encoded = sb.base64.encode(input)
		local decoded = sb.base64.decode(encoded)
		result_match = (input == decoded)
		result_len = #decoded
	`); err != nil {
		t.Fatalf("DoString error: %v", err)
	}
	match := L.GetGlobal("result_match")
	if match.String() != "true" {
		t.Error("base64 roundtrip of binary data (0-255) should produce identical output")
	}
	length := L.GetGlobal("result_len")
	if length.String() != "256" {
		t.Errorf("decoded binary data length = %s, want 256", length.String())
	}
}

func TestLuaBase64URLSafeChars(t *testing.T) {
	L := newTestState()
	defer L.Close()

	// Input with characters that differ between standard and URL-safe base64
	if err := L.DoString(`
		local input = "subjects?_d=1&type=all"
		local encoded = sb.base64.encode(input)
		local decoded = sb.base64.decode(encoded)
		result_match = (input == decoded)
	`); err != nil {
		t.Fatalf("DoString error: %v", err)
	}
	match := L.GetGlobal("result_match")
	if match.String() != "true" {
		t.Error("base64 roundtrip with URL-safe characters should work")
	}
}

func TestLuaBase64LargeString(t *testing.T) {
	L := newTestState()
	defer L.Close()

	if err := L.DoString(`
		local input = string.rep("ABCDEFGHIJ", 10000)
		local encoded = sb.base64.encode(input)
		local decoded = sb.base64.decode(encoded)
		result_match = (input == decoded)
		result_len = #input
	`); err != nil {
		t.Fatalf("DoString error: %v", err)
	}
	match := L.GetGlobal("result_match")
	if match.String() != "true" {
		t.Error("base64 roundtrip of 100KB string should produce identical output")
	}
	length := L.GetGlobal("result_len")
	if length.String() != "100000" {
		t.Errorf("input length = %s, want 100000", length.String())
	}
}

func TestLuaBase64DecodeInvalidChars(t *testing.T) {
	L := newTestState()
	defer L.Close()

	if err := L.DoString(`result, err_msg = sb.base64.decode("!!!invalid!!!")`); err != nil {
		t.Fatalf("DoString error: %v", err)
	}
	result := L.GetGlobal("result")
	if result != lua.LNil {
		t.Errorf("expected nil for invalid base64, got %v", result)
	}
	errMsg := L.GetGlobal("err_msg")
	if errMsg == lua.LNil || errMsg.String() == "" {
		t.Error("expected error message for invalid base64")
	}
}

// --- JSON edge cases ---

func TestLuaJSONNestedObjects(t *testing.T) {
	L := newTestState()
	defer L.Close()

	if err := L.DoString(`
		local data = sb.json.decode('{"a":{"b":{"c":"deep"}}}')
		result = data.a.b.c
	`); err != nil {
		t.Fatalf("DoString error: %v", err)
	}
	result := L.GetGlobal("result")
	if result.String() != "deep" {
		t.Errorf("nested JSON access = %q, want %q", result.String(), "deep")
	}
}

func TestLuaJSONMixedArray(t *testing.T) {
	L := newTestState()
	defer L.Close()

	if err := L.DoString(`
		local data = sb.json.decode('[1, "two", true, null, 4.5]')
		result_1 = data[1]
		result_2 = data[2]
		result_3 = data[3]
		result_5 = data[5]
	`); err != nil {
		t.Fatalf("DoString error: %v", err)
	}
	if L.GetGlobal("result_1").String() != "1" {
		t.Errorf("array[1] = %q, want %q", L.GetGlobal("result_1").String(), "1")
	}
	if L.GetGlobal("result_2").String() != "two" {
		t.Errorf("array[2] = %q, want %q", L.GetGlobal("result_2").String(), "two")
	}
	if L.GetGlobal("result_3").String() != "true" {
		t.Errorf("array[3] = %q, want %q", L.GetGlobal("result_3").String(), "true")
	}
	if L.GetGlobal("result_5").String() != "4.5" {
		t.Errorf("array[5] = %q, want %q", L.GetGlobal("result_5").String(), "4.5")
	}
}

func TestLuaJSONEmptyObject(t *testing.T) {
	L := newTestState()
	defer L.Close()

	if err := L.DoString(`
		local data = sb.json.decode('{}')
		result = sb.json.encode(data)
	`); err != nil {
		t.Fatalf("DoString error: %v", err)
	}
	result := L.GetGlobal("result")
	if result.String() != "{}" {
		t.Errorf("empty object roundtrip = %q, want %q", result.String(), "{}")
	}
}

func TestLuaJSONNullValues(t *testing.T) {
	L := newTestState()
	defer L.Close()

	if err := L.DoString(`
		local data = sb.json.decode('{"key":null}')
		result_is_nil = (data.key == nil)
	`); err != nil {
		t.Fatalf("DoString error: %v", err)
	}
	result := L.GetGlobal("result_is_nil")
	if result.String() != "true" {
		t.Error("JSON null should decode to Lua nil")
	}
}

func TestLuaJSONNumberPrecision(t *testing.T) {
	L := newTestState()
	defer L.Close()

	if err := L.DoString(`
		local data = sb.json.decode('{"int":42,"float":3.14159}')
		result_int = data.int
		result_float = data.float
	`); err != nil {
		t.Fatalf("DoString error: %v", err)
	}
	if L.GetGlobal("result_int").String() != "42" {
		t.Errorf("integer = %q, want %q", L.GetGlobal("result_int").String(), "42")
	}
	f := L.GetGlobal("result_float").String()
	if !strings.HasPrefix(f, "3.14") {
		t.Errorf("float = %q, want prefix %q", f, "3.14")
	}
}

func TestLuaJSONSpecialChars(t *testing.T) {
	L := newTestState()
	defer L.Close()

	// Use Lua long string syntax to avoid escaping issues
	if err := L.DoString(`
		local json_str = [[{"msg":"hello world","path":"a/b/c","special":"<>&"}]]
		local data = sb.json.decode(json_str)
		result_msg = data.msg
		result_path = data.path
		result_special = data.special
	`); err != nil {
		t.Fatalf("DoString error: %v", err)
	}
	msg := L.GetGlobal("result_msg")
	if msg.String() != "hello world" {
		t.Errorf("msg = %q, want %q", msg.String(), "hello world")
	}
	path := L.GetGlobal("result_path")
	if path.String() != "a/b/c" {
		t.Errorf("path = %q, want %q", path.String(), "a/b/c")
	}
	special := L.GetGlobal("result_special")
	if special.String() != "<>&" {
		t.Errorf("special = %q, want %q", special.String(), "<>&")
	}
}

func TestLuaJSONDecodeNotJSON(t *testing.T) {
	L := newTestState()
	defer L.Close()

	if err := L.DoString(`result, err_msg = sb.json.decode("not json at all")`); err != nil {
		t.Fatalf("DoString error: %v", err)
	}
	result := L.GetGlobal("result")
	if result != lua.LNil {
		t.Errorf("expected nil for invalid JSON, got %v", result)
	}
	errMsg := L.GetGlobal("err_msg")
	if errMsg == lua.LNil || errMsg.String() == "" {
		t.Error("expected error message for invalid JSON")
	}
}

func TestLuaJSONEncodeNil(t *testing.T) {
	L := newTestState()
	defer L.Close()

	if err := L.DoString(`result = sb.json.encode(nil)`); err != nil {
		t.Fatalf("DoString error: %v", err)
	}
	result := L.GetGlobal("result")
	// nil should encode to "null"
	if result.String() != "null" {
		t.Errorf("json.encode(nil) = %q, want %q", result.String(), "null")
	}
}

// --- Crypto edge cases ---

func TestLuaSHA256KnownEmpty(t *testing.T) {
	L := newTestState()
	defer L.Close()

	if err := L.DoString(`result = sb.crypto.sha256("")`); err != nil {
		t.Fatalf("DoString error: %v", err)
	}
	result := L.GetGlobal("result")
	expected := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if result.String() != expected {
		t.Errorf("sha256('') = %q, want %q", result.String(), expected)
	}
}

func TestLuaHmacSHA256EmptyKey(t *testing.T) {
	L := newTestState()
	defer L.Close()

	if err := L.DoString(`result = sb.crypto.hmac_sha256("data", "")`); err != nil {
		t.Fatalf("DoString error: %v", err)
	}
	result := L.GetGlobal("result")
	if len(result.String()) != 64 {
		t.Errorf("hmac_sha256 with empty key should return 64-char hex, got %d chars", len(result.String()))
	}
}

func TestLuaHmacSHA256EmptyData(t *testing.T) {
	L := newTestState()
	defer L.Close()

	if err := L.DoString(`result = sb.crypto.hmac_sha256("", "key")`); err != nil {
		t.Fatalf("DoString error: %v", err)
	}
	result := L.GetGlobal("result")
	if len(result.String()) != 64 {
		t.Errorf("hmac_sha256 with empty data should return 64-char hex, got %d chars", len(result.String()))
	}
}

func TestLuaHmacSHA256RFC4231(t *testing.T) {
	L := newTestState()
	defer L.Close()

	if err := L.DoString(`result = sb.crypto.hmac_sha256("what do ya want for nothing?", "Jefe")`); err != nil {
		t.Fatalf("DoString error: %v", err)
	}
	result := L.GetGlobal("result")
	expected := "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
	if result.String() != expected {
		t.Errorf("hmac_sha256 RFC 4231 test = %q, want %q", result.String(), expected)
	}
}

func TestLuaHmacSHA256Deterministic(t *testing.T) {
	L := newTestState()
	defer L.Close()

	if err := L.DoString(`
		r1 = sb.crypto.hmac_sha256("msg", "key")
		r2 = sb.crypto.hmac_sha256("msg", "key")
		result_match = (r1 == r2)
	`); err != nil {
		t.Fatalf("DoString error: %v", err)
	}
	match := L.GetGlobal("result_match")
	if match.String() != "true" {
		t.Error("hmac_sha256 should be deterministic")
	}
}

// --- UUID edge cases ---

func TestLuaUUID1000Unique(t *testing.T) {
	L := newTestState()
	defer L.Close()

	if err := L.DoString(`
		local seen = {}
		local dupes = 0
		for i = 1, 1000 do
			local u = sb.uuid()
			if seen[u] then
				dupes = dupes + 1
			end
			seen[u] = true
		end
		result_dupes = dupes
	`); err != nil {
		t.Fatalf("DoString error: %v", err)
	}
	dupes := L.GetGlobal("result_dupes")
	if dupes.String() != "0" {
		t.Errorf("expected 0 duplicate UUIDs in 1000, got %s", dupes.String())
	}
}

func TestLuaUUIDFormat(t *testing.T) {
	L := newTestState()
	defer L.Close()

	if err := L.DoString(`result = sb.uuid()`); err != nil {
		t.Fatalf("DoString error: %v", err)
	}
	result := L.GetGlobal("result").String()

	uuidRegex := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	if !uuidRegex.MatchString(result) {
		t.Errorf("UUID does not match v4 format: %q", result)
	}
}

// --- Time edge cases ---

func TestLuaTimeNowReturnsNumber(t *testing.T) {
	L := newTestState()
	defer L.Close()

	if err := L.DoString(`
		local val = sb.time.now()
		result_type = type(val)
		result_positive = (val > 0)
	`); err != nil {
		t.Fatalf("DoString error: %v", err)
	}
	if L.GetGlobal("result_type").String() != "number" {
		t.Errorf("time.now() type = %q, want %q", L.GetGlobal("result_type").String(), "number")
	}
	if L.GetGlobal("result_positive").String() != "true" {
		t.Error("time.now() should return a positive number")
	}
}

func TestLuaTimeUnixReturnsInteger(t *testing.T) {
	L := newTestState()
	defer L.Close()

	if err := L.DoString(`
		local val = sb.time.unix()
		result_type = type(val)
		-- Check it's an integer by comparing with math.floor
		result_is_int = (val == math.floor(val))
	`); err != nil {
		t.Fatalf("DoString error: %v", err)
	}
	if L.GetGlobal("result_type").String() != "number" {
		t.Errorf("time.unix() type = %q, want %q", L.GetGlobal("result_type").String(), "number")
	}
	if L.GetGlobal("result_is_int").String() != "true" {
		t.Error("time.unix() should return an integer value")
	}
}

func TestLuaTimeFormatDefaultLayout(t *testing.T) {
	L := newTestState()
	defer L.Close()

	// No args should return RFC3339
	if err := L.DoString(`result = sb.time.format()`); err != nil {
		t.Fatalf("DoString error: %v", err)
	}
	result := L.GetGlobal("result").String()
	// RFC3339 format contains T and Z (or +/-)
	if !strings.Contains(result, "T") {
		t.Errorf("time.format() default should be RFC3339, got %q", result)
	}
}

func TestLuaTimeFormatCustomLayout(t *testing.T) {
	L := newTestState()
	defer L.Close()

	if err := L.DoString(`result = sb.time.format(1712345678, "2006-01-02")`); err != nil {
		t.Fatalf("DoString error: %v", err)
	}
	result := L.GetGlobal("result").String()
	if result != "2024-04-05" {
		t.Errorf("time.format with custom layout = %q, want %q", result, "2024-04-05")
	}
}

func TestLuaTimeFormatCurrentTime(t *testing.T) {
	L := newTestState()
	defer L.Close()

	// Single arg (layout only) should use current time
	if err := L.DoString(`result = sb.time.format("2006")`); err != nil {
		t.Fatalf("DoString error: %v", err)
	}
	result := L.GetGlobal("result").String()
	if len(result) != 4 {
		t.Errorf("time.format('2006') should be 4-char year, got %q", result)
	}
	// Should be a reasonable year
	if result < "2024" || result > "2100" {
		t.Errorf("time.format('2006') returned %q, expected a year >= 2024", result)
	}
}

// --- Logging edge cases ---

func TestLuaLogAllLevels(t *testing.T) {
	L := newTestState()
	defer L.Close()

	levels := []string{"info", "warn", "error", "debug"}
	for _, level := range levels {
		t.Run(level, func(t *testing.T) {
			if err := L.DoString(`sb.log.` + level + `("test message")`); err != nil {
				t.Errorf("sb.log.%s() failed: %v", level, err)
			}
		})
	}
}

func TestLuaLogWithAttributes(t *testing.T) {
	L := newTestState()
	defer L.Close()

	if err := L.DoString(`sb.log.warn("test warning", {key = "value", count = 42})`); err != nil {
		t.Fatalf("DoString error: %v", err)
	}
}

func TestLuaLogWithEmptyMessage(t *testing.T) {
	L := newTestState()
	defer L.Close()

	// Empty string is still a valid string argument
	if err := L.DoString(`sb.log.info("")`); err != nil {
		t.Fatalf("sb.log.info with empty message should not error: %v", err)
	}
}

// --- Integration: sb.* in modify_json ---

func TestLuaIntegrationModifyJSON(t *testing.T) {
	L := newTestState()
	defer L.Close()

	if err := L.DoString(`
		function modify_json(data, ctx)
			data.hash = sb.crypto.sha256(data.name or "")
			data.id = sb.uuid()
			data.timestamp = sb.time.unix()
			data.encoded = sb.base64.encode("hello")
			return data
		end

		-- Simulate calling modify_json
		local input = {name = "alice"}
		local output = modify_json(input, {})
		result_hash = output.hash
		result_id = output.id
		result_ts = output.timestamp
		result_encoded = output.encoded
	`); err != nil {
		t.Fatalf("DoString error: %v", err)
	}

	hash := L.GetGlobal("result_hash").String()
	if len(hash) != 64 {
		t.Errorf("hash should be 64 chars, got %d: %q", len(hash), hash)
	}

	id := L.GetGlobal("result_id").String()
	if len(id) != 36 {
		t.Errorf("id should be UUID (36 chars), got %d: %q", len(id), id)
	}

	ts := L.GetGlobal("result_ts")
	if _, ok := ts.(lua.LNumber); !ok {
		t.Errorf("timestamp should be a number, got %T", ts)
	}

	encoded := L.GetGlobal("result_encoded").String()
	if encoded != "aGVsbG8=" {
		t.Errorf("encoded = %q, want %q", encoded, "aGVsbG8=")
	}
}

// --- Integration: sb.* in match_request ---

func TestLuaIntegrationMatchRequest(t *testing.T) {
	script := `function match_request(req, ctx)
		-- Use crypto to validate a hash
		local expected = sb.crypto.sha256("secret-path")
		local actual = sb.crypto.sha256(req.path)
		-- They should differ since req.path != "secret-path"
		return expected ~= actual
	end`

	matcher, err := NewMatcher(script)
	if err != nil {
		t.Fatalf("NewMatcher() error = %v", err)
	}

	req, _ := http.NewRequest("GET", "http://example.com/other-path", nil)
	if !matcher.Match(req) {
		t.Error("matcher should return true (paths differ)")
	}
}

func TestLuaIntegrationMatchRequestWithTime(t *testing.T) {
	script := `function match_request(req, ctx)
		-- Verify time functions work inside match_request
		local ts = sb.time.unix()
		return ts > 1700000000
	end`

	matcher, err := NewMatcher(script)
	if err != nil {
		t.Fatalf("NewMatcher() error = %v", err)
	}

	req, _ := http.NewRequest("GET", "http://example.com/test", nil)
	if !matcher.Match(req) {
		t.Error("matcher with time should return true")
	}
}

func TestLuaIntegrationMatchRequestWithUUID(t *testing.T) {
	script := `function match_request(req, ctx)
		-- Verify uuid works inside match_request
		local id = sb.uuid()
		return #id == 36
	end`

	matcher, err := NewMatcher(script)
	if err != nil {
		t.Fatalf("NewMatcher() error = %v", err)
	}

	req, _ := http.NewRequest("GET", "http://example.com/test", nil)
	if !matcher.Match(req) {
		t.Error("matcher with uuid should return true")
	}
}

// --- Integration: modify_request with all sb.* functions ---

func TestLuaIntegrationModifyRequestCombined(t *testing.T) {
	script := `function modify_request(req, ctx)
		return {
			set_headers = {
				["X-Request-ID"] = sb.uuid(),
				["X-Path-Hash"] = sb.crypto.sha256(req.path),
				["X-Timestamp"] = tostring(sb.time.unix()),
				["X-Signature"] = sb.crypto.hmac_sha256(req.path, "secret"),
				["X-Encoded"] = sb.base64.encode(req.path)
			}
		}
	end`

	modifier, err := NewModifier(script)
	if err != nil {
		t.Fatalf("NewModifier() error = %v", err)
	}

	req, _ := http.NewRequest("GET", "http://example.com/api/test", nil)
	modReq, err := modifier.Modify(req)
	if err != nil {
		t.Fatalf("Modify() error = %v", err)
	}

	if id := modReq.Header.Get("X-Request-ID"); len(id) != 36 {
		t.Errorf("X-Request-ID should be UUID, got %q", id)
	}
	if hash := modReq.Header.Get("X-Path-Hash"); len(hash) != 64 {
		t.Errorf("X-Path-Hash should be sha256 hex, got %q", hash)
	}
	if ts := modReq.Header.Get("X-Timestamp"); ts == "" {
		t.Error("X-Timestamp should not be empty")
	}
	if sig := modReq.Header.Get("X-Signature"); len(sig) != 64 {
		t.Errorf("X-Signature should be hmac hex, got %q", sig)
	}
	if enc := modReq.Header.Get("X-Encoded"); enc == "" {
		t.Error("X-Encoded should not be empty")
	}
}

// --- Error handling ---

func TestLuaCryptoSHA256ErrorHandling(t *testing.T) {
	L := newTestState()
	defer L.Close()

	// sha256 uses CheckString(1) which will error on nil input via gopher-lua
	err := L.DoString(`result = sb.crypto.sha256(nil)`)
	if err == nil {
		t.Log("sha256(nil) did not error, checking result")
		result := L.GetGlobal("result")
		t.Logf("sha256(nil) = %q", result.String())
	}
	// Either erroring or returning a value is acceptable - we just ensure no panic
}

func TestLuaCryptoHmacSHA256ErrorHandling(t *testing.T) {
	L := newTestState()
	defer L.Close()

	err := L.DoString(`result = sb.crypto.hmac_sha256(nil, nil)`)
	if err == nil {
		t.Log("hmac_sha256(nil, nil) did not error, checking result")
	}
	// Either erroring or returning a value is acceptable - we just ensure no panic
}

func TestLuaJSONDecodeErrorReturnsNilPlusError(t *testing.T) {
	L := newTestState()
	defer L.Close()

	tests := []struct {
		name  string
		input string
	}{
		{"plain text", `"not json"`},
		{"truncated", `'{"key":'`},
		{"single bracket", `"["`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			L2 := newTestState()
			defer L2.Close()
			if err := L2.DoString(`result, err_msg = sb.json.decode(` + tt.input + `)`); err != nil {
				t.Fatalf("DoString error: %v", err)
			}
			result := L2.GetGlobal("result")
			if result != lua.LNil {
				t.Errorf("expected nil for invalid JSON %s, got %v", tt.name, result)
			}
		})
	}
}

// Suppress unused import warning
var _ = regexp.MustCompile
