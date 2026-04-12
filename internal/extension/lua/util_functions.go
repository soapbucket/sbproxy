// Package lua provides Lua scripting support for dynamic request/response processing.
package lua

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	lua "github.com/yuin/gopher-lua"
)

// RegisterUtilFunctions registers utility helper functions in the Lua state.
// This adds the "sb" module with sub-tables for logging, encoding, hashing,
// UUID generation, and time helpers.
func RegisterUtilFunctions(L *lua.LState) {
	sbTable := L.NewTable()

	// sb.log - structured logging
	registerLogFunctions(L, sbTable)

	// sb.base64 - base64 encoding/decoding
	registerBase64Functions(L, sbTable)

	// sb.json - JSON encoding/decoding
	registerJSONFunctions(L, sbTable)

	// sb.crypto - hashing functions
	registerCryptoFunctions(L, sbTable)

	// sb.uuid() - UUID generation
	L.SetField(sbTable, "uuid", L.NewFunction(luaUUID))

	// sb.time - time helpers
	registerTimeFunctions(L, sbTable)

	L.SetGlobal("sb", sbTable)
}

// --- Logging ---

func registerLogFunctions(L *lua.LState, parent *lua.LTable) {
	logTable := L.NewTable()
	L.SetField(logTable, "info", L.NewFunction(luaLogInfo))
	L.SetField(logTable, "warn", L.NewFunction(luaLogWarn))
	L.SetField(logTable, "error", L.NewFunction(luaLogError))
	L.SetField(logTable, "debug", L.NewFunction(luaLogDebug))
	L.SetField(parent, "log", logTable)
}

func luaLogInfo(L *lua.LState) int {
	msg := L.CheckString(1)
	attrs := extractLogAttrs(L, 2)
	slog.Info("[lua] "+msg, attrs...)
	return 0
}

func luaLogWarn(L *lua.LState) int {
	msg := L.CheckString(1)
	attrs := extractLogAttrs(L, 2)
	slog.Warn("[lua] "+msg, attrs...)
	return 0
}

func luaLogError(L *lua.LState) int {
	msg := L.CheckString(1)
	attrs := extractLogAttrs(L, 2)
	slog.Error("[lua] "+msg, attrs...)
	return 0
}

func luaLogDebug(L *lua.LState) int {
	msg := L.CheckString(1)
	attrs := extractLogAttrs(L, 2)
	slog.Debug("[lua] "+msg, attrs...)
	return 0
}

// extractLogAttrs extracts optional key-value pairs from the Lua stack
// starting at position startIdx. If a table is passed, its string keys
// are used as attribute pairs.
func extractLogAttrs(L *lua.LState, startIdx int) []any {
	var attrs []any
	if L.GetTop() >= startIdx {
		val := L.Get(startIdx)
		if tbl, ok := val.(*lua.LTable); ok {
			tbl.ForEach(func(k, v lua.LValue) {
				if ks, ok := k.(lua.LString); ok {
					attrs = append(attrs, string(ks), luaValueToString(v))
				}
			})
		}
	}
	return attrs
}

func luaValueToString(v lua.LValue) string {
	switch val := v.(type) {
	case lua.LBool:
		if val {
			return "true"
		}
		return "false"
	case lua.LNumber:
		return fmt.Sprintf("%g", float64(val))
	case *lua.LNilType:
		return "nil"
	default:
		return v.String()
	}
}

// --- Base64 ---

func registerBase64Functions(L *lua.LState, parent *lua.LTable) {
	b64Table := L.NewTable()
	L.SetField(b64Table, "encode", L.NewFunction(luaBase64Encode))
	L.SetField(b64Table, "decode", L.NewFunction(luaBase64Decode))
	L.SetField(parent, "base64", b64Table)
}

// luaBase64Encode encodes a string to base64.
// Usage: sb.base64.encode("hello") -> "aGVsbG8="
func luaBase64Encode(L *lua.LState) int {
	input := L.CheckString(1)
	encoded := base64.StdEncoding.EncodeToString([]byte(input))
	L.Push(lua.LString(encoded))
	return 1
}

// luaBase64Decode decodes a base64 string.
// Usage: sb.base64.decode("aGVsbG8=") -> "hello"
// Returns: decoded string, or nil + error string on failure
func luaBase64Decode(L *lua.LState) int {
	input := L.CheckString(1)
	decoded, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))
		return 2
	}
	L.Push(lua.LString(string(decoded)))
	return 1
}

// --- JSON ---

func registerJSONFunctions(L *lua.LState, parent *lua.LTable) {
	jsonTable := L.NewTable()
	L.SetField(jsonTable, "encode", L.NewFunction(luaJSONEncode))
	L.SetField(jsonTable, "decode", L.NewFunction(luaJSONDecode))
	L.SetField(parent, "json", jsonTable)
}

// luaJSONEncode encodes a Lua table to a JSON string.
// Usage: sb.json.encode({name = "alice", age = 30}) -> '{"age":30,"name":"alice"}'
func luaJSONEncode(L *lua.LState) int {
	val := L.Get(1)
	goVal := convertLuaToGo(L, val)
	encoded, err := json.Marshal(goVal)
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))
		return 2
	}
	L.Push(lua.LString(string(encoded)))
	return 1
}

// luaJSONDecode decodes a JSON string into a Lua table.
// Usage: sb.json.decode('{"name":"alice"}') -> {name = "alice"}
// Returns: decoded table, or nil + error string on failure
func luaJSONDecode(L *lua.LState) int {
	input := L.CheckString(1)
	var result interface{}
	if err := json.Unmarshal([]byte(input), &result); err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))
		return 2
	}
	L.Push(convertGoToLua(L, result))
	return 1
}

// Note: convertLuaToGo and convertGoToLua are defined in json_modifier.go

// --- Crypto ---

func registerCryptoFunctions(L *lua.LState, parent *lua.LTable) {
	cryptoTable := L.NewTable()
	L.SetField(cryptoTable, "sha256", L.NewFunction(luaSHA256))
	L.SetField(cryptoTable, "hmac_sha256", L.NewFunction(luaHmacSHA256))
	L.SetField(parent, "crypto", cryptoTable)
}

// luaSHA256 computes the SHA-256 hex digest of a string.
// Usage: sb.crypto.sha256("hello") -> "2cf24dba..."
func luaSHA256(L *lua.LState) int {
	input := L.CheckString(1)
	h := sha256.Sum256([]byte(input))
	L.Push(lua.LString(hex.EncodeToString(h[:])))
	return 1
}

// luaHmacSHA256 computes the HMAC-SHA256 hex digest.
// Usage: sb.crypto.hmac_sha256("data", "secret") -> "88aab3ed..."
func luaHmacSHA256(L *lua.LState) int {
	data := L.CheckString(1)
	key := L.CheckString(2)
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(data))
	L.Push(lua.LString(hex.EncodeToString(mac.Sum(nil))))
	return 1
}

// --- UUID ---

// luaUUID generates a random UUID v4 string.
// Usage: sb.uuid() -> "550e8400-e29b-41d4-a716-446655440000"
func luaUUID(L *lua.LState) int {
	L.Push(lua.LString(uuid.New().String()))
	return 1
}

// --- Time ---

func registerTimeFunctions(L *lua.LState, parent *lua.LTable) {
	timeTable := L.NewTable()
	L.SetField(timeTable, "now", L.NewFunction(luaTimeNow))
	L.SetField(timeTable, "format", L.NewFunction(luaTimeFormat))
	L.SetField(timeTable, "unix", L.NewFunction(luaTimeUnix))
	L.SetField(parent, "time", timeTable)
}

// luaTimeNow returns the current Unix timestamp in seconds (with fractional part).
// Usage: sb.time.now() -> 1712345678.123
func luaTimeNow(L *lua.LState) int {
	now := time.Now()
	L.Push(lua.LNumber(float64(now.UnixNano()) / 1e9))
	return 1
}

// luaTimeFormat formats a Unix timestamp using Go time layout strings.
// Usage: sb.time.format(1712345678, "2006-01-02T15:04:05Z07:00") -> "2024-04-05T..."
// Common layouts: "2006-01-02", "15:04:05", "2006-01-02T15:04:05Z07:00" (RFC3339)
// If no timestamp is provided, formats the current time.
func luaTimeFormat(L *lua.LState) int {
	var t time.Time
	if L.GetTop() >= 2 {
		ts := L.CheckNumber(1)
		sec := int64(ts)
		nsec := int64((float64(ts) - float64(sec)) * 1e9)
		t = time.Unix(sec, nsec).UTC()
		layout := L.CheckString(2)
		L.Push(lua.LString(t.Format(layout)))
	} else if L.GetTop() == 1 {
		// Single arg: format current time with given layout
		layout := L.CheckString(1)
		L.Push(lua.LString(time.Now().UTC().Format(layout)))
	} else {
		// No args: RFC3339 of current time
		L.Push(lua.LString(time.Now().UTC().Format(time.RFC3339)))
	}
	return 1
}

// luaTimeUnix returns the current Unix timestamp as an integer (seconds).
// Usage: sb.time.unix() -> 1712345678
func luaTimeUnix(L *lua.LState) int {
	L.Push(lua.LNumber(time.Now().Unix()))
	return 1
}
