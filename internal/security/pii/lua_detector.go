// Package pii detects and redacts personally identifiable information from request/response data.
package pii

import (
	"context"
	"fmt"
	"time"

	lua "github.com/yuin/gopher-lua"
)

const (
	luaDefaultTimeout = 100 * time.Millisecond
	luaMaxMemory      = 10 * 1024 * 1024 // 10MB
)

// LuaDetector runs a user-defined Lua script for custom PII detection.
//
// The script must define a function:
//
//	function detect_pii(text, field_path)
//	    -- return nil for no match, or a table:
//	    -- { type = "custom_type", value = "matched text", redacted = "[REDACTED]" }
//	end
type LuaDetector struct {
	name    string
	script  string
	timeout time.Duration
}

// NewLuaDetector creates a custom PII detector from a Lua script.
func NewLuaDetector(name, script string, timeout time.Duration) (*LuaDetector, error) {
	if script == "" {
		return nil, fmt.Errorf("pii: lua_detector: script is required")
	}
	if timeout <= 0 {
		timeout = luaDefaultTimeout
	}

	// Validate the script compiles
	L := lua.NewState(lua.Options{SkipOpenLibs: true})
	defer L.Close()
	lua.OpenBase(L)
	lua.OpenString(L)
	lua.OpenTable(L)
	if _, err := L.LoadString(script); err != nil {
		return nil, fmt.Errorf("pii: lua_detector %q: compile error: %w", name, err)
	}

	return &LuaDetector{
		name:    name,
		script:  script,
		timeout: timeout,
	}, nil
}

// Type performs the type operation on the LuaDetector.
func (d *LuaDetector) Type() DetectorType {
	return DetectorCustom
}

// MatchesFlags returns true as Lua detectors are always run when configured.
func (d *LuaDetector) MatchesFlags(flags CandidateFlags) bool {
	return true
}

// Detect performs the detect operation on the LuaDetector.
func (d *LuaDetector) Detect(data []byte, fieldPath string) []Finding {
	var findings []Finding
	d.DetectTo(data, fieldPath, &findings)
	return findings
}

// DetectTo performs the detect to operation on the LuaDetector.
func (d *LuaDetector) DetectTo(data []byte, fieldPath string, findings *[]Finding) {
	L := lua.NewState(lua.Options{SkipOpenLibs: true})
	defer L.Close()

	lua.OpenBase(L)
	lua.OpenString(L)
	lua.OpenTable(L)
	lua.OpenMath(L)

	// Remove dangerous globals
	for _, name := range []string{"dofile", "loadfile", "load", "loadstring", "require", "module"} {
		L.SetGlobal(name, lua.LNil)
	}

	ctx, cancel := context.WithTimeout(context.Background(), d.timeout)
	defer cancel()
	L.SetContext(ctx)

	if err := L.DoString(d.script); err != nil {
		return
	}

	fn := L.GetGlobal("detect_pii")
	if fn == lua.LNil {
		return
	}

	if err := L.CallByParam(lua.P{
		Fn:      fn,
		NRet:    1,
		Protect: true,
	}, lua.LString(string(data)), lua.LString(fieldPath)); err != nil {
		return
	}

	ret := L.Get(-1)
	L.Pop(1)

	d.parseResultTo(ret, fieldPath, findings)
}

// Redact performs the redact operation on the LuaDetector.
func (d *LuaDetector) Redact(value string) string {
	return "[REDACTED-" + d.name + "]"
}

func (d *LuaDetector) parseResultTo(value lua.LValue, fieldPath string, findings *[]Finding) {
	if value == lua.LNil {
		return
	}

	switch v := value.(type) {
	case *lua.LTable:
		// Check if it's a single finding (has "type" key) or an array of findings
		if v.RawGetString("type") != lua.LNil {
			f := d.tableFinding(v, fieldPath)
			if f != nil {
				*findings = append(*findings, *f)
			}
			return
		}
		// Array of findings
		v.ForEach(func(_, val lua.LValue) {
			if tbl, ok := val.(*lua.LTable); ok {
				if f := d.tableFinding(tbl, fieldPath); f != nil {
					*findings = append(*findings, *f)
				}
			}
		})
	}
}

func (d *LuaDetector) parseResult(value lua.LValue, fieldPath string) []Finding {
	var findings []Finding
	d.parseResultTo(value, fieldPath, &findings)
	return findings
}

func (d *LuaDetector) tableFinding(tbl *lua.LTable, fieldPath string) *Finding {
	typVal := tbl.RawGetString("type")
	if typVal == lua.LNil {
		return nil
	}

	val := tbl.RawGetString("value")
	redacted := tbl.RawGetString("redacted")

	valStr := ""
	if val != lua.LNil {
		valStr = val.String()
	}

	redactedStr := d.Redact(valStr)
	if redacted != lua.LNil {
		redactedStr = redacted.String()
	}

	return &Finding{
		Type:       DetectorCustom,
		Value:      valStr,
		Redacted:   redactedStr,
		FieldPath:  fieldPath,
		Confidence: 0.80,
	}
}
