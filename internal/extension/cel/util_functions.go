// Package cel provides Common Expression Language (CEL) evaluation for dynamic request matching and filtering.
package cel

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/uuid"
)

// UtilFunctions returns CEL library options for utility functions including
// crypto hashing, UUID generation, and time helpers.
func UtilFunctions() cel.EnvOption {
	return cel.Lib(utilLib{})
}

type utilLib struct{}

// CompileOptions returns the compile-time function declarations for utility functions.
func (utilLib) CompileOptions() []cel.EnvOption {
	return []cel.EnvOption{
		// sha256(string) -> string - Compute SHA-256 hex digest
		cel.Function("sha256",
			cel.Overload("sha256_string",
				[]*cel.Type{cel.StringType},
				cel.StringType,
				cel.UnaryBinding(sha256Hash),
			),
		),
		// hmacSHA256(data, key) -> string - Compute HMAC-SHA256 hex digest
		cel.Function("hmacSHA256",
			cel.Overload("hmac_sha256_string_string",
				[]*cel.Type{cel.StringType, cel.StringType},
				cel.StringType,
				cel.BinaryBinding(hmacSHA256Hash),
			),
		),
		// uuid() -> string - Generate a random UUID v4
		cel.Function("uuid",
			cel.Overload("uuid_void",
				[]*cel.Type{},
				cel.StringType,
				cel.FunctionBinding(uuidGenerate),
			),
		),
		// now() -> timestamp - Current time as a CEL timestamp
		cel.Function("now",
			cel.Overload("now_void",
				[]*cel.Type{},
				cel.TimestampType,
				cel.FunctionBinding(nowTimestamp),
			),
		),
	}
}

// ProgramOptions returns runtime program options (none needed for util functions).
func (utilLib) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{}
}

// sha256Hash computes the SHA-256 hash of a string and returns the hex-encoded digest.
func sha256Hash(val ref.Val) ref.Val {
	s, ok := val.(types.String)
	if !ok {
		return types.NewErr("sha256 requires a string argument")
	}
	h := sha256.Sum256([]byte(string(s)))
	return types.String(hex.EncodeToString(h[:]))
}

// hmacSHA256Hash computes HMAC-SHA256 of data using key and returns the hex-encoded digest.
func hmacSHA256Hash(lhs, rhs ref.Val) ref.Val {
	data, ok := lhs.(types.String)
	if !ok {
		return types.NewErr("hmacSHA256 first argument (data) must be a string")
	}
	key, ok := rhs.(types.String)
	if !ok {
		return types.NewErr("hmacSHA256 second argument (key) must be a string")
	}
	mac := hmac.New(sha256.New, []byte(string(key)))
	mac.Write([]byte(string(data)))
	return types.String(hex.EncodeToString(mac.Sum(nil)))
}

// uuidGenerate returns a new random UUID v4 string.
func uuidGenerate(vals ...ref.Val) ref.Val {
	return types.String(uuid.New().String())
}

// nowTimestamp returns the current time as a CEL timestamp value.
func nowTimestamp(vals ...ref.Val) ref.Val {
	return types.DefaultTypeAdapter.NativeToValue(time.Now())
}
