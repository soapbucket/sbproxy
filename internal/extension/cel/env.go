// Package cel provides Common Expression Language (CEL) evaluation for dynamic request matching and filtering.
package cel

import (
	"sync"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"
)

// Shared CEL environments. These are created once and reused across all
// compilations since cel.NewEnv is expensive and the variable declarations
// are identical for each environment type.

var (
	requestEnvOnce sync.Once
	requestEnvVal  *cel.Env
	requestEnvErr  error

	responseEnvOnce sync.Once
	responseEnvVal  *cel.Env
	responseEnvErr  error

	jsonEnvOnce sync.Once
	jsonEnvVal  *cel.Env
	jsonEnvErr  error

	tokenEnvOnce sync.Once
	tokenEnvVal  *cel.Env
	tokenEnvErr  error
)

// requestEnvOpts returns the common CEL options for request-scoped environments.
// Uses the 9-namespace model: origin, server, vars, features, request, session, client, ctx, cache.
// Secrets are intentionally not exposed to CEL. Keep CEL secret-free unless the
// security model is intentionally revisited.
func requestEnvOpts() []cel.EnvOption {
	return []cel.EnvOption{
		cel.Variable("request", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("session", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("origin", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("server", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("vars", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("features", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("client", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("ctx", cel.MapType(cel.StringType, cel.DynType)),
		ext.Strings(),
		ext.Encoders(),
		IPFunctions(),
	}
}

// getRequestEnv returns the shared CEL environment for request matching and modification.
func getRequestEnv() (*cel.Env, error) {
	requestEnvOnce.Do(func() {
		requestEnvVal, requestEnvErr = cel.NewEnv(requestEnvOpts()...)
	})
	return requestEnvVal, requestEnvErr
}

// GetResponseEnv returns the shared CEL environment for response matching and modification.
// This is a superset of the request env, adding response and oauth_user variables.
func GetResponseEnv() (*cel.Env, error) {
	responseEnvOnce.Do(func() {
		opts := append(requestEnvOpts(),
			cel.Variable("response", cel.MapType(cel.StringType, cel.DynType)),
			cel.Variable("oauth_user", cel.MapType(cel.StringType, cel.DynType)),
		)
		responseEnvVal, responseEnvErr = cel.NewEnv(opts...)
	})
	return responseEnvVal, responseEnvErr
}

// getJSONEnv returns the shared CEL environment for JSON modification expressions.
func getJSONEnv() (*cel.Env, error) {
	jsonEnvOnce.Do(func() {
		jsonEnvVal, jsonEnvErr = cel.NewEnv(
			cel.Variable("json", cel.MapType(cel.StringType, cel.DynType)),
			ext.Strings(),
			ext.Encoders(),
		)
	})
	return jsonEnvVal, jsonEnvErr
}

// getTokenEnv returns the shared CEL environment for token matching expressions.
func getTokenEnv() (*cel.Env, error) {
	tokenEnvOnce.Do(func() {
		tokenEnvVal, tokenEnvErr = cel.NewEnv(
			cel.Variable("token", cel.MapType(cel.StringType, cel.AnyType)),
			ext.Strings(),
			ext.Encoders(),
		)
	})
	return tokenEnvVal, tokenEnvErr
}
