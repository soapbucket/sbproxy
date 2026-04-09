// Package cel provides Common Expression Language (CEL) evaluation for dynamic request matching and filtering.
package cel

import (
	json "github.com/goccy/go-json"
	"errors"
	"log/slog"

	"github.com/google/cel-go/cel"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"golang.org/x/net/html"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
)

type tokenObj struct {
	Data  string            `json:"data"`
	Attrs map[string]string `json:"attrs"`
}

type tokenMatcher struct {
	cel.Program
}

// Match performs the match operation on the tokenMatcher.
func (m *tokenMatcher) Match(token html.Token) bool {
	vars := getTokenVar(token)

	out, _, err := m.Eval(vars)
	if err != nil {
		slog.Debug("error evaluating token", "token", token, "error", err)
		return false
	}

	if outBool, ok := out.Value().(bool); ok {
		return outBool
	}
	return false

}

// NewTokenMatcher creates a new CEL matcher for HTML tokens.
// The expression must evaluate to a boolean value and can access token properties
// through the 'token' variable which has the following fields:
//   - data: string (tag name)
//   - attrs: map[string]string (attributes)
//
// Example expressions:
//   - `token.data == "a"`
//   - `"href" in token.attrs`
//   - `token.attrs['class'].contains('button')`
func NewTokenMatcher(expr string) (reqctx.TokenMatcher, error) {
	env, err := getTokenEnv()
	if err != nil {
		return nil, err
	}

	ast, iss := env.Compile(expr)
	if iss != nil && iss.Err() != nil {
		return nil, iss.Err()
	}
	if ast == nil {
		return nil, errors.New("cel: compilation produced nil AST")
	}
	if ast.OutputType() != cel.BoolType {
		return nil, ErrWrongType
	}

	program, err := env.Program(ast)
	if err != nil {
		return nil, err
	}
	return &tokenMatcher{Program: program}, nil
}

func getTokenVar(token html.Token) map[string]interface{} {
	obj := &tokenObj{
		Data:  token.Data,
		Attrs: make(map[string]string),
	}

	for _, attr := range token.Attr {
		obj.Attrs[attr.Key] = attr.Val
	}

	// Now, get the input in the correct format (conversion: Go struct -> JSON -> structpb).
	data, err := json.Marshal(obj)
	if err != nil {
		slog.Debug("error marshaling token data", "error", err)
		return map[string]interface{}{"token": &structpb.Struct{}}
	}

	spb := new(structpb.Struct)
	if err := protojson.Unmarshal(data, spb); err != nil {
		slog.Debug("error unmarshaling token data", "error", err)
		return map[string]interface{}{"token": &structpb.Struct{}}
	}

	return map[string]interface{}{"token": spb}
}
