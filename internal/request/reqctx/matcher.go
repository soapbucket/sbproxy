// Package models defines shared data types, constants, and request/response models used across packages.
package reqctx

import (
	"encoding/json"
	"regexp"
	"strings"


	"golang.org/x/net/html"
)

// TokenMatcher evaluates expressions against HTML tokens.
// This interface is implemented by CEL and Lua matchers.
type TokenMatcher interface {
	// Match evaluates the expression against the given HTML token.
	// Returns true if the expression evaluates to true, false otherwise.
	Match(html.Token) bool
}

// NewTokenMatcherFunc is a function type that creates a token matcher from an expression.
// This is used to avoid circular imports between models and cel/lua packages.
type NewTokenMatcherFunc func(string) (TokenMatcher, error)

type matcher Matcher

// tokenMatcherFactory is the function used to create token matchers.
// This is set during initialization to wire up the CEL/Lua implementations.
var tokenMatcherFactory NewTokenMatcherFunc

// SetTokenMatcherFactory sets the factory function for creating token matchers.
func SetTokenMatcherFactory(factory NewTokenMatcherFunc) {
	tokenMatcherFactory = factory
}

// GetTokenMatcherFactory returns the current token matcher factory function.
func GetTokenMatcherFactory() NewTokenMatcherFunc {
	return tokenMatcherFactory
}

// Matcher matches a tag
type Matcher struct {
	Tag     string           `json:"tag"`
	Regex   string           `json:"regex,omitempty"`
	Attrs   []Attr `json:"attrs,omitempty"`
	CELExpr string           `json:"celExpr,omitempty"`
	LuaExpr string           `json:"luaExpr,omitempty"`

	prg TokenMatcher
	re  *regexp.Regexp
}

// UnmarshalJSON unmarshals m's expression.
func (m *Matcher) UnmarshalJSON(data []byte) error {
	var nm matcher
	if err := json.Unmarshal(data, &nm); err != nil {
		return err
	}

	*m = Matcher(nm)

	if m.CELExpr != "" && tokenMatcherFactory != nil {
		prg, err := tokenMatcherFactory(m.CELExpr)
		if err != nil {
			return err
		}
		m.prg = prg
	}

	if m.Regex != "" {
		re, err := regexp.Compile(m.Regex)
		if err != nil {
			return err
		}
		m.re = re
	}
	return nil
}

// Match performs the match operation on the Matcher.
func (m *Matcher) Match(token html.Token) bool {
	if token.Type != html.StartTagToken && token.Type != html.SelfClosingTagToken {
		return false
	}

	if m.Tag != "" && !strings.EqualFold(m.Tag, token.Data) {
		return false
	}

	if m.prg != nil && !m.prg.Match(token) {
		return false
	}

	if m.re != nil && !m.re.MatchString(token.String()) {
		return false
	}

	attrs := map[string]string{}
	for _, attr := range token.Attr {
		attrs[attr.Key] = attr.Val
	}
	for _, attr := range m.Attrs {
		if val, ok := attrs[attr.Key]; !ok {
			return false
		} else if attr.Value != "" && val != attr.Value {
			return false
		}
	}

	return true
}

// MatchOptimized matches a SimpleToken for the optimized transformer
func (m *Matcher) MatchOptimized(token SimpleToken) bool {
	if token.Type != StateTagName {
		return false
	}

	if m.Tag != "" && !strings.EqualFold(m.Tag, token.TagName) {
		return false
	}

	// For CEL expressions, we need to convert SimpleToken to html.Token
	if m.prg != nil {
		htmlToken := html.Token{
			Type: html.StartTagToken,
			Data: token.TagName,
		}
		for key, value := range token.Attributes {
			htmlToken.Attr = append(htmlToken.Attr, html.Attribute{
				Key: key,
				Val: value,
			})
		}
		if !m.prg.Match(htmlToken) {
			return false
		}
	}

	// For regex matching, we need to reconstruct the tag string
	if m.re != nil {
		tagStr := "<" + token.TagName
		for key, value := range token.Attributes {
			tagStr += " " + key + "=\"" + value + "\""
		}
		tagStr += ">"
		if !m.re.MatchString(tagStr) {
			return false
		}
	}

	// Check attributes
	for _, attr := range m.Attrs {
		if val, ok := token.Attributes[attr.Key]; !ok {
			return false
		} else if attr.Value != "" && val != attr.Value {
			return false
		}
	}

	return true
}

// NewMatcher creates and initializes a new Matcher.
func NewMatcher(tag, re, expr string, attr map[string]string) (*Matcher, error) {
	matcher := &Matcher{
		Tag:     tag,
		Regex:   re,
		CELExpr: expr,
		Attrs:   make([]Attr, 0),
	}
	for key, value := range attr {
		matcher.Attrs = append(matcher.Attrs, Attr{Key: key, Value: value})
	}
	var err error
	if re != "" {
		if matcher.re, err = regexp.Compile(re); err != nil {
			return nil, err
		}
	}
	if expr != "" && tokenMatcherFactory != nil {
		if matcher.prg, err = tokenMatcherFactory(expr); err != nil {
			return nil, err
		}
	}
	return matcher, nil
}

