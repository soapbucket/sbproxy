package cel

import (
	"testing"

	"golang.org/x/net/html"
)

func TestNewTokenMatcher(t *testing.T) {
	tests := []struct {
		name    string
		expr    string
		wantErr bool
	}{
		{
			name:    "match tag name",
			expr:    `token.data == 'a'`,
			wantErr: false,
		},
		{
			name:    "check attribute exists",
			expr:    `'href' in token.attrs`,
			wantErr: false,
		},
		{
			name:    "match attribute value",
			expr:    `token.attrs['class'].contains('button')`,
			wantErr: false,
		},
		{
			name:    "invalid expression - not boolean",
			expr:    `token.data`,
			wantErr: true,
		},
		{
			name:    "syntax error",
			expr:    `token.data ==`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewTokenMatcher(tt.expr)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewTokenMatcher() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestTokenMatcherMatchTagName(t *testing.T) {
	tests := []struct {
		name      string
		expr      string
		token     html.Token
		wantMatch bool
	}{
		{
			name:      "match anchor tag",
			expr:      `token.data == 'a'`,
			token:     html.Token{Type: html.StartTagToken, Data: "a"},
			wantMatch: true,
		},
		{
			name:      "not match div when looking for a",
			expr:      `token.data == 'a'`,
			token:     html.Token{Type: html.StartTagToken, Data: "div"},
			wantMatch: false,
		},
		{
			name:      "match div tag",
			expr:      `token.data == 'div'`,
			token:     html.Token{Type: html.StartTagToken, Data: "div"},
			wantMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher, err := NewTokenMatcher(tt.expr)
			if err != nil {
				t.Fatalf("NewTokenMatcher() error = %v", err)
			}

			got := matcher.Match(tt.token)
			if got != tt.wantMatch {
				t.Errorf("Match() = %v, want %v", got, tt.wantMatch)
			}
		})
	}
}

func TestTokenMatcherMatchAttributes(t *testing.T) {
	token := html.Token{
		Type: html.StartTagToken,
		Data: "a",
		Attr: []html.Attribute{
			{Key: "href", Val: "https://example.com"},
			{Key: "class", Val: "btn btn-primary"},
			{Key: "id", Val: "submit-button"},
		},
	}

	tests := []struct {
		name      string
		expr      string
		wantMatch bool
	}{
		{
			name:      "attribute exists",
			expr:      `'href' in token.attrs`,
			wantMatch: true,
		},
		{
			name:      "attribute doesn't exist",
			expr:      `'data-test' in token.attrs`,
			wantMatch: false,
		},
		{
			name:      "attribute value match",
			expr:      `token.attrs['href'] == 'https://example.com'`,
			wantMatch: true,
		},
		{
			name:      "attribute contains substring",
			expr:      `token.attrs['class'].contains('btn-primary')`,
			wantMatch: true,
		},
		{
			name:      "attribute doesn't contain substring",
			expr:      `token.attrs['class'].contains('btn-danger')`,
			wantMatch: false,
		},
		{
			name:      "attribute startsWith",
			expr:      `token.attrs['href'].startsWith('https://')`,
			wantMatch: true,
		},
		{
			name:      "attribute endsWith",
			expr:      `token.attrs['href'].endsWith('.com')`,
			wantMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher, err := NewTokenMatcher(tt.expr)
			if err != nil {
				t.Fatalf("NewTokenMatcher() error = %v", err)
			}

			got := matcher.Match(token)
			if got != tt.wantMatch {
				t.Errorf("Match() = %v, want %v", got, tt.wantMatch)
			}
		})
	}
}

func TestTokenMatcherComplexExpressions(t *testing.T) {
	token := html.Token{
		Type: html.StartTagToken,
		Data: "a",
		Attr: []html.Attribute{
			{Key: "href", Val: "https://example.com"},
			{Key: "class", Val: "btn btn-primary"},
		},
	}

	tests := []struct {
		name      string
		expr      string
		wantMatch bool
	}{
		{
			name:      "tag and attribute",
			expr:      `token.data == 'a' && 'href' in token.attrs`,
			wantMatch: true,
		},
		{
			name:      "tag and attribute value",
			expr:      `token.data == 'a' && token.attrs['href'].startsWith('https://')`,
			wantMatch: true,
		},
		{
			name:      "multiple conditions",
			expr:      `token.data == 'a' && token.attrs['class'].contains('btn') && token.attrs['href'].contains('example')`,
			wantMatch: true,
		},
		{
			name:      "or condition",
			expr:      `token.data == 'button' || token.attrs['class'].contains('btn')`,
			wantMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher, err := NewTokenMatcher(tt.expr)
			if err != nil {
				t.Fatalf("NewTokenMatcher() error = %v", err)
			}

			got := matcher.Match(token)
			if got != tt.wantMatch {
				t.Errorf("Match() = %v, want %v", got, tt.wantMatch)
			}
		})
	}
}

func TestTokenMatcherNoAttributes(t *testing.T) {
	token := html.Token{
		Type: html.StartTagToken,
		Data: "div",
		Attr: []html.Attribute{},
	}

	matcher, err := NewTokenMatcher(`token.data == 'div'`)
	if err != nil {
		t.Fatalf("NewTokenMatcher() error = %v", err)
	}

	if !matcher.Match(token) {
		t.Error("Expected match for div tag with no attributes")
	}
}

func TestTokenMatcherEmptyToken(t *testing.T) {
	token := html.Token{
		Type: html.TextToken,
		Data: "",
	}

	matcher, err := NewTokenMatcher(`token.data == ''`)
	if err != nil {
		t.Fatalf("NewTokenMatcher() error = %v", err)
	}

	if !matcher.Match(token) {
		t.Error("Expected match for empty token")
	}
}

func TestTokenMatcherFormElements(t *testing.T) {
	inputToken := html.Token{
		Type: html.StartTagToken,
		Data: "input",
		Attr: []html.Attribute{
			{Key: "type", Val: "text"},
			{Key: "name", Val: "username"},
			{Key: "required", Val: ""},
		},
	}

	tests := []struct {
		name      string
		expr      string
		wantMatch bool
	}{
		{
			name:      "input tag",
			expr:      `token.data == 'input'`,
			wantMatch: true,
		},
		{
			name:      "input type",
			expr:      `token.data == 'input' && token.attrs['type'] == 'text'`,
			wantMatch: true,
		},
		{
			name:      "required attribute exists",
			expr:      `'required' in token.attrs`,
			wantMatch: true,
		},
		{
			name:      "specific name",
			expr:      `token.attrs['name'] == 'username'`,
			wantMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher, err := NewTokenMatcher(tt.expr)
			if err != nil {
				t.Fatalf("NewTokenMatcher() error = %v", err)
			}

			got := matcher.Match(inputToken)
			if got != tt.wantMatch {
				t.Errorf("Match() = %v, want %v", got, tt.wantMatch)
			}
		})
	}
}
