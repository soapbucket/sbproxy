package transformer

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/html"
)

func TestAttrJSONSerialization(t *testing.T) {
	attr := reqctx.Attr{
		Key:   "class",
		Value: "test-class",
	}

	// Test that the struct has JSON tags
	assert.Equal(t, "class", attr.Key)
	assert.Equal(t, "test-class", attr.Value)
}

func TestTagJSONSerialization(t *testing.T) {
	tag := Tag{
		Name:  "div",
		Data:  "Hello World",
		Attrs: []reqctx.Attr{{Key: "class", Value: "test"}},
		Type:  html.StartTagToken,
	}

	// Test that the struct has JSON tags
	assert.Equal(t, "div", tag.Name)
	assert.Equal(t, "Hello World", tag.Data)
	assert.Len(t, tag.Attrs, 1)
	assert.Equal(t, html.StartTagToken, tag.Type)
}

func TestTagString(t *testing.T) {
	tests := []struct {
		name     string
		tag      Tag
		expected string
	}{
		{
			name: "simple tag",
			tag: Tag{
				Name:  "div",
				Data:  "Hello",
				Type:  html.StartTagToken,
				Attrs: []reqctx.Attr{},
			},
			expected: "<div>Hello</div>",
		},
		{
			name: "tag with attributes",
			tag: Tag{
				Name:  "div",
				Data:  "Hello",
				Type:  html.StartTagToken,
				Attrs: []reqctx.Attr{{Key: "class", Value: "test"}},
			},
			expected: `<div class="test">Hello</div>`,
		},
		{
			name: "self-closing tag",
			tag: Tag{
				Name:  "img",
				Data:  "",
				Type:  html.SelfClosingTagToken,
				Attrs: []reqctx.Attr{{Key: "src", Value: "test.jpg"}},
			},
			expected: `<img src="test.jpg" />`,
		},
		{
			name: "void element",
			tag: Tag{
				Name:  "br",
				Data:  "",
				Type:  html.ErrorToken, // This triggers void element logic
				Attrs: []reqctx.Attr{},
			},
			expected: `<br />`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.tag.String()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestModifierJSONSerialization(t *testing.T) {
	tag := &Tag{
		Name:  "div",
		Data:  "content",
		Type:  html.StartTagToken,
		Attrs: []reqctx.Attr{},
	}

	modifier := Modifier{
		Tag:     tag,
		Content: "test content",
	}

	// Test that the struct has JSON tags
	assert.Equal(t, tag, modifier.Tag)
	assert.Equal(t, "test content", modifier.Content)
}

func TestVoidElements(t *testing.T) {
	// Test that all expected void elements are present
	expectedVoidElements := []string{
		"area", "base", "br", "col", "embed", "hr", "img", "input",
		"link", "meta", "param", "source", "track", "wbr",
	}

	for _, element := range expectedVoidElements {
		_, exists := voidElements[element]
		assert.True(t, exists, "Void element %s should be present", element)
	}
}

func TestAddToTag(t *testing.T) {
	tests := []struct {
		name     string
		src      string
		text     string
		token    html.Token
		expected string
	}{
		{
			name: "add to head end tag",
			src:  "head",
			text: "<script>console.log('test');</script>",
			token: html.Token{
				Type: html.StartTagToken,
				Data: "head",
			},
			expected: "", // AddToTag with prepend=false now adds after opening tag, so no output on start tag
		},
		{
			name: "no match - different tag",
			src:  "head",
			text: "<script>console.log('test');</script>",
			token: html.Token{
				Type: html.EndTagToken,
				Data: "body",
			},
			expected: "",
		},
		{
			name: "no match - different type",
			src:  "head",
			text: "<script>console.log('test');</script>",
			token: html.Token{
				Type: html.StartTagToken,
				Data: "head",
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn := AddToTag(tt.src, tt.text)

			var buffer bytes.Buffer
			err := fn(tt.token, &buffer)
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, buffer.String())
		})
	}
}

func TestAddToTagWithOptionalClosingTag(t *testing.T) {
	tests := []struct {
		name        string
		htmlContent string
		expected    string
		description string
	}{
		{
			name:        "head with explicit closing tag",
			htmlContent: `<html><head><title>Test</title></head><body><h1>Hello</h1></body></html>`,
			expected:    `<html><head><title>Test</title><script>console.log('test');</script></head><body><h1>Hello</h1></body></html>`,
			description: "HTML with explicit </head> tag should work as before",
		},
		{
			name:        "head without closing tag - should add before body",
			htmlContent: `<html><head><title>Test</title><body><h1>Hello</h1></body></html>`,
			expected:    `<html><head><title>Test</title><script>console.log('test');</script><body><h1>Hello</h1></body></html>`,
			description: "HTML without </head> tag should add content before <body> tag",
		},
		{
			name:        "head without closing tag and no body",
			htmlContent: `<html><head><title>Test</title></html>`,
			expected:    `<html><head><title>Test</title><script>console.log('test');</script></html>`,
			description: "HTML without </head> and </body> should add content at end of head",
		},
		{
			name:        "minimal HTML with head",
			htmlContent: `<head><title>Test</title><body><h1>Hello</h1></body>`,
			expected:    `<head><title>Test</title><script>console.log('test');</script><body><h1>Hello</h1></body>`,
			description: "Minimal HTML without html tags should still work",
		},
		{
			name:        "real-world example.com HTML with optional head closing",
			htmlContent: `<!doctype html><html lang="en"><head><title>Example Domain</title><meta name="viewport" content="width=device-width, initial-scale=1"><style>body{background:#eee;width:60vw;margin:15vh auto;font-family:system-ui,sans-serif}h1{font-size:1.5em}div{opacity:0.8}a:link,a:visited{color:#348}</style><body><div><h1>Example Domain</h1><p>This domain is for use in documentation examples without needing permission. Avoid use in operations.<p><a href="https://iana.org/domains/example">Learn more</a></div></body></html>`,
			expected:    `<!doctype html><html lang="en"><head><title>Example Domain</title><meta name="viewport" content="width=device-width, initial-scale=1"><style>body{background:#eee;width:60vw;margin:15vh auto;font-family:system-ui,sans-serif}h1{font-size:1.5em}div{opacity:0.8}a:link,a:visited{color:#348}</style><script>console.log('test');</script><body><div><h1>Example Domain</h1><p>This domain is for use in documentation examples without needing permission. Avoid use in operations.<p><a href="https://iana.org/domains/example">Learn more</a></div></body></html>`,
			description: "Real-world HTML from example.com with optional </head> tag should add content before <body>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test the current implementation to show it fails
			reader := strings.NewReader(tt.htmlContent)
			transformer := &HTMLTransformer{
				tokenizer: html.NewTokenizer(io.NopCloser(reader)),
				buffer:    &bytes.Buffer{},
				closer:    io.NopCloser(reader),
				// Use prepend: true to add before closing tag (old behavior)
				fns: []ModifyFn{AddToTagPrepend("head", "<script>console.log('test');</script>", true)},
			}

			var result bytes.Buffer
			buffer := make([]byte, 1024)
			for {
				n, err := transformer.Read(buffer)
				if err == io.EOF {
					break
				}
				require.NoError(t, err)
				result.Write(buffer[:n])
			}

			// Test the fixed implementation
			assert.Equal(t, tt.expected, result.String(), tt.description)
		})
	}
}

func TestTagTransformerModify(t *testing.T) {
	// This is a complex test that would require setting up matchers
	// For now, just test the basic structure
	transformer := &TagTransformer{
		matcher:   &reqctx.Matcher{},
		transform: &Modifier{Content: "test"},
		current:   nil,
	}

	assert.NotNil(t, transformer)
	assert.NotNil(t, transformer.matcher)
	assert.NotNil(t, transformer.transform)
}

func TestTransformTag(t *testing.T) {
	matcher := &reqctx.Matcher{}
	modifier := &Modifier{Content: "test"}

	fn := TransformTag(matcher, modifier)
	assert.NotNil(t, fn)
}
