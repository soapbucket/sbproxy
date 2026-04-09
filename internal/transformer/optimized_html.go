// Package transform applies content transformations to HTTP request and response bodies.
package transformer

import (
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"bytes"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strings"
	"sync"
	"unicode"

	"golang.org/x/net/html"
)

const optimizedMaxBufferSize = 3 * 1024

// Optimized modification function that works with SimpleToken
type OptimizedModifyFn func(reqctx.SimpleToken, io.Writer) error

// ErrSkipOptimizedToken is a sentinel error for skip optimized token conditions.
var ErrSkipOptimizedToken = errors.New("skip")

// Pool for optimized HTML transformer buffers
var optimizedBufferPool = sync.Pool{
	New: func() interface{} {
		return bytes.NewBuffer(make([]byte, 0, optimizedMaxBufferSize))
	},
}

// Pool for string builders
var stringBuilderPool = sync.Pool{
	New: func() interface{} {
		return &strings.Builder{}
	},
}

// Pool for attribute maps
var attributeMapPool = sync.Pool{
	New: func() interface{} {
		m := make(map[string]string, 8) // Pre-allocate for typical tag attributes
		return &m
	},
}

// Pool for raw buffers
var rawBufferPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 0, 512)
		return &buf
	},
}

// OptimizedHTMLTransformer represents a optimized html transformer.
type OptimizedHTMLTransformer struct {
	reader io.Reader
	buffer *bytes.Buffer
	closer io.Closer
	fns    []OptimizedModifyFn
	state  reqctx.HTMLState
	err    error

	// State machine variables - using pooled objects
	currentTag   *strings.Builder
	currentAttr  *strings.Builder
	currentValue *strings.Builder
	attrName     string
	attributes   *map[string]string
	inQuotes     bool
	quoteChar    rune
	rawBuffer    *[]byte
}

// Read performs the read operation on the OptimizedHTMLTransformer.
func (t *OptimizedHTMLTransformer) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}

	// If we have buffered data, read from it first
	if t.buffer.Len() > 0 {
		n, err := t.buffer.Read(b)
		// Return data even if EOF, we'll get EOF on next call if needed
		if n > 0 {
			return n, nil
		}
		if err != nil && err != io.EOF {
			return 0, err
		}
	}

	// If we've already reached EOF and buffer is empty, return EOF
	if t.err == io.EOF {
		return 0, io.EOF
	}

	// Try to fill the buffer
	if err := t.fill(); err != nil {
		t.err = err
		// If we got EOF, check if we filled any data
		if err == io.EOF && t.buffer.Len() > 0 {
			// We have data, read it and return, EOF will be returned on next call
			return t.buffer.Read(b)
		}
		return 0, err
	}

	// Read from the newly filled buffer
	return t.buffer.Read(b)
}

func (t *OptimizedHTMLTransformer) initPools() {
	if t.currentTag == nil {
		t.currentTag = stringBuilderPool.Get().(*strings.Builder)
		t.currentTag.Reset()
	}
	if t.currentAttr == nil {
		t.currentAttr = stringBuilderPool.Get().(*strings.Builder)
		t.currentAttr.Reset()
	}
	if t.currentValue == nil {
		t.currentValue = stringBuilderPool.Get().(*strings.Builder)
		t.currentValue.Reset()
	}
	if t.attributes == nil {
		t.attributes = attributeMapPool.Get().(*map[string]string)
		// Clear any existing entries
		for k := range *t.attributes {
			delete(*t.attributes, k)
		}
	}
	if t.rawBuffer == nil {
		t.rawBuffer = rawBufferPool.Get().(*[]byte)
		*t.rawBuffer = (*t.rawBuffer)[:0]
	}
}

// Close releases resources held by the OptimizedHTMLTransformer.
func (t *OptimizedHTMLTransformer) Close() error {
	// Return buffer to pool
	if t.buffer != nil {
		slog.Debug("Returning optimized buffer to pool", "size", t.buffer.Len())
		t.buffer.Reset()
		optimizedBufferPool.Put(t.buffer)
		t.buffer = nil
	}

	// Return pooled objects
	if t.currentTag != nil {
		t.currentTag.Reset()
		stringBuilderPool.Put(t.currentTag)
		t.currentTag = nil
	}
	if t.currentAttr != nil {
		t.currentAttr.Reset()
		stringBuilderPool.Put(t.currentAttr)
		t.currentAttr = nil
	}
	if t.currentValue != nil {
		t.currentValue.Reset()
		stringBuilderPool.Put(t.currentValue)
		t.currentValue = nil
	}
	if t.attributes != nil {
		// Clear the map
		for k := range *t.attributes {
			delete(*t.attributes, k)
		}
		attributeMapPool.Put(t.attributes)
		t.attributes = nil
	}
	if t.rawBuffer != nil {
		*t.rawBuffer = (*t.rawBuffer)[:0]
		rawBufferPool.Put(t.rawBuffer)
		t.rawBuffer = nil
	}

	return t.closer.Close()
}

func (t *OptimizedHTMLTransformer) fill() error {
	// Initialize pooled objects if needed
	t.initPools()

	processedTokens := false

	// Read data in chunks
	chunk := make([]byte, 1024)

	for {
		if t.buffer.Len() >= optimizedMaxBufferSize {
			return nil
		}

		n, err := t.reader.Read(chunk)
		if n == 0 {
			if err == io.EOF {
				// Process any remaining state
				if t.state != reqctx.StateText {
					t.finalizeCurrentToken()
				}
				if processedTokens {
					return nil
				}
				return io.EOF
			}
			return err
		}

		// Process the chunk character by character
		processed := t.processChunk(chunk[:n])
		if processed {
			processedTokens = true
		}

		// Check if we've exceeded max buffer size
		if t.buffer.Len() >= optimizedMaxBufferSize {
			return nil
		}
	}
}

func (t *OptimizedHTMLTransformer) processChunk(data []byte) bool {
	processed := false

	for i := 0; i < len(data); i++ {
		char := data[i]

		switch t.state {
		case reqctx.StateText:
			if char == '<' {
				// Start of tag - write any accumulated text first
				if t.rawBuffer != nil && len(*t.rawBuffer) > 0 {
					t.buffer.Write(*t.rawBuffer)
					*t.rawBuffer = (*t.rawBuffer)[:0]
				}
				*t.rawBuffer = append(*t.rawBuffer, char)
				t.state = reqctx.StateTagStart
				t.currentTag.Reset()
				// Clear the attributes map instead of allocating a new one
				for k := range *t.attributes {
					delete(*t.attributes, k)
				}
				t.attrName = ""
				t.currentAttr.Reset()
				t.currentValue.Reset()
				t.inQuotes = false
			} else {
				// Regular text - accumulate in rawBuffer
				*t.rawBuffer = append(*t.rawBuffer, char)
			}

		case reqctx.StateTagStart:
			*t.rawBuffer = append(*t.rawBuffer, char)
			if char == '!' {
				// Comment or CDATA or DOCTYPE
				if i+1 < len(data) && data[i+1] == '-' {
					t.state = reqctx.StateComment
					i++ // Skip next character
					*t.rawBuffer = append(*t.rawBuffer, data[i])
				} else {
					t.state = reqctx.StateDoctype
				}
			} else if char == '?' {
				t.state = reqctx.StateProcessingInstruction
			} else if char == '/' {
				// End tag
				t.state = reqctx.StateTagName
				t.currentTag.WriteString("/")
			} else if unicode.IsLetter(rune(char)) {
				// Start tag
				t.state = reqctx.StateTagName
				t.currentTag.WriteByte(char)
			} else if char == '>' {
				// Empty tag
				t.finalizeCurrentToken()
				t.state = reqctx.StateText
				processed = true
			}

		case reqctx.StateTagName:
			*t.rawBuffer = append(*t.rawBuffer, char)
			if char == '>' {
				// End of tag
				t.finalizeCurrentToken()
				t.state = reqctx.StateText
				processed = true
			} else if unicode.IsSpace(rune(char)) {
				// Start of attributes
				t.state = reqctx.StateTagAttrName
				t.currentAttr.Reset()
			} else if char == '/' {
				// Self-closing tag - check if this is the end
				if i+1 < len(data) && data[i+1] == '>' {
					t.currentTag.WriteByte(char)
					*t.rawBuffer = append(*t.rawBuffer, data[i+1])
					i++ // Skip the '>'
					t.finalizeCurrentToken()
					t.state = reqctx.StateText
					processed = true
				} else {
					t.currentTag.WriteByte(char)
				}
			} else {
				t.currentTag.WriteByte(char)
			}

		case reqctx.StateTagAttrName:
			*t.rawBuffer = append(*t.rawBuffer, char)
			if char == '=' {
				t.attrName = strings.ToLower(strings.TrimSpace(t.currentAttr.String()))
				t.state = reqctx.StateTagAttrValue
				t.currentValue.Reset()
			} else if char == '>' {
				// End of tag without value
				if t.currentAttr.Len() > 0 {
					(*t.attributes)[strings.ToLower(strings.TrimSpace(t.currentAttr.String()))] = ""
				}
				t.finalizeCurrentToken()
				t.state = reqctx.StateText
				processed = true
			} else if char == '/' {
				// Self-closing tag - check if next char is '>'
				if i+1 < len(data) && data[i+1] == '>' {
					if t.currentAttr.Len() > 0 {
						(*t.attributes)[strings.ToLower(strings.TrimSpace(t.currentAttr.String()))] = ""
					}
					*t.rawBuffer = append(*t.rawBuffer, data[i+1])
					i++ // Skip the '>'
					t.finalizeCurrentToken()
					t.state = reqctx.StateText
					processed = true
				} else {
					// Just a slash, continue with attribute name
					t.currentAttr.WriteByte(char)
				}
			} else if !unicode.IsSpace(rune(char)) {
				t.currentAttr.WriteByte(char)
			}

		case reqctx.StateTagAttrValue:
			*t.rawBuffer = append(*t.rawBuffer, char)
			if char == '"' || char == '\'' {
				t.quoteChar = rune(char)
				t.inQuotes = true
				t.state = reqctx.StateTagAttrValueQuoted
			} else if !unicode.IsSpace(rune(char)) {
				t.currentValue.WriteByte(char)
				t.state = reqctx.StateTagAttrValueUnquoted
			}

		case reqctx.StateTagAttrValueQuoted:
			*t.rawBuffer = append(*t.rawBuffer, char)
			if char == byte(t.quoteChar) {
				// End of quoted value
				(*t.attributes)[t.attrName] = t.currentValue.String()
				t.attrName = ""
				t.currentAttr.Reset()
				t.currentValue.Reset()
				t.inQuotes = false
				t.state = reqctx.StateTagAttrName
			} else {
				t.currentValue.WriteByte(char)
			}

		case reqctx.StateTagAttrValueUnquoted:
			*t.rawBuffer = append(*t.rawBuffer, char)
			if char == '>' {
				// End of tag
				(*t.attributes)[t.attrName] = t.currentValue.String()
				t.finalizeCurrentToken()
				t.state = reqctx.StateText
				processed = true
			} else if char == '/' {
				// Self-closing tag - check if next char is '>'
				if i+1 < len(data) && data[i+1] == '>' {
					(*t.attributes)[t.attrName] = t.currentValue.String()
					*t.rawBuffer = append(*t.rawBuffer, data[i+1])
					i++ // Skip the '>'
					t.finalizeCurrentToken()
					t.state = reqctx.StateText
					processed = true
				} else {
					// Just a slash, continue with value
					t.currentValue.WriteByte(char)
				}
			} else if unicode.IsSpace(rune(char)) {
				// End of unquoted value
				(*t.attributes)[t.attrName] = t.currentValue.String()
				t.attrName = ""
				t.currentAttr.Reset()
				t.currentValue.Reset()
				t.state = reqctx.StateTagAttrName
			} else {
				t.currentValue.WriteByte(char)
			}

		case reqctx.StateComment:
			*t.rawBuffer = append(*t.rawBuffer, char)
			if char == '>' && i >= 2 && data[i-1] == '-' && data[i-2] == '-' {
				// End of comment
				t.buffer.Write(*t.rawBuffer)
				*t.rawBuffer = (*t.rawBuffer)[:0]
				t.state = reqctx.StateText
			}

		case reqctx.StateCDATA:
			*t.rawBuffer = append(*t.rawBuffer, char)
			if char == '>' && i >= 2 && data[i-1] == ']' && data[i-2] == ']' {
				// End of CDATA
				t.buffer.Write(*t.rawBuffer)
				*t.rawBuffer = (*t.rawBuffer)[:0]
				t.state = reqctx.StateText
			}

		case reqctx.StateDoctype:
			*t.rawBuffer = append(*t.rawBuffer, char)
			if char == '>' {
				// End of DOCTYPE
				t.buffer.Write(*t.rawBuffer)
				*t.rawBuffer = (*t.rawBuffer)[:0]
				t.state = reqctx.StateText
			}

		case reqctx.StateProcessingInstruction:
			*t.rawBuffer = append(*t.rawBuffer, char)
			if char == '>' && i >= 1 && data[i-1] == '?' {
				// End of processing instruction
				t.buffer.Write(*t.rawBuffer)
				*t.rawBuffer = (*t.rawBuffer)[:0]
				t.state = reqctx.StateText
			}
		}
	}

	return processed
}

func (t *OptimizedHTMLTransformer) finalizeCurrentToken() {
	// If we're in text state and have raw buffer, just write it
	if t.state == reqctx.StateText {
		if len(*t.rawBuffer) > 0 {
			t.buffer.Write(*t.rawBuffer)
			*t.rawBuffer = (*t.rawBuffer)[:0]
		}
		return
	}

	// For comments, doctype, and processing instructions, just write the raw buffer
	if t.state == reqctx.StateComment || t.state == reqctx.StateDoctype || t.state == reqctx.StateProcessingInstruction {
		t.buffer.Write(*t.rawBuffer)
		*t.rawBuffer = (*t.rawBuffer)[:0]
		return
	}

	// For tag states, create a token and apply modifications
	if t.currentTag.Len() == 0 {
		// Just write the raw buffer for non-tag states
		t.buffer.Write(*t.rawBuffer)
		*t.rawBuffer = (*t.rawBuffer)[:0]
		return
	}

	tagName := strings.ToLower(strings.TrimSpace(t.currentTag.String()))

	// Create a simple token for compatibility
	token := reqctx.SimpleToken{
		Type:       reqctx.StateTagName, // Always use reqctx.StateTagName for tags
		Data:       tagName,
		TagName:    tagName,
		Attributes: *t.attributes,
		Raw:        make([]byte, len(*t.rawBuffer)),
	}
	copy(token.Raw, *t.rawBuffer)

	// Apply modification functions if any
	if len(t.fns) > 0 {
		var err error
		for _, fn := range t.fns {
			if err = fn(token, t.buffer); err != nil {
				if err == ErrSkipOptimizedToken {
					// Skip writing this token
					*t.rawBuffer = (*t.rawBuffer)[:0]
					return
				}
				// For other errors, we'll continue but log the error
				slog.Error("Error in modification function", "error", err)
			}
		}
	}

	// Write the raw HTML
	t.buffer.Write(*t.rawBuffer)
	*t.rawBuffer = (*t.rawBuffer)[:0]
}

// OptimizedModifyHTML performs the optimized modify html operation.
func OptimizedModifyHTML(fns ...OptimizedModifyFn) Transformer {
	return Func(func(resp *http.Response) error {
		return optimizedModifyHTML(resp, fns...)
	})
}

func optimizedModifyHTML(resp *http.Response, fns ...OptimizedModifyFn) error {
	slog.Debug("optimizedModifyHTML for origin", "url", resp.Request.URL)

	// Skip HTML transformation for methods that should not have a response body
	// HEAD and OPTIONS requests typically don't have response bodies to transform
	if resp.Request != nil {
		method := resp.Request.Method
		if method == http.MethodHead || method == http.MethodOptions {
			slog.Debug("Skipping HTML transform for request method without response body", "method", method)
			return nil
		}
	}

	contentType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		slog.Error("Failed to parse content type", "error", err)
		return err
	}

	if !strings.EqualFold(contentType, "text/html") {
		slog.Debug("Skipping HTML transform for content type", "content_type", contentType)
		return ErrInvalidContentType
	}

	slog.Debug("Applying optimized HTML transform", "modification_functions", len(fns))

	// Get buffer from pool
	buffer := optimizedBufferPool.Get().(*bytes.Buffer)
	buffer.Reset()

	t := &OptimizedHTMLTransformer{
		buffer: buffer,
		reader: resp.Body,
		closer: resp.Body,
		fns:    fns,
		state:  reqctx.StateText,
		// Pooled objects will be initialized on first use
	}

	resp.Body = t
	return nil
}

// Helper function to convert OptimizedModifyFn to ModifyFn for backward compatibility
func ConvertToOptimizedModifyFn(fn ModifyFn) OptimizedModifyFn {
	return func(token reqctx.SimpleToken, writer io.Writer) error {
		// Convert reqctx.SimpleToken to html.Token for compatibility
		// In optimized HTML, end tags are represented by TagName starting with "/"
		var tokenType html.TokenType
		tagName := token.TagName
		
		if token.Type == reqctx.StateTagName {
			if strings.HasPrefix(token.TagName, "/") {
				// This is an end tag
				tokenType = html.EndTagToken
				tagName = strings.TrimPrefix(token.TagName, "/")
			} else {
				// This is a start tag
				tokenType = html.StartTagToken
			}
		} else {
			// For non-tag tokens, use the type as-is
			tokenType = html.TokenType(token.Type)
		}
		
		htmlToken := html.Token{
			Type: tokenType,
			Data: tagName,
		}

		// Convert attributes (only for start tags)
		if tokenType == html.StartTagToken {
			for key, value := range token.Attributes {
				htmlToken.Attr = append(htmlToken.Attr, html.Attribute{
					Key: key,
					Val: value,
				})
			}
		}

		return fn(htmlToken, writer)
	}
}
