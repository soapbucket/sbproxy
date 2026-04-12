// Package transform applies content transformations to HTTP request and response bodies.
package transformer

import (
	"bytes"
	"io"
	"log/slog"
	"strings"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"golang.org/x/net/html"
)

// AddToTag performs the add to tag operation.
func AddToTag(src string, text string) ModifyFn {
	// Default behavior: add after opening tag (prepend = false)
	return AddToTagPrepend(src, text, false)
}

// AddToTagPrepend performs the add to tag prepend operation.
func AddToTagPrepend(src string, text string, prepend bool) ModifyFn {
	// For head tag, we need special handling for optional closing tag
	if strings.EqualFold(src, "head") {
		if prepend {
			// prepend: true means add before closing tag (end of head content)
			return addToHeadTagEnd(text)
		}
		// prepend: false means add after opening tag (beginning of head content)
		return addToHeadTagBeginning(text)
	}

	// For other tags
	if prepend {
		// prepend: true means add before closing tag (end of tag content)
		return addToTagEnd(src, text)
	}
	// prepend: false means add after opening tag (beginning of tag content)
	return addToTagBeginning(src, text)
}

func addToTagBeginning(tagName string, text string) ModifyFn {
	// Track if we need to write content after the next token
	var pendingWrite bool
	var pendingContent string
	
	return func(token html.Token, writer io.Writer) error {
		// If we have a pending write, write it now (after the previous token was written)
		if pendingWrite {
			_, _ = writer.Write([]byte(pendingContent))
			pendingWrite = false
			pendingContent = ""
		}
		
		// If this is the start tag we're looking for, mark that we need to write after it
		if token.Type == html.StartTagToken && strings.EqualFold(token.Data, tagName) {
			pendingWrite = true
			pendingContent = text
		}
		
		return nil
	}
}

func addToTagEnd(tagName string, text string) ModifyFn {
	return func(token html.Token, writer io.Writer) error {
		// For end tags, we write before the closing tag (which is correct)
		if token.Type == html.EndTagToken && strings.EqualFold(token.Data, tagName) {
			_, _ = writer.Write([]byte(text))
		}
		return nil
	}
}

// addToHeadTagEnd handles the special case where </head> tag is optional
// Content is added before the closing </head> tag (or before body/html if no closing head)
func addToHeadTagEnd(text string) ModifyFn {
	var inHead bool
	var contentAdded bool

	return func(token html.Token, writer io.Writer) error {
		switch token.Type {
		case html.StartTagToken:
			if strings.EqualFold(token.Data, "head") {
				inHead = true
			} else if strings.EqualFold(token.Data, "body") && inHead && !contentAdded {
				// Body tag encountered while in head - add content before body
				_, _ = writer.Write([]byte(text))
				contentAdded = true
				inHead = false
			}
		case html.EndTagToken:
			if strings.EqualFold(token.Data, "head") {
				// Explicit </head> tag - add content before it
				if !contentAdded {
					_, _ = writer.Write([]byte(text))
					contentAdded = true
				}
				inHead = false
			} else if strings.EqualFold(token.Data, "html") && inHead && !contentAdded {
				// Closing </html> tag while still in head - add content before it
				_, _ = writer.Write([]byte(text))
				contentAdded = true
				inHead = false
			}
		}

		return nil
	}
}

// addToHeadTagBeginning handles adding content right after <head> opening tag
func addToHeadTagBeginning(text string) ModifyFn {
	// Track if we need to write content after the next token
	var pendingWrite bool
	
	return func(token html.Token, writer io.Writer) error {
		// If we have a pending write, write it now (after the previous token was written)
		if pendingWrite {
			_, _ = writer.Write([]byte(text))
			pendingWrite = false
		}
		
		// If this is the head start tag, mark that we need to write after it
		if token.Type == html.StartTagToken && strings.EqualFold(token.Data, "head") {
			pendingWrite = true
		}
		
		return nil
	}
}

var voidElements = map[string]interface{}{
	"area":   nil,
	"base":   nil,
	"br":     nil,
	"col":    nil,
	"embed":  nil,
	"hr":     nil,
	"img":    nil,
	"input":  nil,
	"link":   nil,
	"meta":   nil,
	"param":  nil,
	"source": nil,
	"track":  nil,
	"wbr":    nil,
}

// Tag represents a tag.
type Tag struct {
	Name  string           `json:"name"`
	Data  string           `json:"data"`
	Attrs []reqctx.Attr `json:"attrs,omitempty"`

	Type html.TokenType `json:"-"`
}

// String returns a human-readable representation of the Tag.
func (t *Tag) String() string {
	var buffer bytes.Buffer
	buffer.WriteByte('<')
	buffer.WriteString(t.Name)
	for _, attr := range t.Attrs {
		buffer.WriteByte(' ')
		buffer.WriteString(attr.Key)
		buffer.WriteByte('=')
		buffer.WriteByte('"')
		buffer.WriteString(attr.Value)
		buffer.WriteByte('"')
	}

	var selfClosing bool
	if t.Type == html.ErrorToken {
		_, ok := voidElements[t.Name]
		selfClosing = ok
	} else {
		selfClosing = t.Type == html.SelfClosingTagToken
	}

	if selfClosing {
		buffer.WriteString(" />")
	} else {
		buffer.WriteByte('>')
		buffer.WriteString(t.Data)
		buffer.WriteString("</")
		buffer.WriteString(t.Name)
		buffer.WriteByte('>')
	}
	return buffer.String()
}

// Modifier represents a modifier.
type Modifier struct {
	Tag     *Tag   `json:"tag,omitempty"`
	Content string `json:"content,omitempty"`
}

// TagTransformer represents a tag transformer.
type TagTransformer struct {
	matcher   *reqctx.Matcher
	transform *Modifier

	current *Tag
}

// Modify performs the modify operation on the TagTransformer.
func (t *TagTransformer) Modify(token html.Token, writer io.Writer) error {
	var err error
	var writeCurrent bool

	switch token.Type {
	case html.StartTagToken, html.SelfClosingTagToken:
		if t.matcher.Match(token) {
			attrs := make([]reqctx.Attr, len(token.Attr))
			for i, attr := range token.Attr {
				attrs[i] = reqctx.Attr{Key: attr.Key, Value: attr.Val}
			}
			t.current = &Tag{
				Name:  strings.ToLower(token.Data),
				Attrs: attrs,
				Type:  token.Type,
			}
			writeCurrent = token.Type == html.SelfClosingTagToken
			err = ErrSkipToken
		}

	case html.EndTagToken:
		writeCurrent = true

	case html.TextToken:
		if t.current != nil {
			t.current.Data += token.Data
			err = ErrSkipToken
		}

	}

	if writeCurrent && t.current != nil {
		tagValue := t.current.String()
		slog.Debug("write tag", "tag", tagValue)

		if t.transform.Tag != nil {
			_, _ = writer.Write([]byte(t.transform.Tag.String()))
		} else {
			_, _ = writer.Write([]byte(t.transform.Content))
		}
		t.current = nil
		err = ErrSkipToken

	}

	return err
}

// TransformTag performs the transform tag operation.
func TransformTag(matcher *reqctx.Matcher, transform *Modifier) ModifyFn {
	t := &TagTransformer{
		matcher:   matcher,
		transform: transform,
	}
	return t.Modify
}
