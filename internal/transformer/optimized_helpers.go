// Package transform applies content transformations to HTTP request and response bodies.
package transformer

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync/atomic"

	"github.com/soapbucket/sbproxy/internal/observe/logging"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// OptimizedTagTransformer provides similar functionality to the original TagTransformer
// but works with SimpleToken instead of html.Token
type OptimizedTagTransformer struct {
	matcher   *reqctx.Matcher
	transform *Modifier
	current   *OptimizedTag
}

// OptimizedTag represents a optimized tag.
type OptimizedTag struct {
	Name  string
	Attrs map[string]string
	Type  reqctx.HTMLState
	Data  string
}

// String returns a human-readable representation of the OptimizedTag.
func (t *OptimizedTag) String() string {
	var buf strings.Builder

	if t.Type == reqctx.StateTagName && strings.HasPrefix(t.Name, "/") {
		// End tag
		buf.WriteString("</")
		buf.WriteString(strings.TrimPrefix(t.Name, "/"))
		buf.WriteString(">")
	} else {
		// Start tag
		buf.WriteString("<")
		buf.WriteString(t.Name)

		// Add attributes
		for key, value := range t.Attrs {
			buf.WriteString(" ")
			buf.WriteString(key)
			if value != "" {
				buf.WriteString("=\"")
				buf.WriteString(value)
				buf.WriteString("\"")
			}
		}

		if strings.HasSuffix(t.Name, "/") {
			buf.WriteString(" />")
		} else {
			buf.WriteString(">")
		}
	}

	return buf.String()
}

// Modify performs the modify operation on the OptimizedTagTransformer.
func (t *OptimizedTagTransformer) Modify(token reqctx.SimpleToken, writer io.Writer) error {
	var err error
	var writeCurrent bool

	switch token.Type {
	case reqctx.StateTagName:
		if !strings.HasPrefix(token.TagName, "/") {
			// Start tag
			if t.matcher.MatchOptimized(token) {
				t.current = &OptimizedTag{
					Name:  strings.ToLower(token.TagName),
					Attrs: token.Attributes,
					Type:  token.Type,
				}
				writeCurrent = strings.HasSuffix(token.TagName, "/")
				err = ErrSkipOptimizedToken
			}
		} else {
			// End tag
			writeCurrent = true
		}

	case reqctx.StateText:
		if t.current != nil {
			t.current.Data += token.Data
			err = ErrSkipOptimizedToken
		}
	}

	if writeCurrent && t.current != nil {
		tagValue := t.current.String()
		slog.Debug("write optimized tag",
			logging.FieldCaller, "transform:OptimizedTagTransformer:Modify",
			"tag", tagValue)

		if t.transform.Tag != nil {
			writer.Write([]byte(t.transform.Tag.String()))
		} else {
			writer.Write([]byte(t.transform.Content))
		}
		t.current = nil
		err = ErrSkipOptimizedToken
	}

	return err
}

// OptimizedTransformTag creates a modification function for tag transformation
func OptimizedTransformTag(matcher *reqctx.Matcher, transform *Modifier) OptimizedModifyFn {
	t := &OptimizedTagTransformer{
		matcher:   matcher,
		transform: transform,
	}
	return t.Modify
}

// OptimizedAddAttribute adds an attribute to matching tags
func OptimizedAddAttribute(matcher *reqctx.Matcher, attrName, attrValue string) OptimizedModifyFn {
	return func(token reqctx.SimpleToken, writer io.Writer) error {
		if token.Type == reqctx.StateTagName && !strings.HasPrefix(token.TagName, "/") {
			if matcher.MatchOptimized(token) {
				// Check if attribute already exists
				if _, exists := token.Attributes[attrName]; !exists {
					// We need to modify the raw HTML to add the attribute
					// This is a simplified approach - in practice, you might want to
					// reconstruct the tag with the new attribute
					rawStr := string(token.Raw)
					if strings.HasSuffix(rawStr, ">") {
						newRaw := strings.TrimSuffix(rawStr, ">")
						newRaw += fmt.Sprintf(" %s=\"%s\">", attrName, attrValue)
						writer.Write([]byte(newRaw))
						return ErrSkipOptimizedToken
					}
				}
			}
		}
		return nil
	}
}

// OptimizedRemoveAttribute removes an attribute from matching tags
func OptimizedRemoveAttribute(matcher *reqctx.Matcher, attrName string) OptimizedModifyFn {
	return func(token reqctx.SimpleToken, writer io.Writer) error {
		if token.Type == reqctx.StateTagName && !strings.HasPrefix(token.TagName, "/") {
			if matcher.MatchOptimized(token) {
				if _, exists := token.Attributes[attrName]; exists {
					// Remove the attribute from the raw HTML
					rawStr := string(token.Raw)

					// Remove quoted attributes
					rawStr = strings.ReplaceAll(rawStr, fmt.Sprintf(` %s="%s"`, attrName, token.Attributes[attrName]), "")
					rawStr = strings.ReplaceAll(rawStr, fmt.Sprintf(` %s='%s'`, attrName, token.Attributes[attrName]), "")
					rawStr = strings.ReplaceAll(rawStr, fmt.Sprintf(` %s=%s`, attrName, token.Attributes[attrName]), "")

					writer.Write([]byte(rawStr))
					return ErrSkipOptimizedToken
				}
			}
		}
		return nil
	}
}

// OptimizedReplaceContent replaces the content of matching tags
func OptimizedReplaceContent(matcher *reqctx.Matcher, newContent string) OptimizedModifyFn {
	return func(token reqctx.SimpleToken, writer io.Writer) error {
		if token.Type == reqctx.StateText {
			// This would need to track the current tag context
			// For now, this is a placeholder implementation
			writer.Write([]byte(newContent))
			return ErrSkipOptimizedToken
		}
		return nil
	}
}

// Helper function to create a simple matcher for the optimized transformer
func OptimizedMatchTag(tagName string) *reqctx.Matcher {
	return &reqctx.Matcher{
		Tag: tagName,
	}
}

// Helper function to create a matcher with attributes for the optimized transformer
func OptimizedMatchTagWithAttr(tagName, attrName, attrValue string) *reqctx.Matcher {
	return &reqctx.Matcher{
		Tag: tagName,
		Attrs: []reqctx.Attr{
			{Key: attrName, Value: attrValue},
		},
	}
}

// OptimizedAddUniqueID creates an optimized modifier function that adds unique IDs to HTML elements.
// This is the optimized version that works with SimpleToken instead of html.Token.
func OptimizedAddUniqueID(options AddUniqueIDOptions) OptimizedModifyFn {
	// Set defaults
	if options.Prefix == "" {
		options.Prefix = "id"
	}

	// Counter for sequential IDs
	var counter int64

	// Elements that support the id attribute (most HTML elements do)
	// We'll be permissive and add IDs to most elements, excluding only a few that don't make sense
	elementsWithoutID := map[string]bool{
		"html":   true,
		"head":   true,
		"body":   true,
		"meta":   true,
		"title":  true,
		"link":   true,
		"script": true,
		"style":  true,
		"base":   true,
	}

	return func(token reqctx.SimpleToken, w io.Writer) error {
		// Only process tag tokens (not end tags)
		if token.Type != reqctx.StateTagName || strings.HasPrefix(token.TagName, "/") {
			return nil
		}

		// Skip elements that don't support or shouldn't have IDs
		if elementsWithoutID[strings.ToLower(token.TagName)] {
			return nil
		}

		// Check if element already has an ID
		hasID := false
		if _, exists := token.Attributes["id"]; exists {
			hasID = true
		}

		// Skip if element already has ID and we're not replacing
		if hasID && !options.ReplaceExisting {
			return nil
		}

		// Generate unique ID
		var id string
		if options.UseRandomSuffix {
			// Generate random hex suffix
			randomBytes := make([]byte, 4)
			rand.Read(randomBytes)
			id = fmt.Sprintf("%s-%s", options.Prefix, hex.EncodeToString(randomBytes))
		} else {
			// Use sequential counter
			id = fmt.Sprintf("%s-%d", options.Prefix, atomic.AddInt64(&counter, 1))
		}

		// Create new attributes map
		newAttrs := make(map[string]string)
		for key, value := range token.Attributes {
			newAttrs[key] = value
		}

		// Add or replace the ID
		newAttrs["id"] = id

		// Reconstruct the tag with the new ID
		var result strings.Builder
		result.WriteString("<")
		result.WriteString(token.TagName)

		// Add attributes
		for key, value := range newAttrs {
			result.WriteString(" ")
			result.WriteString(key)
			if value != "" {
				result.WriteString("=\"")
				result.WriteString(value)
				result.WriteString("\"")
			}
		}

		// Handle self-closing tags
		if strings.HasSuffix(token.TagName, "/") {
			result.WriteString(" />")
		} else {
			result.WriteString(">")
		}

		// Write the modified token
		w.Write([]byte(result.String()))
		return ErrSkipOptimizedToken // Skip the original token
	}
}
