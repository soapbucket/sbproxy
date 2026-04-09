// Package transform applies content transformations to HTTP request and response bodies.
package transformer

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync/atomic"

	"golang.org/x/net/html"
)

// StripSpaceOptions configures the behavior of the stripSpace modifier
type StripSpaceOptions struct {
	// StripNewlines removes unnecessary newline characters and replaces multiple spaces with single spaces
	StripNewlines bool
	// StripExtraSpaces removes extra spaces between attributes in HTML tags
	StripExtraSpaces bool
}

// StripSpace creates a modifier function that strips unnecessary whitespace from HTML documents.
// It can be passed to the HTMLTransformer to clean up whitespace in HTML content.
//
// Options:
//   - StripNewlines: When true, removes newlines and replaces multiple spaces with single spaces
//   - StripExtraSpaces: When true, trims spaces from attribute values in HTML tags
//
// Example usage:
//
//	transform := ModifyHTML(StripSpace(StripSpaceOptions{
//	    StripNewlines:    true,
//	    StripExtraSpaces: true,
//	}))
func StripSpace(options StripSpaceOptions) ModifyFn {
	return func(token html.Token, w io.Writer) error {
		// Process text tokens to strip whitespace
		if token.Type == html.TextToken {
			// Strip whitespace from text content
			cleaned := token.Data
			if options.StripNewlines {
				// Remove newlines and replace multiple spaces with single space
				cleaned = regexp.MustCompile(`\s+`).ReplaceAllString(cleaned, " ")
			} else {
				// Only trim leading and trailing whitespace
				cleaned = strings.TrimSpace(cleaned)
			}

			// Only write if there's content (skip empty whitespace-only tokens)
			if cleaned != "" {
				_, _ = w.Write([]byte(cleaned))
			}
			return ErrSkipToken // Skip the original token
		} else if token.Type == html.StartTagToken || token.Type == html.SelfClosingTagToken {
			// Clean up attributes for start tags
			if options.StripExtraSpaces {
				// Rebuild the token with cleaned attributes
				var cleanedAttrs []html.Attribute
				for _, attr := range token.Attr {
					// Trim spaces from attribute values
					attr.Key = strings.TrimSpace(attr.Key)
					attr.Val = strings.TrimSpace(attr.Val)
					cleanedAttrs = append(cleanedAttrs, attr)
				}
				token.Attr = cleanedAttrs

				// Write the cleaned token
				_, _ = w.Write([]byte(token.String()))
				return ErrSkipToken // Skip the original token
			}
		}
		return nil
	}
}

// OptimizeHTMLOptions configures the behavior of the OptimizeHTML modifier
type OptimizeHTMLOptions struct {
	// RemoveBooleanAttributes removes quotes from boolean attributes (e.g., checked="checked" -> checked)
	RemoveBooleanAttributes bool
	// RemoveQuotesFromAttributes removes quotes from attributes that don't need them per HTML spec
	// (e.g., class="my-class" -> class=my-class, but only when the value is safe to unquote)
	RemoveQuotesFromAttributes bool
	// RemoveTrailingSlashes removes trailing slashes from self-closing tags where not needed
	RemoveTrailingSlashes bool
	// StripComments removes HTML comments
	StripComments bool
	// OptimizeAttributes removes unnecessary spaces and quotes from attributes
	OptimizeAttributes bool
	// SortAttributes sorts attributes alphabetically for consistent output
	SortAttributes bool

	LowercaseTags bool
	// LowercaseAttributes lowercase attribute names
	LowercaseAttributes bool
}

// OptimizeHTML creates a modifier function that optimizes HTML according to HTML specification.
// It can be passed to the HTMLTransformer to optimize HTML content.
//
// Options:
//   - RemoveBooleanAttributes: When true, removes quotes from boolean attributes (checked="checked" -> checked)
//   - RemoveTrailingSlashes: When true, removes trailing slashes from self-closing tags where not needed
//   - StripComments: When true, removes HTML comments
//   - OptimizeAttributes: When true, optimizes attribute formatting
//   - SortAttributes: When true, sorts attributes alphabetically for consistent output
//   - LowercaseTags: When true, converts tag names to lowercase
//   - LowercaseAttributes: When true, converts attribute names to lowercase
//
// Example usage:
//
//	transform := ModifyHTML(OptimizeHTML(OptimizeHTMLOptions{
//	    RemoveBooleanAttributes: true,
//	    RemoveTrailingSlashes:   true,
//	    StripComments:           true,
//	    OptimizeAttributes:      true,
//	    SortAttributes:          true,
//	    LowercaseTags:           true,
//	    LowercaseAttributes:     true,
//	}))
func OptimizeHTML(options OptimizeHTMLOptions) ModifyFn {
	// Boolean attributes that don't need quotes
	booleanAttributes := map[string]bool{
		"checked":        true,
		"disabled":       true,
		"readonly":       true,
		"required":       true,
		"selected":       true,
		"defer":          true,
		"async":          true,
		"autofocus":      true,
		"autoplay":       true,
		"controls":       true,
		"default":        true,
		"formnovalidate": true,
		"hidden":         true,
		"ismap":          true,
		"itemscope":      true,
		"loop":           true,
		"multiple":       true,
		"muted":          true,
		"noresize":       true,
		"noshade":        true,
		"novalidate":     true,
		"nowrap":         true,
		"open":           true,
		"reversed":       true,
		"seamless":       true,
		"truespeed":      true,
	}

	// canUnquoteAttributeValue checks if an attribute value can be safely unquoted per HTML spec
	canUnquoteAttributeValue := func(value string) bool {
		if value == "" {
			return false
		}

		// Check each character in the value
		for i, r := range value {
			// First character cannot be a hyphen
			if i == 0 && r == '-' {
				return false
			}

			// Character must be alphanumeric, hyphen, underscore, or period
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
				(r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.') {
				return false
			}
		}

		return true
	}

	// Tags that don't need trailing slashes in HTML5
	noTrailingSlashTags := map[string]bool{
		"area":   true,
		"base":   true,
		"br":     true,
		"col":    true,
		"embed":  true,
		"hr":     true,
		"img":    true,
		"input":  true,
		"link":   true,
		"meta":   true,
		"param":  true,
		"source": true,
		"track":  true,
		"wbr":    true,
	}

	return func(token html.Token, w io.Writer) error {
		// Strip HTML comments
		if token.Type == html.CommentToken && options.StripComments {
			return ErrSkipToken // Skip the comment
		}

		// Handle end tags - only lowercase if requested
		if token.Type == html.EndTagToken {
			if options.LowercaseTags {
				token.Data = strings.ToLower(token.Data)
				// Write the modified end tag
				_, _ = w.Write([]byte(fmt.Sprintf("</%s>", token.Data)))
				return ErrSkipToken
			}
			return nil
		}

		// Optimize start tags and self-closing tags
		if token.Type == html.StartTagToken || token.Type == html.SelfClosingTagToken {
			if options.RemoveBooleanAttributes || options.RemoveQuotesFromAttributes || options.RemoveTrailingSlashes || options.OptimizeAttributes || options.SortAttributes || options.LowercaseTags || options.LowercaseAttributes {
				// Lowercase tag name if requested
				if options.LowercaseTags {
					token.Data = strings.ToLower(token.Data)
				}

				// Create optimized attributes
				var optimizedAttrs []html.Attribute
				for _, attr := range token.Attr {
					optimizedAttr := attr

					// Lowercase attribute name if requested
					if options.LowercaseAttributes {
						optimizedAttr.Key = strings.ToLower(attr.Key)
					}

					// Optimize attribute formatting first
					if options.OptimizeAttributes {
						optimizedAttr.Key = strings.TrimSpace(optimizedAttr.Key)
						optimizedAttr.Val = strings.TrimSpace(attr.Val)
					}

					// Remove quotes from boolean attributes (after trimming)
					// Use the potentially lowercased key for boolean attribute check
					attrKeyForCheck := optimizedAttr.Key
					if options.RemoveBooleanAttributes && booleanAttributes[attrKeyForCheck] {
						// For boolean attributes, remove the value entirely per HTML spec
						// Boolean attributes are either present (no value) or absent
						optimizedAttr.Val = ""
					}

					// Remove quotes from attributes that don't need them per HTML spec
					if options.RemoveQuotesFromAttributes && optimizedAttr.Val != "" && canUnquoteAttributeValue(optimizedAttr.Val) {
						// Keep the value but mark it as unquoted (we'll handle this in optimizeTokenString)
						// We'll add a special marker to indicate this should be unquoted
						optimizedAttr.Val = "UNQUOTE:" + optimizedAttr.Val
					}

					optimizedAttrs = append(optimizedAttrs, optimizedAttr)
				}

				// Sort attributes alphabetically if requested
				if options.SortAttributes {
					// Sort by attribute key
					for i := 0; i < len(optimizedAttrs); i++ {
						for j := i + 1; j < len(optimizedAttrs); j++ {
							if optimizedAttrs[i].Key > optimizedAttrs[j].Key {
								optimizedAttrs[i], optimizedAttrs[j] = optimizedAttrs[j], optimizedAttrs[i]
							}
						}
					}
				}

				token.Attr = optimizedAttrs

				// Remove trailing slash for certain tags in HTML5
				if options.RemoveTrailingSlashes && token.Type == html.SelfClosingTagToken {
					if noTrailingSlashTags[token.Data] {
						// Convert to regular start tag
						token.Type = html.StartTagToken
					}
				}

				// Write the optimized token manually to handle boolean attributes correctly
				_, _ = w.Write([]byte(optimizeTokenString(token)))
				return ErrSkipToken // Skip the original token
			}
		}

		return nil
	}
}

// optimizeTokenString manually constructs HTML string to handle boolean attributes correctly
func optimizeTokenString(token html.Token) string {
	var result strings.Builder

	// Boolean attributes that don't need values
	booleanAttributes := map[string]bool{
		"checked":        true,
		"disabled":       true,
		"readonly":       true,
		"required":       true,
		"selected":       true,
		"defer":          true,
		"async":          true,
		"autofocus":      true,
		"autoplay":       true,
		"controls":       true,
		"default":        true,
		"formnovalidate": true,
		"hidden":         true,
		"ismap":          true,
		"itemscope":      true,
		"loop":           true,
		"multiple":       true,
		"muted":          true,
		"noresize":       true,
		"noshade":        true,
		"novalidate":     true,
		"nowrap":         true,
		"open":           true,
		"reversed":       true,
		"seamless":       true,
		"truespeed":      true,
	}

	result.WriteString("<")
	result.WriteString(token.Data)

	for _, attr := range token.Attr {
		result.WriteString(" ")
		result.WriteString(attr.Key)

		// For boolean attributes with empty values, don't add =""
		if booleanAttributes[attr.Key] && attr.Val == "" {
			// Don't add value for boolean attributes
		} else if strings.HasPrefix(attr.Val, "UNQUOTE:") {
			// Handle unquoted values (remove the marker and don't add quotes)
			unquotedValue := strings.TrimPrefix(attr.Val, "UNQUOTE:")
			result.WriteString("=")
			result.WriteString(unquotedValue)
		} else {
			result.WriteString("=\"")
			result.WriteString(attr.Val)
			result.WriteString("\"")
		}
	}

	if token.Type == html.SelfClosingTagToken {
		result.WriteString(" />")
	} else {
		result.WriteString(">")
	}

	return result.String()
}

// AddUniqueIDOptions configures the behavior of the AddUniqueID modifier
type AddUniqueIDOptions struct {
	// Prefix is the prefix to use for generated IDs (default: "id")
	Prefix string
	// ReplaceExisting when true, replaces existing IDs; when false, skips elements that already have IDs
	ReplaceExisting bool
	// UseRandomSuffix when true, uses random hex suffix; when false, uses sequential counter
	UseRandomSuffix bool
}

// AddUniqueID creates a modifier function that adds unique IDs to HTML elements that support the id attribute.
// It can be passed to the HTMLTransformer to add unique identifiers to HTML content.
//
// Options:
//   - Prefix: The prefix to use for generated IDs (default: "id")
//   - ReplaceExisting: When true, replaces existing IDs; when false, skips elements that already have IDs
//   - UseRandomSuffix: When true, uses random hex suffix; when false, uses sequential counter
//
// Example usage:
//
//	transform := ModifyHTML(AddUniqueID(AddUniqueIDOptions{
//	    Prefix:           "element",
//	    ReplaceExisting:  false,
//	    UseRandomSuffix:  true,
//	}))
func AddUniqueID(options AddUniqueIDOptions) ModifyFn {
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

	return func(token html.Token, w io.Writer) error {
		// Only process start tags and self-closing tags
		if token.Type != html.StartTagToken && token.Type != html.SelfClosingTagToken {
			return nil
		}

		// Skip elements that don't support or shouldn't have IDs
		if elementsWithoutID[strings.ToLower(token.Data)] {
			return nil
		}

		// Check if element already has an ID
		hasID := false
		for _, attr := range token.Attr {
			if strings.EqualFold(attr.Key, "id") {
				hasID = true
				break
			}
		}

		// Skip if element already has ID and we're not replacing
		if hasID && !options.ReplaceExisting {
			return nil
		}

		prefix := options.Prefix
		if prefix == "" {
			prefix = "id"
		}

		// Generate unique ID
		var id string
		if options.UseRandomSuffix {
			// Generate random hex suffix
			randomBytes := make([]byte, 4)
			_, _ = rand.Read(randomBytes)
			id = fmt.Sprintf("%s%s", prefix, hex.EncodeToString(randomBytes))
		} else {
			// Use sequential counter
			id = fmt.Sprintf("%s%d", prefix, atomic.AddInt64(&counter, 1))
		}

		// Create new attributes slice
		var newAttrs []html.Attribute
		idAdded := false

		for _, attr := range token.Attr {
			if strings.EqualFold(attr.Key, "id") {
				// Replace existing ID
				newAttrs = append(newAttrs, html.Attribute{Key: "id", Val: id})
				idAdded = true
			} else {
				newAttrs = append(newAttrs, attr)
			}
		}

		// Add ID if it wasn't already present
		if !idAdded {
			newAttrs = append(newAttrs, html.Attribute{Key: "id", Val: id})
		}

		// Create new token with the ID
		newToken := html.Token{
			Type:     token.Type,
			Data:     token.Data,
			Attr:     newAttrs,
			DataAtom: token.DataAtom,
		}

		// Write the modified token
		_, _ = w.Write([]byte(newToken.String()))
		return ErrSkipToken // Skip the original token
	}
}
