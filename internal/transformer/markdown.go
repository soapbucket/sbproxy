// Package transform applies content transformations to HTTP request and response bodies.
package transformer

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"math"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/net/html"
)

const (
	// DefaultTokenEstimate is the average tokens per word (GPT-3 style)
	// GPT-3 tokenizer uses ~1.3 tokens per word on average
	DefaultTokenEstimate = 1.3

	// MarkdownContentType is the content type for markdown responses
	MarkdownContentType = "text/markdown"

	// TokenCountHeader is the response header for token count
	TokenCountHeader = "x-markdown-tokens"
)

// ErrMarkdownConversionFailed is a sentinel error for markdown conversion failed conditions.
var ErrMarkdownConversionFailed = errors.New("markdown conversion failed")

// MarkdownOptions configures markdown transformation behavior
type MarkdownOptions struct {
	// TokenCounting enables x-markdown-tokens header in response
	TokenCounting bool

	// AcceptHeaderNegotiation only converts if Accept: text/markdown is present
	AcceptHeaderNegotiation bool

	// TokenEstimate is tokens per word approximation
	TokenEstimate float64
}

// DefaultMarkdownOptions returns sensible defaults
func DefaultMarkdownOptions() MarkdownOptions {
	return MarkdownOptions{
		TokenCounting:           false,
		AcceptHeaderNegotiation: true,
		TokenEstimate:           DefaultTokenEstimate,
	}
}

// ConvertMarkdown transforms HTML responses to markdown
func ConvertMarkdown(opts MarkdownOptions) Func {
	return Func(func(resp *http.Response) error {
		return convertMarkdown(resp, opts)
	})
}

func convertMarkdown(resp *http.Response, opts MarkdownOptions) error {
	slog.Debug("convertMarkdown for origin", "url", resp.Request.URL)

	// Skip for methods that don't have response bodies
	if resp.Request != nil {
		method := resp.Request.Method
		if method == http.MethodHead || method == http.MethodOptions {
			slog.Debug("Skipping markdown transform for request method without response body", "method", method)
			return nil
		}
	}

	// Check Accept header negotiation if enabled
	if opts.AcceptHeaderNegotiation && resp.Request != nil {
		acceptHeader := resp.Request.Header.Get("Accept")
		if !strings.Contains(acceptHeader, MarkdownContentType) {
			slog.Debug("Skipping markdown transform: Accept header does not request markdown",
				"accept", acceptHeader)
			return nil
		}
	}

	// Verify content type is HTML
	contentType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		slog.Debug("Failed to parse content type", "error", err)
		return nil // Skip on parse error
	}

	if !strings.EqualFold(contentType, "text/html") {
		slog.Debug("Skipping markdown transform for content type", "content_type", contentType)
		return nil // Skip non-HTML content
	}

	// Read the entire HTML body
	htmlBody, err := io.ReadAll(resp.Body)
	if err != nil {
		slog.Error("Failed to read response body", "error", err)
		return err
	}
	resp.Body.Close()

	// Parse HTML and convert to markdown
	markdownBody, err := htmlToMarkdown(htmlBody)
	if err != nil {
		slog.Error("Failed to convert HTML to markdown", "error", err)
		return ErrMarkdownConversionFailed
	}

	// Calculate token count if enabled
	var tokenCount int
	if opts.TokenCounting {
		tokenCount = estimateTokens(string(markdownBody), opts.TokenEstimate)
	}

	// Update response body
	resp.Body = io.NopCloser(bytes.NewReader(markdownBody))
	resp.ContentLength = int64(len(markdownBody))

	// Update Content-Type header
	resp.Header.Set("Content-Type", MarkdownContentType+"; charset=utf-8")

	// Add token count header if enabled
	if opts.TokenCounting && tokenCount > 0 {
		resp.Header.Set(TokenCountHeader, strconv.Itoa(tokenCount))
	}

	slog.Debug("Successfully converted HTML to markdown",
		"original_size", len(htmlBody),
		"markdown_size", len(markdownBody),
		"reduction_percent", int(100*(1-float64(len(markdownBody))/float64(len(htmlBody)))),
		"token_count", tokenCount)

	return nil
}

// htmlToMarkdown converts HTML content to markdown
func htmlToMarkdown(htmlBody []byte) ([]byte, error) {
	// Parse HTML
	doc, err := html.Parse(bytes.NewReader(htmlBody))
	if err != nil {
		slog.Warn("HTML parsing failed, attempting with best effort", "error", err)
		// Continue with partial parse
	}

	// Extract and convert to markdown
	markdown := extractBodyMarkdown(doc)
	return markdown, nil
}

// extractBodyMarkdown extracts the body content from parsed HTML and converts to markdown
func extractBodyMarkdown(doc *html.Node) []byte {
	if doc == nil {
		return []byte{}
	}

	var buf bytes.Buffer
	extractBodyNode(&buf, doc)
	return buf.Bytes()
}

// extractBodyNode recursively extracts text and structure from HTML nodes
func extractBodyNode(buf *bytes.Buffer, n *html.Node) {
	if n == nil {
		return
	}

	switch n.Type {
	case html.DocumentNode:
		// Process all children
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			extractBodyNode(buf, c)
		}

	case html.ElementNode:
		// Skip script and style tags
		if n.Data == "script" || n.Data == "style" {
			return
		}

		// Handle specific tags for markdown output
		switch n.Data {
		case "h1", "h2", "h3", "h4", "h5", "h6":
			level := int(n.Data[1] - '0')
			buf.WriteString(strings.Repeat("#", level) + " ")
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				extractBodyNode(buf, c)
			}
			buf.WriteString("\n\n")

		case "p":
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				extractBodyNode(buf, c)
			}
			buf.WriteString("\n\n")

		case "br":
			buf.WriteString("\n")

		case "hr":
			buf.WriteString("---\n\n")

		case "a":
			href := getAttr(n, "href")
			buf.WriteString("[")
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				extractBodyNode(buf, c)
			}
			if href != "" {
				buf.WriteString("](" + href + ")")
			} else {
				buf.WriteString("]")
			}

		case "strong", "b":
			buf.WriteString("**")
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				extractBodyNode(buf, c)
			}
			buf.WriteString("**")

		case "em", "i":
			buf.WriteString("*")
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				extractBodyNode(buf, c)
			}
			buf.WriteString("*")

		case "code":
			buf.WriteString("`")
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				extractBodyNode(buf, c)
			}
			buf.WriteString("`")

		case "pre":
			buf.WriteString("```\n")
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				extractBodyNode(buf, c)
			}
			buf.WriteString("\n```\n\n")

		case "ul", "ol":
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				extractBodyNode(buf, c)
			}
			buf.WriteString("\n")

		case "li":
			buf.WriteString("- ")
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				extractBodyNode(buf, c)
			}
			buf.WriteString("\n")

		case "blockquote":
			buf.WriteString("> ")
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				extractBodyNode(buf, c)
			}
			buf.WriteString("\n\n")

		case "table":
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				extractBodyNode(buf, c)
			}

		case "tr":
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				extractBodyNode(buf, c)
			}
			buf.WriteString("\n")

		case "td", "th":
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				extractBodyNode(buf, c)
			}
			buf.WriteString(" | ")

		case "img":
			alt := getAttr(n, "alt")
			src := getAttr(n, "src")
			if src != "" {
				buf.WriteString("![" + alt + "](" + src + ")")
			}

		default:
			// For other tags, just process children
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				extractBodyNode(buf, c)
			}
		}

	case html.TextNode:
		// Add text content, clean up whitespace
		text := strings.TrimSpace(n.Data)
		if text != "" {
			// Collapse multiple spaces
			text = strings.Join(strings.Fields(text), " ")
			buf.WriteString(text + " ")
		}

	case html.CommentNode:
		// Skip comments
	}
}

// getAttr gets an attribute value from an HTML node
func getAttr(n *html.Node, attrName string) string {
	for _, attr := range n.Attr {
		if strings.EqualFold(attr.Key, attrName) {
			return attr.Val
		}
	}
	return ""
}

// estimateTokens provides a rough token count estimate using GPT-3 style approximation
// The approximation: split on word boundaries, multiply by tokens-per-word coefficient
func estimateTokens(text string, tokensPerWord float64) int {
	if text == "" {
		return 0
	}

	// Split on whitespace and punctuation
	words := strings.FieldsFunc(text, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsPunct(r)
	})

	// Calculate estimated tokens
	estimate := math.Ceil(float64(len(words)) * tokensPerWord)
	return int(estimate)
}
