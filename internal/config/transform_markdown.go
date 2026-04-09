// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"github.com/gomarkdown/markdown"
	"github.com/gomarkdown/markdown/html"
	"github.com/gomarkdown/markdown/parser"
	"github.com/soapbucket/sbproxy/internal/transformer"
)

func init() {
	transformLoaderFns[TransformMarkdown] = NewMarkdownTransform
}

var _ TransformConfig = (*MarkdownTransform)(nil)

// NewMarkdownTransform creates and initializes a new MarkdownTransform.
func NewMarkdownTransform(data []byte) (TransformConfig, error) {
	t := &MarkdownTransform{}
	if err := json.Unmarshal(data, t); err != nil {
		return nil, err
	}
	t.tr = createMarkdownTransform(t)
	return t, nil
}

func createMarkdownTransform(t *MarkdownTransform) transformer.Transformer {
	return transformer.Func(func(resp *http.Response) error {
		// Check if transform should be applied
		if !t.shouldApply(resp) {
			return nil
		}

		// Read the response body
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			if t.FailOnError {
				return err
			}
			return nil
		}
		resp.Body.Close()

		// Parse and render markdown
		htmlOutput := t.render(body)

		// Replace body with HTML output
		resp.Body = io.NopCloser(bytes.NewReader(htmlOutput))
		resp.ContentLength = int64(len(htmlOutput))
		resp.Header.Set("Content-Length", string(rune(len(htmlOutput))))
		resp.Header.Set("Content-Type", "text/html; charset=utf-8")

		return nil
	})
}

func (t *MarkdownTransform) render(md []byte) []byte {
	// Compute parser extensions and HTML flags once per transform instance
	t.initOnce.Do(func() {
		extensions := parser.CommonExtensions

		if !t.DisableTables {
			extensions |= parser.Tables
		}
		if !t.DisableFencedCode {
			extensions |= parser.FencedCode
		}
		if !t.DisableAutolink {
			extensions |= parser.Autolink
		}
		if !t.DisableStrikethrough {
			extensions |= parser.Strikethrough
		}
		if !t.DisableTaskLists {
			extensions |= parser.LaxHTMLBlocks
		}
		if !t.DisableDefinitionLists {
			extensions |= parser.DefinitionLists
		}
		if !t.DisableFootnotes {
			extensions |= parser.Footnotes
		}
		if !t.DisableHeadingIDs {
			extensions |= parser.HeadingIDs
		}
		if !t.DisableAutoHeadingIDs {
			extensions |= parser.AutoHeadingIDs
		}
		t.extensions = int(extensions)

		htmlFlags := html.CommonFlags

		if t.SkipHTML {
			htmlFlags |= html.SkipHTML
		}
		if t.UseXHTML {
			htmlFlags |= html.UseXHTML
		}
		if t.NoreferrerNoopener {
			htmlFlags |= html.NoreferrerLinks
			htmlFlags |= html.NoopenerLinks
		}
		if t.Nofollow {
			htmlFlags |= html.NofollowLinks
		}
		if t.HrefTargetBlank {
			htmlFlags |= html.HrefTargetBlank
		}
		t.htmlFlags = int(htmlFlags)
	})

	// Create parser and renderer per call from cached config (parser holds state during Parse)
	p := parser.NewWithExtensions(parser.Extensions(t.extensions))
	doc := p.Parse(md)

	renderer := html.NewRenderer(html.RendererOptions{
		Flags: html.Flags(t.htmlFlags),
	})
	return markdown.Render(doc, renderer)
}

func (t *MarkdownTransform) shouldApply(resp *http.Response) bool {
	// Check if disabled for this content type
	contentType := resp.Header.Get("Content-Type")
	if t.disabledByContentType[contentType] {
		return false
	}

	// Check if content type matches
	matched := false
	for _, ct := range t.ContentTypes {
		if contentType == ct || (len(contentType) > len(ct) && contentType[:len(ct)] == ct) {
			matched = true
			break
		}
	}

	return matched
}

// GetType returns the type for the MarkdownTransform.
func (t *MarkdownTransform) GetType() string {
	return TransformMarkdown
}

// Transform performs the transform operation on the MarkdownTransform.
func (t *MarkdownTransform) Transform() transformer.Transformer {
	return t.tr
}
