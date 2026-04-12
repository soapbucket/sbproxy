// Package markdown registers the markdown transform.
package markdown

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"sync"

	"github.com/gomarkdown/markdown"
	"github.com/gomarkdown/markdown/html"
	"github.com/gomarkdown/markdown/parser"
	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func init() {
	plugin.RegisterTransform("markdown", New)
}

// Config holds configuration for the markdown transform.
type Config struct {
	Type                   string   `json:"type"`
	ContentTypes           []string `json:"content_types,omitempty"`
	FailOnError            bool     `json:"fail_on_error"`
	Sanitize               bool     `json:"sanitize,omitempty"`
	DisableTables          bool     `json:"disable_tables,omitempty"`
	DisableFencedCode      bool     `json:"disable_fenced_code,omitempty"`
	DisableAutolink        bool     `json:"disable_autolink,omitempty"`
	DisableStrikethrough   bool     `json:"disable_strikethrough,omitempty"`
	DisableTaskLists       bool     `json:"disable_task_lists,omitempty"`
	DisableDefinitionLists bool     `json:"disable_definition_lists,omitempty"`
	DisableFootnotes       bool     `json:"disable_footnotes,omitempty"`
	DisableHeadingIDs      bool     `json:"disable_heading_ids,omitempty"`
	DisableAutoHeadingIDs  bool     `json:"disable_auto_heading_ids,omitempty"`
	SkipHTML               bool     `json:"skip_html,omitempty"`
	UseXHTML               bool     `json:"use_xhtml,omitempty"`
	Nofollow               bool     `json:"nofollow,omitempty"`
	NoreferrerNoopener     bool     `json:"noreferrer_noopener,omitempty"`
	HrefTargetBlank        bool     `json:"href_target_blank,omitempty"`
}

var defaultMarkdownContentTypes = []string{"text/markdown", "text/x-markdown"}

// markdownTransform implements plugin.TransformHandler.
type markdownTransform struct {
	cfg        Config
	extensions int
	htmlFlags  int
	initOnce   sync.Once
}

// New creates a new markdown transform.
func New(data json.RawMessage) (plugin.TransformHandler, error) {
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &markdownTransform{cfg: cfg}, nil
}

func (t *markdownTransform) Type() string { return "markdown" }
func (t *markdownTransform) Apply(resp *http.Response) error {
	if !t.shouldApply(resp) {
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		if t.cfg.FailOnError {
			return err
		}
		return nil
	}
	resp.Body.Close()

	htmlOutput := t.render(body)

	resp.Body = io.NopCloser(bytes.NewReader(htmlOutput))
	resp.ContentLength = int64(len(htmlOutput))
	resp.Header.Set("Content-Length", string(rune(len(htmlOutput))))
	resp.Header.Set("Content-Type", "text/html; charset=utf-8")

	return nil
}

func (t *markdownTransform) render(md []byte) []byte {
	t.initOnce.Do(func() {
		extensions := parser.CommonExtensions
		if !t.cfg.DisableTables {
			extensions |= parser.Tables
		}
		if !t.cfg.DisableFencedCode {
			extensions |= parser.FencedCode
		}
		if !t.cfg.DisableAutolink {
			extensions |= parser.Autolink
		}
		if !t.cfg.DisableStrikethrough {
			extensions |= parser.Strikethrough
		}
		if !t.cfg.DisableTaskLists {
			extensions |= parser.LaxHTMLBlocks
		}
		if !t.cfg.DisableDefinitionLists {
			extensions |= parser.DefinitionLists
		}
		if !t.cfg.DisableFootnotes {
			extensions |= parser.Footnotes
		}
		if !t.cfg.DisableHeadingIDs {
			extensions |= parser.HeadingIDs
		}
		if !t.cfg.DisableAutoHeadingIDs {
			extensions |= parser.AutoHeadingIDs
		}
		t.extensions = int(extensions)

		htmlFlags := html.CommonFlags
		if t.cfg.SkipHTML {
			htmlFlags |= html.SkipHTML
		}
		if t.cfg.UseXHTML {
			htmlFlags |= html.UseXHTML
		}
		if t.cfg.NoreferrerNoopener {
			htmlFlags |= html.NoreferrerLinks
			htmlFlags |= html.NoopenerLinks
		}
		if t.cfg.Nofollow {
			htmlFlags |= html.NofollowLinks
		}
		if t.cfg.HrefTargetBlank {
			htmlFlags |= html.HrefTargetBlank
		}
		t.htmlFlags = int(htmlFlags)
	})

	p := parser.NewWithExtensions(parser.Extensions(t.extensions))
	doc := p.Parse(md)
	renderer := html.NewRenderer(html.RendererOptions{
		Flags: html.Flags(t.htmlFlags),
	})
	return markdown.Render(doc, renderer)
}

func (t *markdownTransform) shouldApply(resp *http.Response) bool {
	contentType := resp.Header.Get("Content-Type")

	cts := t.cfg.ContentTypes
	if cts == nil {
		cts = defaultMarkdownContentTypes
	}

	for _, ct := range cts {
		if contentType == ct || (len(contentType) > len(ct) && contentType[:len(ct)] == ct) {
			return true
		}
	}
	return false
}
