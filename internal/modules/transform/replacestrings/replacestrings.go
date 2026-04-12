// Package replacestrings registers the replace_strings transform.
package replacestrings

import (
	"encoding/json"
	"net/http"

	"github.com/soapbucket/sbproxy/internal/transformer"
	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func init() {
	plugin.RegisterTransform("replace_strings", New)
}

// ReplaceString is a single find/replace pair.
type ReplaceString struct {
	Find    string `json:"find"`
	Replace string `json:"replace"`
	Regex   bool   `json:"regex,omitempty"`
}

// ReplaceStrings holds the list of replacements.
type ReplaceStrings struct {
	Replacements []ReplaceString `json:"replacements,omitempty"`
}

// Config holds configuration for the replace_strings transform.
type Config struct {
	Type           string         `json:"type"`
	ReplaceStrings ReplaceStrings `json:"replace_strings"`
	ContentTypes   []string       `json:"content_types,omitempty"`
}

// replaceStringsTransform implements plugin.TransformHandler.
type replaceStringsTransform struct {
	tr transformer.Transformer
}

// New creates a new replace_strings transform.
func New(data json.RawMessage) (plugin.TransformHandler, error) {
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	replacements := make([]transformer.Replacement, 0, len(cfg.ReplaceStrings.Replacements))
	for _, r := range cfg.ReplaceStrings.Replacements {
		replacements = append(replacements, transformer.Replacement{
			Src:     r.Find,
			Dest:    r.Replace,
			IsRegex: r.Regex,
		})
	}

	t := &replaceStringsTransform{}
	if len(replacements) > 0 {
		t.tr = transformer.MultiStringReplacement(replacements)
	}
	return t, nil
}

func (r *replaceStringsTransform) Type() string { return "replace_strings" }
func (r *replaceStringsTransform) Apply(resp *http.Response) error {
	if r.tr == nil {
		return nil
	}
	return r.tr.Modify(resp)
}
