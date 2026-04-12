// Package optimizehtml registers the optimized_html transform.
package optimizehtml

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/soapbucket/sbproxy/internal/transformer"
	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func init() {
	plugin.RegisterTransform("optimized_html", New)
}

// OptimizedFormatOptions holds format options for the optimized HTML transform.
type OptimizedFormatOptions struct {
	StripNewlines              bool `json:"strip_newlines,omitempty"`
	StripSpace                 bool `json:"strip_space,omitempty"`
	RemoveBooleanAttributes    bool `json:"remove_boolean_attributes,omitempty"`
	RemoveQuotesFromAttributes bool `json:"remove_quotes_from_attributes,omitempty"`
	RemoveTrailingSlashes      bool `json:"remove_trailing_slashes,omitempty"`
	StripComments              bool `json:"strip_comments,omitempty"`
	OptimizeAttributes         bool `json:"optimize_attributes,omitempty"`
	SortAttributes             bool `json:"sort_attributes,omitempty"`
}

// AttributeOptions holds attribute options.
type AttributeOptions struct {
	AddUniqueIDs    bool   `json:"add_unique_ids,omitempty"`
	UniqueIDPrefix  string `json:"unique_id_prefix,omitempty"`
	ReplaceExisting bool   `json:"replace_existing,omitempty"`
	UseRandomSuffix bool   `json:"use_random_suffix,omitempty"`
}

// AddToTagConfig configures content to add to a specific tag.
type AddToTagConfig struct {
	Tag             string `json:"tag"`
	AddBeforeEndTag *bool  `json:"add_before_end_tag,omitempty"`
	Content         string `json:"content"`
}

// Config holds configuration for the optimized_html transform.
type Config struct {
	Type             string                  `json:"type"`
	ContentTypes     []string                `json:"content_types,omitempty"`
	FormatOptions    *OptimizedFormatOptions `json:"format_options,omitempty"`
	AttributeOptions *AttributeOptions       `json:"attribute_options,omitempty"`
	AddToTags        []AddToTagConfig        `json:"add_to_tags,omitempty"`
}

// optimizedHTMLTransform implements plugin.TransformHandler.
type optimizedHTMLTransform struct {
	tr transformer.Transformer
}

// New creates a new optimized_html transform.
func New(data json.RawMessage) (plugin.TransformHandler, error) {
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	var modifyFns []transformer.OptimizedModifyFn

	if cfg.FormatOptions != nil {
		if cfg.FormatOptions.StripNewlines || cfg.FormatOptions.StripSpace {
			modifyFns = append(modifyFns, transformer.ConvertToOptimizedModifyFn(
				transformer.StripSpace(
					transformer.StripSpaceOptions{
						StripExtraSpaces: cfg.FormatOptions.StripSpace,
						StripNewlines:    cfg.FormatOptions.StripNewlines,
					},
				),
			))
		}

		if cfg.FormatOptions.RemoveBooleanAttributes || cfg.FormatOptions.RemoveQuotesFromAttributes ||
			cfg.FormatOptions.RemoveTrailingSlashes || cfg.FormatOptions.StripComments ||
			cfg.FormatOptions.OptimizeAttributes || cfg.FormatOptions.SortAttributes {
			modifyFns = append(modifyFns,
				transformer.ConvertToOptimizedModifyFn(
					transformer.OptimizeHTML(
						transformer.OptimizeHTMLOptions{
							RemoveBooleanAttributes:    cfg.FormatOptions.RemoveBooleanAttributes,
							RemoveQuotesFromAttributes: cfg.FormatOptions.RemoveQuotesFromAttributes,
							RemoveTrailingSlashes:      cfg.FormatOptions.RemoveTrailingSlashes,
							StripComments:              cfg.FormatOptions.StripComments,
							OptimizeAttributes:         cfg.FormatOptions.OptimizeAttributes,
							SortAttributes:             cfg.FormatOptions.SortAttributes,
						},
					),
				),
			)
		}
	}

	if cfg.AttributeOptions != nil && cfg.AttributeOptions.AddUniqueIDs {
		modifyFns = append(modifyFns,
			transformer.OptimizedAddUniqueID(
				transformer.AddUniqueIDOptions{
					Prefix:          cfg.AttributeOptions.UniqueIDPrefix,
					ReplaceExisting: cfg.AttributeOptions.ReplaceExisting,
					UseRandomSuffix: cfg.AttributeOptions.UseRandomSuffix,
				},
			),
		)
	}

	for _, addToTag := range cfg.AddToTags {
		addBeforeEndTag := false
		if addToTag.AddBeforeEndTag != nil {
			addBeforeEndTag = *addToTag.AddBeforeEndTag
		}
		slog.Debug("processing add_to_tags (optimized)",
			"tag", addToTag.Tag,
			"add_before_end_tag", addToTag.AddBeforeEndTag,
			"final_value", addBeforeEndTag,
			"content", addToTag.Content)
		modifyFns = append(modifyFns,
			transformer.ConvertToOptimizedModifyFn(
				transformer.AddToTagPrepend(
					addToTag.Tag,
					addToTag.Content,
					addBeforeEndTag,
				),
			),
		)
	}

	return &optimizedHTMLTransform{
		tr: transformer.OptimizedModifyHTML(modifyFns...),
	}, nil
}

func (o *optimizedHTMLTransform) Type() string                    { return "optimized_html" }
func (o *optimizedHTMLTransform) Apply(resp *http.Response) error { return o.tr.Modify(resp) }
