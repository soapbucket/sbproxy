// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"encoding/json"
	"log/slog"

	"github.com/soapbucket/sbproxy/internal/transformer"
)

func init() {
	transformLoaderFns[TransformOptimizedHTML] = NewOptimizedHTMLTransform
}

// OptimizedHTMLTransformConfig holds configuration for optimized html transformer.
type OptimizedHTMLTransformConfig struct {
	OptimizedHTMLTransform
}

// NewOptimizedHTMLTransform creates and initializes a new OptimizedHTMLTransform.
func NewOptimizedHTMLTransform(data []byte) (TransformConfig, error) {
	cfg := &OptimizedHTMLTransformConfig{}
	err := json.Unmarshal(data, cfg)
	if err != nil {
		return nil, err
	}

	var modifyFns []transformer.OptimizedModifyFn

	// remove spaces
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

		// optimize HTML
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

	// Handle AddToTags configurations
	for _, addToTag := range cfg.AddToTags {
		// add_before_end_tag: nil/omitted = false (insert after opening tag)
		// add_before_end_tag: false = insert after opening tag
		// add_before_end_tag: true = insert before closing tag
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

	// apply default content types if not set
	if cfg.ContentTypes == nil {
		cfg.ContentTypes = HTMLContentTypes
	}

	cfg.tr = transformer.OptimizedModifyHTML(modifyFns...)

	return cfg, nil
}
