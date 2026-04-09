// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"encoding/json"
	"log/slog"

	"github.com/soapbucket/sbproxy/internal/transformer"
)

func init() {
	transformLoaderFns[TransformHTML] = NewHTMLTransform
}

// HTMLTransformConfig holds configuration for html transformer.
type HTMLTransformConfig struct {
	HTMLTransform
}

// NewHTMLTransform creates and initializes a new HTMLTransform.
func NewHTMLTransform(data []byte) (TransformConfig, error) {
	cfg := &HTMLTransformConfig{}
	err := json.Unmarshal(data, cfg)
	if err != nil {
		return nil, err
	}

	var modifyFns []transformer.ModifyFn

	if cfg.FormatOptions != nil {
		if cfg.FormatOptions.StripNewlines || cfg.FormatOptions.StripSpace {
			modifyFns = append(modifyFns, transformer.StripSpace(transformer.StripSpaceOptions{
				StripExtraSpaces: cfg.FormatOptions.StripSpace,
				StripNewlines:    cfg.FormatOptions.StripNewlines,
			}))
		}
		if cfg.FormatOptions.RemoveBooleanAttributes || cfg.FormatOptions.RemoveQuotesFromAttributes ||
			cfg.FormatOptions.RemoveTrailingSlashes || cfg.FormatOptions.StripComments || cfg.FormatOptions.OptimizeAttributes || cfg.FormatOptions.SortAttributes {
			modifyFns = append(modifyFns, transformer.OptimizeHTML(transformer.OptimizeHTMLOptions{
				RemoveBooleanAttributes:    cfg.FormatOptions.RemoveBooleanAttributes,
				RemoveQuotesFromAttributes: cfg.FormatOptions.RemoveQuotesFromAttributes,
				RemoveTrailingSlashes:      cfg.FormatOptions.RemoveTrailingSlashes,
				StripComments:              cfg.FormatOptions.StripComments,
				OptimizeAttributes:         cfg.FormatOptions.OptimizeAttributes,
				SortAttributes:             cfg.FormatOptions.SortAttributes,
				LowercaseTags:              cfg.FormatOptions.LowercaseTags,
				LowercaseAttributes:        cfg.FormatOptions.LowercaseAttributes,
			}))
		}
	}

	if cfg.AttributeOptions != nil && cfg.AttributeOptions.AddUniqueIDs {
		modifyFns = append(modifyFns,
			transformer.AddUniqueID(
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
		slog.Debug("processing add_to_tags",
			"tag", addToTag.Tag,
			"add_before_end_tag", addToTag.AddBeforeEndTag,
			"final_value", addBeforeEndTag,
			"content", addToTag.Content)
		modifyFns = append(modifyFns,
			transformer.AddToTagPrepend(
				addToTag.Tag,
				addToTag.Content,
				addBeforeEndTag,
			),
		)
	}

	cfg.tr = transformer.ModifyHTML(modifyFns...)

	// apply default content types if not set
	if cfg.ContentTypes == nil {
		cfg.ContentTypes = HTMLContentTypes
	}

	return cfg, nil
}
