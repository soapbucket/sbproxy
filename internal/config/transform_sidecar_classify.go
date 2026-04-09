// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/soapbucket/sbproxy/internal/request/classifier"
	"github.com/soapbucket/sbproxy/internal/transformer"
)

func init() {
	transformLoaderFns[TransformSidecarClassify] = NewSidecarClassifyTransform
}

// SidecarClassifyTransformConfig delegates classification to the classifier sidecar.
type SidecarClassifyTransformConfig struct {
	SidecarClassifyTransform
	configID string
}

// SidecarClassifyTransform holds the user-facing configuration for sidecar-based classification.
type SidecarClassifyTransform struct {
	BaseTransform
	TopK            int                    `json:"top_k,omitempty"`
	HeaderName      string                 `json:"header_name,omitempty"`
	ScoreHeader     string                 `json:"score_header,omitempty"`
	AllLabelsHeader string                 `json:"all_labels_header,omitempty"`
	Labels          []SidecarClassifyLabel `json:"labels,omitempty"`
	Classification  *SidecarClassification `json:"classification,omitempty"`
}

// SidecarClassifyLabel defines a label with patterns for sidecar classification.
type SidecarClassifyLabel struct {
	Name     string   `json:"name"`
	Weight   float64  `json:"weight,omitempty"`
	Patterns []string `json:"patterns"`
}

// SidecarClassification holds classification settings for the sidecar.
type SidecarClassification struct {
	ConfidenceThreshold float64 `json:"confidence_threshold,omitempty"`
	DefaultLabel        string  `json:"default_label,omitempty"`
}

// NewSidecarClassifyTransform creates a new sidecar classification transform from JSON config.
func NewSidecarClassifyTransform(data []byte) (TransformConfig, error) {
	cfg := &SidecarClassifyTransformConfig{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("sidecar_classify: %w", err)
	}
	if cfg.HeaderName == "" {
		cfg.HeaderName = "X-Content-Class"
	}
	if cfg.TopK <= 0 {
		cfg.TopK = 1
	}
	cfg.tr = transformer.Func(cfg.classify)
	return cfg, nil
}

// Init registers labels with the classifier sidecar via TenantSync.
func (c *SidecarClassifyTransformConfig) Init(cfg *Config) error {
	c.configID = cfg.ID
	if err := c.BaseTransform.Init(cfg); err != nil {
		return err
	}
	// Register labels as part of the tenant
	if ts := classifier.GlobalSync(); ts != nil && len(c.Labels) > 0 {
		labels := make([]classifier.SidecarLabelConfig, len(c.Labels))
		for i, l := range c.Labels {
			labels[i] = classifier.SidecarLabelConfig{
				Name:     l.Name,
				Patterns: l.Patterns,
				Weight:   l.Weight,
			}
		}
		osc := &classifier.OriginSidecarConfig{Labels: labels}
		if c.Classification != nil {
			osc.Classification = &classifier.SidecarClassifyConfig{
				ConfidenceThreshold: c.Classification.ConfidenceThreshold,
				DefaultLabel:        c.Classification.DefaultLabel,
			}
		}
		_ = ts.RegisterOrigin(c.configID, osc)
	}
	return nil
}

func (c *SidecarClassifyTransformConfig) classify(resp *http.Response) error {
	mc := classifier.Global()
	if mc == nil || !mc.IsAvailable() {
		return nil // fail open
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	resp.Body.Close()

	text := extractUserMessage(body)
	if text == "" {
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return nil
	}

	result, cerr := mc.ClassifyForTenant(text, c.TopK, c.configID)
	if cerr != nil {
		slog.Debug("sidecar_classify: classification error", "error", cerr)
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return nil // fail open
	}

	if len(result.Labels) > 0 {
		resp.Request.Header.Set(c.HeaderName, result.Labels[0].Label)
		if c.ScoreHeader != "" {
			resp.Request.Header.Set(c.ScoreHeader, strconv.FormatFloat(result.Labels[0].Score, 'f', 4, 64))
		}
	}

	if c.AllLabelsHeader != "" && len(result.Labels) > 0 {
		labelsJSON, _ := json.Marshal(result.Labels)
		resp.Request.Header.Set(c.AllLabelsHeader, string(labelsJSON))
	}

	resp.Body = io.NopCloser(bytes.NewReader(body))
	return nil
}
