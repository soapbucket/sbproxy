// Package policy implements DLP, audit, and network security for the AI gateway.
package policy

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

// DLPAction defines what happens when a DLP detector triggers.
type DLPAction string

const (
	// DLPActionBlock rejects the request entirely.
	DLPActionBlock DLPAction = "block"
	// DLPActionRedact masks matched content and allows the request.
	DLPActionRedact DLPAction = "redact"
	// DLPActionLog logs the detection without blocking or modifying.
	DLPActionLog DLPAction = "log"
)

// DLPDetectorRef references a guardrail detector type with its configuration.
type DLPDetectorRef struct {
	Type   string         `json:"type"`
	Config map[string]any `json:"config,omitempty"`
}

// DLPProfile groups detectors into a named, reusable profile.
type DLPProfile struct {
	ID               string           `json:"id"`
	Name             string           `json:"name"`
	Detectors        []DLPDetectorRef `json:"detectors"`
	Action           DLPAction        `json:"action"`
	BufferedResponse bool             `json:"buffered_response,omitempty"`
}

// DLPDetection represents a single detection within content.
type DLPDetection struct {
	Type     string `json:"type"`
	Matched  string `json:"matched"`
	Location int    `json:"location"` // byte offset in content
}

// DLPResult holds the outcome of a DLP evaluation.
type DLPResult struct {
	Triggered       bool           `json:"triggered"`
	Action          DLPAction      `json:"action"`
	Detections      []DLPDetection `json:"detections,omitempty"`
	RedactedContent string         `json:"redacted_content,omitempty"`
	Latency         time.Duration  `json:"latency"`
}

// DLPExecutor runs guardrail detector checks on content for DLP profiles.
// It wraps registered GuardrailDetector instances to provide a detector-oriented API.
type DLPExecutor struct {
	detectors map[string]GuardrailDetector
	mu        sync.RWMutex
}

// NewDLPExecutor creates a new DLP executor.
func NewDLPExecutor() *DLPExecutor {
	return &DLPExecutor{
		detectors: make(map[string]GuardrailDetector),
	}
}

// RegisterDetector registers a guardrail detector for a given detector type.
func (de *DLPExecutor) RegisterDetector(detectorType string, detector GuardrailDetector) {
	de.mu.Lock()
	defer de.mu.Unlock()
	de.detectors[detectorType] = detector
}

// RunCheck executes a detector check for the given type against content.
func (de *DLPExecutor) RunCheck(ctx context.Context, detectorType string, content string, config map[string]any) (*GuardrailResult, error) {
	de.mu.RLock()
	detector, ok := de.detectors[detectorType]
	de.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("unknown detector type: %s", detectorType)
	}

	gc := &GuardrailConfig{
		ID:     detectorType,
		Name:   detectorType,
		Type:   detectorType,
		Action: GuardrailActionBlock,
		Config: config,
	}

	return detector.Detect(ctx, gc, content)
}

// DLPEngine runs DLP profiles against content using registered detectors.
type DLPEngine struct {
	profiles map[string]*DLPProfile
	executor *DLPExecutor
	mu       sync.RWMutex
}

// NewDLPEngine creates a DLP engine backed by the given executor's detectors.
func NewDLPEngine(executor *DLPExecutor) *DLPEngine {
	return &DLPEngine{
		profiles: make(map[string]*DLPProfile),
		executor: executor,
	}
}

// AddProfile registers a DLP profile.
func (d *DLPEngine) AddProfile(profile *DLPProfile) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.profiles[profile.ID] = profile
}

// GetProfile returns a profile by ID.
func (d *DLPEngine) GetProfile(id string) (*DLPProfile, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	p, ok := d.profiles[id]
	return p, ok
}

// EvaluateInput runs all detectors in the specified profiles against input content.
func (d *DLPEngine) EvaluateInput(ctx context.Context, profileIDs []string, content string) (*DLPResult, error) {
	return d.evaluate(ctx, profileIDs, content)
}

// EvaluateOutput runs all detectors in the specified profiles against output content.
// This is intended for buffered response mode where the full response is available.
func (d *DLPEngine) EvaluateOutput(ctx context.Context, profileIDs []string, content string) (*DLPResult, error) {
	return d.evaluate(ctx, profileIDs, content)
}

func (d *DLPEngine) evaluate(ctx context.Context, profileIDs []string, content string) (*DLPResult, error) {
	start := time.Now()

	d.mu.RLock()
	var profiles []*DLPProfile
	for _, id := range profileIDs {
		if p, ok := d.profiles[id]; ok {
			profiles = append(profiles, p)
		}
	}
	d.mu.RUnlock()

	if len(profiles) == 0 {
		return &DLPResult{Latency: time.Since(start)}, nil
	}

	result := &DLPResult{}
	highestAction := DLPActionLog // escalate: log < redact < block

	for _, profile := range profiles {
		for _, ref := range profile.Detectors {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
			}

			gr, err := d.executor.RunCheck(ctx, ref.Type, content, ref.Config)
			if err != nil {
				return nil, fmt.Errorf("dlp detector %q in profile %q: %w", ref.Type, profile.ID, err)
			}

			if gr.Triggered {
				result.Triggered = true

				detection := DLPDetection{
					Type:    ref.Type,
					Matched: gr.Details,
				}
				// Find location of detected content.
				if gr.Details != "" {
					parts := strings.SplitN(gr.Details, ": ", 2)
					if len(parts) == 2 {
						firstMatch := strings.SplitN(parts[1], ", ", 2)[0]
						idx := strings.Index(content, firstMatch)
						if idx >= 0 {
							detection.Location = idx
						}
					}
				}
				result.Detections = append(result.Detections, detection)

				if dlpActionSeverity(profile.Action) > dlpActionSeverity(highestAction) {
					highestAction = profile.Action
				}
			}
		}
	}

	if result.Triggered {
		result.Action = highestAction

		if highestAction == DLPActionRedact {
			result.RedactedContent = redactContent(content, result.Detections)
		}
	}

	result.Latency = time.Since(start)
	return result, nil
}

// dlpActionSeverity returns a numeric severity for DLP actions (higher = more severe).
func dlpActionSeverity(a DLPAction) int {
	switch a {
	case DLPActionLog:
		return 0
	case DLPActionRedact:
		return 1
	case DLPActionBlock:
		return 2
	default:
		return 0
	}
}

// redactContent masks detected content with asterisks.
func redactContent(content string, detections []DLPDetection) string {
	redacted := content
	for _, det := range detections {
		if det.Matched == "" {
			continue
		}
		// Extract the actual matched string from the details.
		parts := strings.SplitN(det.Matched, ": ", 2)
		if len(parts) != 2 {
			continue
		}
		matches := strings.Split(parts[1], ", ")
		for _, m := range matches {
			mask := strings.Repeat("*", len(m))
			redacted = strings.ReplaceAll(redacted, m, mask)
		}
	}
	return redacted
}
