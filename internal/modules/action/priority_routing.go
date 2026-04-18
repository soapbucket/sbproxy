// Package action contains action-level traffic management handlers.
package action

import "net/http"

// PriorityConfig configures priority-based routing.
type PriorityConfig struct {
	Header  string            `json:"header,omitempty" yaml:"header"`   // header to read priority from
	Default string            `json:"default,omitempty" yaml:"default"` // default priority level
	Routes  map[string]string `json:"routes" yaml:"routes"`            // priority level -> upstream URL
}

// SelectByPriority returns the upstream URL based on request priority.
// It reads the priority value from the configured header (or uses the default)
// and maps it to an upstream URL via the Routes map.
// If no matching route is found, an empty string is returned.
func SelectByPriority(r *http.Request, cfg PriorityConfig) string {
	priority := cfg.Default

	if cfg.Header != "" {
		if hv := r.Header.Get(cfg.Header); hv != "" {
			priority = hv
		}
	}

	if priority == "" {
		return ""
	}

	if upstream, ok := cfg.Routes[priority]; ok {
		return upstream
	}

	return ""
}
