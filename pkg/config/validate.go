package config

import "fmt"

// Validate checks that the origin has the minimum required fields to be usable
// by the proxy engine. It verifies that a hostname is set (used for request routing)
// and that an action configuration is present (every origin must do something).
//
// Call Validate after unmarshaling an origin from any source (YAML file, API response,
// database row) and before passing it to the engine for pipeline construction.
// Plugin-specific validation (e.g., checking that a proxy action has a valid URL)
// happens later when each plugin unmarshals its own json.RawMessage.
func (o *Origin) Validate() error {
	if o.Hostname == "" {
		return fmt.Errorf("origin hostname is required")
	}
	if len(o.Action) == 0 {
		return fmt.Errorf("origin %s: action is required", o.Hostname)
	}
	return nil
}
