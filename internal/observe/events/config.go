// Package events implements a publish-subscribe event bus for system observability and inter-component communication.
package events

// ConfigLifecycleEvent describes config activation, failure, and failsafe events.
type ConfigLifecycleEvent struct {
	EventBase
	Stage             string `json:"stage,omitempty"`
	Reason            string `json:"reason,omitempty"`
	Detail            string `json:"detail,omitempty"`
	Revision          string `json:"revision,omitempty"`
	ActiveRevision    string `json:"active_revision,omitempty"`
	CandidateRevision string `json:"candidate_revision,omitempty"`
	FailsafeMode      string `json:"failsafe_mode,omitempty"`
	SourceType        string `json:"source_type,omitempty"`
	SourceRef         string `json:"source_ref,omitempty"`
}
