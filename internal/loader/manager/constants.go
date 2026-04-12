// Package manager defines the Manager interface for coordinating proxy lifecycle and configuration reloads.
package manager

type contextKey string

const (
	// ManagerKey is a constant for manager key.
	ManagerKey contextKey = "manager"
)
