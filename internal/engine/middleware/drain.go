// Package middleware contains HTTP middleware for authentication, rate limiting, logging, and request processing.
package middleware

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/soapbucket/sbproxy/internal/loader/configloader"
)

func handleDrainWorkspace(w http.ResponseWriter, r *http.Request) {
	workspaceID := r.URL.Query().Get("workspace_id")
	if workspaceID == "" {
		http.Error(w, `{"error":"workspace_id is required"}`, http.StatusBadRequest)
		return
	}

	configloader.DrainWorkspace(workspaceID)
	slog.Info("workspace drain requested via API", "workspace_id", workspaceID)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":       "draining",
		"workspace_id": workspaceID,
	})
}

func handleUndrainWorkspace(w http.ResponseWriter, r *http.Request) {
	workspaceID := r.URL.Query().Get("workspace_id")
	if workspaceID == "" {
		http.Error(w, `{"error":"workspace_id is required"}`, http.StatusBadRequest)
		return
	}

	configloader.UndrainWorkspace(workspaceID)
	slog.Info("workspace undrain requested via API", "workspace_id", workspaceID)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":       "active",
		"workspace_id": workspaceID,
	})
}

func handleDrainStatus(w http.ResponseWriter, r *http.Request) {
	workspaceID := r.URL.Query().Get("workspace_id")
	if workspaceID == "" {
		http.Error(w, `{"error":"workspace_id is required"}`, http.StatusBadRequest)
		return
	}

	draining := configloader.IsWorkspaceDraining(workspaceID)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	status := "active"
	if draining {
		status = "draining"
	}
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"workspace_id": workspaceID,
		"status":       status,
		"draining":     draining,
	})
}
