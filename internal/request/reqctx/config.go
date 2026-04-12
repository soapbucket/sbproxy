// Package common provides shared HTTP utilities, helper functions, and type definitions used across packages.
package reqctx

import (
	"path/filepath"
)

// GetConfigPath returns the config path.
func GetConfigPath(name, configDir string) string {
	if !IsFileInputValid(name) {
		return ""
	}
	if name != "" && !filepath.IsAbs(name) {
		return filepath.Join(configDir, name)
	}
	return name
}

// IsFileInputValid reports whether is file input valid.
func IsFileInputValid(fileInput string) bool {
	cleanInput := filepath.Clean(fileInput)
	if cleanInput == "." || cleanInput == ".." {
		return false
	}
	return true
}

// CleanDirInput cleans and validates directory input
func CleanDirInput(dirInput string) string {
	if dirInput == "" {
		return "."
	}
	cleanInput := filepath.Clean(dirInput)
	if cleanInput == "." || cleanInput == ".." {
		return "."
	}
	return cleanInput
}
