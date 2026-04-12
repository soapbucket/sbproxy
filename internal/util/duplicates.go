// Package common provides shared HTTP utilities, helper functions, and type definitions used across packages.
package util

import "strings"

// RemoveDuplicates returns a new slice removing any duplicate element from the initial one
func RemoveDuplicates(obj []string, trim bool) []string {
	if len(obj) == 0 {
		return obj
	}
	seen := make(map[string]bool)
	validIdx := 0
	for _, item := range obj {
		if trim {
			item = strings.TrimSpace(item)
		}
		if !seen[item] {
			seen[item] = true
			obj[validIdx] = item
			validIdx++
		}
	}
	return obj[:validIdx]
}
