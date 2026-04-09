// Package common provides shared HTTP utilities, helper functions, and type definitions used across packages.
package util

// Map is a map type for map.
type Map map[string]string

// MergeMap performs the merge map operation.
func MergeMap(src1, src2 Map) Map {
	dst := make(Map)
	for key, value := range src1 {
		dst[key] = value
	}
	for key, value := range src2 {
		dst[key] = value
	}
	return dst
}
