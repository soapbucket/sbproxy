// Package uaparser parses User-Agent strings to extract browser, OS, and device information.
package uaparser

import "time"

const (
	// DriverNoop is a constant for driver noop.
	DriverNoop     = "noop"
	// DriverUAParser is a constant for driver ua parser.
	DriverUAParser = "uaparser"

	// ParamRegexFile is a constant for param regex file.
	ParamRegexFile = "path"

	// DefaultCacheDuration is the default value for cache duration.
	DefaultCacheDuration = 5 * time.Minute
)
