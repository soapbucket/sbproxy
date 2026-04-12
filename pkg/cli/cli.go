// Package cli exports the sbproxy CLI entry point for use by external
// binaries (e.g. sbproxy-enterprise). It delegates to the internal CLI
// implementation.
package cli

import (
	"github.com/soapbucket/sbproxy/internal/cli"
)

// Execute starts the sbproxy CLI. This is the entry point for both
// OSS and enterprise binaries. Call this from main() after importing
// module packages via blank imports.
func Execute() {
	cli.Execute()
}
