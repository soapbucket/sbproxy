// Package main provides main functionality for the proxy.
package main

import (
	"fmt"
	"os"

	_ "github.com/soapbucket/sbproxy/internal/modules"
	"github.com/soapbucket/sbproxy/pkg/cli"

	"go.uber.org/automaxprocs/maxprocs"
)

func main() {
	// Automatically set GOMAXPROCS to match Linux container CPU quota
	if _, err := maxprocs.Set(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to set GOMAXPROCS: %v\n", err)
	}

	cli.Execute()
}
