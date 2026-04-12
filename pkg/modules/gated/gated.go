// Package gated re-exports OSS action modules that are enterprise-gated.
// These modules are implemented in the OSS codebase but their registration
// is reserved for the enterprise binary. Import this package with a blank
// import to activate them:
//
//	_ "github.com/soapbucket/sbproxy/pkg/modules/gated"
package gated

import (
	_ "github.com/soapbucket/sbproxy/internal/modules/action/a2a"
	_ "github.com/soapbucket/sbproxy/internal/modules/action/graphql"
	_ "github.com/soapbucket/sbproxy/internal/modules/action/storage"
)
