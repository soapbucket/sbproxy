// Package modules re-exports the OSS module registrations from internal/modules
// so that external binaries (e.g. sbproxy-enterprise) can import them via a
// blank import:
//
//	_ "github.com/soapbucket/sbproxy/pkg/modules"
//
// This triggers all OSS module init() functions, registering actions, auth
// providers, policies, and transforms into the pkg/plugin registry.
package modules

import _ "github.com/soapbucket/sbproxy/internal/modules"
