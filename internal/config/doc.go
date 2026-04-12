// Package config loads, parses, validates, and compiles proxy configuration from YAML.
//
// This is the internal configuration package. It defines the [RawOrigin] struct
// (the parsed but uncompiled origin), the [CompileOrigin] function that builds
// the 18-layer compiled handler chain, and all supporting types for actions,
// authentication schemes, policies, transforms, forward rules, callbacks,
// error pages, message signatures, vault integration, variables, and session
// management.
//
// The JSON struct tags on [RawOrigin] are the canonical field names for sb.yml
// files. The compiler uses the pkg/plugin registry to look up module factories
// by type name and assembles the handler chain inside-out at config load time.
package config
