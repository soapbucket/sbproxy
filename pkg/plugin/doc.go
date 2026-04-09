// Package plugin defines interfaces for extensible proxy components.
//
// Actions, authentication providers, policies, transforms, and middleware
// are all registered through this package's global registry. Third-party
// code can call RegisterAction, RegisterAuth, RegisterPolicy, or
// RegisterTransform to extend the proxy at startup.
package plugin
