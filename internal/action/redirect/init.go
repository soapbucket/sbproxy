// Package redirect implements the HTTP redirect action for sbproxy.
//
// The redirect action returns 301/302/307/308 redirect responses to clients,
// supporting URL pattern rewriting with capture groups from the original
// request path.
//
// Registration happens via [Register], which wires the redirect action
// loader into the config registry so that origins with action type
// "redirect" are handled by this package.
package redirect

import (
	"github.com/soapbucket/sbproxy/internal/config"
)

// Register adds the redirect action loader to the given Registry.
// After registration, any origin config with action type "redirect"
// will be deserialized and validated by the redirect loader during
// config load.
func Register(r *config.Registry) {
	r.RegisterAction(config.TypeRedirect, config.LoadRedirectConfig)
}
