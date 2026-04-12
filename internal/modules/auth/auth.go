// Package auth registers all built-in authentication providers into the pkg/plugin registry.
//
// Each auth type is implemented as a self-contained sub-package that calls
// plugin.RegisterAuth in its init() function. The blank imports below
// trigger those init() calls so all auth types are available when this
// package is imported.
package auth

import (
	_ "github.com/soapbucket/sbproxy/internal/modules/auth/apikey"
	_ "github.com/soapbucket/sbproxy/internal/modules/auth/basicauth"
	_ "github.com/soapbucket/sbproxy/internal/modules/auth/bearer"
	_ "github.com/soapbucket/sbproxy/internal/modules/auth/digest"
	_ "github.com/soapbucket/sbproxy/internal/modules/auth/forwardauth"
	_ "github.com/soapbucket/sbproxy/internal/modules/auth/grpcauth"
	_ "github.com/soapbucket/sbproxy/internal/modules/auth/jwt"
	_ "github.com/soapbucket/sbproxy/internal/modules/auth/noop"
)
