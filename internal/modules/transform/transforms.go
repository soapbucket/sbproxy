// Package transform registers all built-in response transforms into the pkg/plugin registry.
//
// Each transform is implemented as a self-contained sub-package that calls
// plugin.RegisterTransform in its init() function. The blank imports below
// trigger those init() calls so all transforms are available when this
// package is imported.
package transform

import (
	_ "github.com/soapbucket/sbproxy/internal/modules/transform/css"
	_ "github.com/soapbucket/sbproxy/internal/modules/transform/discard"
	_ "github.com/soapbucket/sbproxy/internal/modules/transform/encoding"
	_ "github.com/soapbucket/sbproxy/internal/modules/transform/formatconvert"
	_ "github.com/soapbucket/sbproxy/internal/modules/transform/html"
	_ "github.com/soapbucket/sbproxy/internal/modules/transform/htmltomarkdown"
	_ "github.com/soapbucket/sbproxy/internal/modules/transform/javascript"
	_ "github.com/soapbucket/sbproxy/internal/modules/transform/json"
	_ "github.com/soapbucket/sbproxy/internal/modules/transform/jsonprojection"
	_ "github.com/soapbucket/sbproxy/internal/modules/transform/jsonschema"
	_ "github.com/soapbucket/sbproxy/internal/modules/transform/luajson"
	_ "github.com/soapbucket/sbproxy/internal/modules/transform/markdown"
	_ "github.com/soapbucket/sbproxy/internal/modules/transform/noop"
	_ "github.com/soapbucket/sbproxy/internal/modules/transform/normalize"
	_ "github.com/soapbucket/sbproxy/internal/modules/transform/optimizehtml"
	_ "github.com/soapbucket/sbproxy/internal/modules/transform/payloadlimit"
	_ "github.com/soapbucket/sbproxy/internal/modules/transform/replacestrings"
	_ "github.com/soapbucket/sbproxy/internal/modules/transform/ssechunking"
	_ "github.com/soapbucket/sbproxy/internal/modules/transform/template"
)
