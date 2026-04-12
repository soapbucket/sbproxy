package config

// Blank imports ensure that migrated modules register themselves into the
// pkg/plugin registry before any test in this package runs. Add a new import
// here each time a module is migrated to internal/modules.
import (
	// Transform modules
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

	// Auth modules
	_ "github.com/soapbucket/sbproxy/internal/modules/auth/apikey"
	_ "github.com/soapbucket/sbproxy/internal/modules/auth/basicauth"
	_ "github.com/soapbucket/sbproxy/internal/modules/auth/bearer"
	_ "github.com/soapbucket/sbproxy/internal/modules/auth/digest"
	_ "github.com/soapbucket/sbproxy/internal/modules/auth/forwardauth"
	_ "github.com/soapbucket/sbproxy/internal/modules/auth/grpcauth"
	_ "github.com/soapbucket/sbproxy/internal/modules/auth/jwt"
	_ "github.com/soapbucket/sbproxy/internal/modules/auth/noop"

	// Policy modules
	_ "github.com/soapbucket/sbproxy/internal/modules/policy/csrf"
	_ "github.com/soapbucket/sbproxy/internal/modules/policy/ddos"
	_ "github.com/soapbucket/sbproxy/internal/modules/policy/expression"
	_ "github.com/soapbucket/sbproxy/internal/modules/policy/ipfilter"
	_ "github.com/soapbucket/sbproxy/internal/modules/policy/ratelimit"
	_ "github.com/soapbucket/sbproxy/internal/modules/policy/requestlimit"
	_ "github.com/soapbucket/sbproxy/internal/modules/policy/secheaders"
	_ "github.com/soapbucket/sbproxy/internal/modules/policy/sri"
	_ "github.com/soapbucket/sbproxy/internal/modules/policy/waf"

	// Action modules
	_ "github.com/soapbucket/sbproxy/internal/modules/action/a2a"
	_ "github.com/soapbucket/sbproxy/internal/modules/action/aiproxy"
	_ "github.com/soapbucket/sbproxy/internal/modules/action/beacon"
	_ "github.com/soapbucket/sbproxy/internal/modules/action/echo"
	_ "github.com/soapbucket/sbproxy/internal/modules/action/graphql"
	_ "github.com/soapbucket/sbproxy/internal/modules/action/grpc"
	_ "github.com/soapbucket/sbproxy/internal/modules/action/loadbalancer"
	_ "github.com/soapbucket/sbproxy/internal/modules/action/mcp"
	_ "github.com/soapbucket/sbproxy/internal/modules/action/mock"
	_ "github.com/soapbucket/sbproxy/internal/modules/action/noop"
	_ "github.com/soapbucket/sbproxy/internal/modules/action/proxy"
	_ "github.com/soapbucket/sbproxy/internal/modules/action/redirect"
	_ "github.com/soapbucket/sbproxy/internal/modules/action/static"
	_ "github.com/soapbucket/sbproxy/internal/modules/action/storage"
	_ "github.com/soapbucket/sbproxy/internal/modules/action/websocket"
)
