// imports.go triggers module registration via blank imports of all built-in modules.
package modules

// Blank imports trigger the init() functions in each module, registering them
// into the pkg/plugin registry. Add new modules here as they are migrated.
import (
	_ "github.com/soapbucket/sbproxy/internal/modules/action"
	_ "github.com/soapbucket/sbproxy/internal/modules/action/aiproxy"
	_ "github.com/soapbucket/sbproxy/internal/modules/action/beacon"
	_ "github.com/soapbucket/sbproxy/internal/modules/action/echo"
	_ "github.com/soapbucket/sbproxy/internal/modules/action/loadbalancer"
	_ "github.com/soapbucket/sbproxy/internal/modules/action/mcp"
	_ "github.com/soapbucket/sbproxy/internal/modules/action/mock"
	_ "github.com/soapbucket/sbproxy/internal/modules/action/noop"
	_ "github.com/soapbucket/sbproxy/internal/modules/action/redirect"
	_ "github.com/soapbucket/sbproxy/internal/modules/action/static"
	_ "github.com/soapbucket/sbproxy/internal/modules/action/websocket"
	_ "github.com/soapbucket/sbproxy/internal/modules/auth"
	_ "github.com/soapbucket/sbproxy/internal/modules/policy"
	_ "github.com/soapbucket/sbproxy/internal/modules/transform"
)
