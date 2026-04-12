// Package action imports all built-in action modules so their init() functions
// register them into the pkg/plugin registry. The config loader discovers
// actions from the registry at runtime.
//
// All action types are now self-contained leaf packages that register themselves
// via init(). This file exists only to trigger their imports.
package action

import (
	// Leaf packages that self-register via init().
	_ "github.com/soapbucket/sbproxy/internal/modules/action/a2a"
	_ "github.com/soapbucket/sbproxy/internal/modules/action/aiproxy"
	_ "github.com/soapbucket/sbproxy/internal/modules/action/graphql"
	_ "github.com/soapbucket/sbproxy/internal/modules/action/grpc"
	_ "github.com/soapbucket/sbproxy/internal/modules/action/loadbalancer"
	_ "github.com/soapbucket/sbproxy/internal/modules/action/mcp"
	_ "github.com/soapbucket/sbproxy/internal/modules/action/proxy"
	_ "github.com/soapbucket/sbproxy/internal/modules/action/storage"
	_ "github.com/soapbucket/sbproxy/internal/modules/action/websocket"
)
