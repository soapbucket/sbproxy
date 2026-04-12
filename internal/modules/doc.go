// Package modules contains self-contained proxy modules that register
// themselves into the pkg/plugin registry via init().
//
// Each module owns its config struct, implements the appropriate pkg/plugin
// interface (ActionHandler, AuthProvider, PolicyEnforcer, TransformHandler,
// or RequestEnricher), and has no dependencies on internal/config types.
//
// Sub-packages:
//   - action: proxy, redirect, static, echo, loadbalancer, aiproxy, mcp, a2a, websocket, grpc, graphql, mock, beacon, noop, storage
//   - auth: apikey, basicauth, bearer, jwt, forwardauth, digest, grpcauth, noop
//   - policy: ratelimit, ipfilter, expression (CEL), waf, ddos, csrf, secheaders, requestlimit, assertion, sri
//   - transform: json, jsonprojection, jsonschema, html, markdown, css, template, luajson, encoding, and more
//
// The binary controls which modules are included via blank imports
// in internal/modules/imports.go.
package modules
