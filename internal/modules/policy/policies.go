// Package policy imports all built-in policy modules so they register
// themselves into the pkg/plugin registry via their init() functions.
package policy

import (
	_ "github.com/soapbucket/sbproxy/internal/modules/policy/assertion"
	_ "github.com/soapbucket/sbproxy/internal/modules/policy/csrf"
	_ "github.com/soapbucket/sbproxy/internal/modules/policy/ddos"
	_ "github.com/soapbucket/sbproxy/internal/modules/policy/expression"
	_ "github.com/soapbucket/sbproxy/internal/modules/policy/ipfilter"
	_ "github.com/soapbucket/sbproxy/internal/modules/policy/ratelimit"
	_ "github.com/soapbucket/sbproxy/internal/modules/policy/requestlimit"
	_ "github.com/soapbucket/sbproxy/internal/modules/policy/secheaders"
	_ "github.com/soapbucket/sbproxy/internal/modules/policy/sri"
	_ "github.com/soapbucket/sbproxy/internal/modules/policy/waf"
)
