package configcompat

// Blank imports ensure that modules register themselves into the
// pkg/plugin registry before any test in this package runs.
import (
	// Transform modules
	_ "github.com/soapbucket/sbproxy/internal/modules/transform/encoding"
	_ "github.com/soapbucket/sbproxy/internal/modules/transform/noop"

	// Auth modules
	_ "github.com/soapbucket/sbproxy/internal/modules/auth/apikey"

	// Policy modules
	_ "github.com/soapbucket/sbproxy/internal/modules/policy/ipfilter"
	_ "github.com/soapbucket/sbproxy/internal/modules/policy/ratelimit"

	// Action modules
	_ "github.com/soapbucket/sbproxy/internal/modules/action/aiproxy"
	_ "github.com/soapbucket/sbproxy/internal/modules/action/proxy"
)
