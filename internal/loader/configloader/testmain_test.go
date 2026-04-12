package configloader

import (
	"os"
	"testing"

	"github.com/soapbucket/sbproxy/internal/config"

	// Register all action modules for E2E tests.
	_ "github.com/soapbucket/sbproxy/internal/modules/action/aiproxy"
	_ "github.com/soapbucket/sbproxy/internal/modules/action/echo"
	_ "github.com/soapbucket/sbproxy/internal/modules/action/graphql"
	_ "github.com/soapbucket/sbproxy/internal/modules/action/loadbalancer"
	_ "github.com/soapbucket/sbproxy/internal/modules/action/mock"
	_ "github.com/soapbucket/sbproxy/internal/modules/action/noop"
	_ "github.com/soapbucket/sbproxy/internal/modules/action/proxy"
	_ "github.com/soapbucket/sbproxy/internal/modules/action/redirect"
	_ "github.com/soapbucket/sbproxy/internal/modules/action/static"

	// Register additional action modules for E2E tests.
	_ "github.com/soapbucket/sbproxy/internal/modules/action/grpc"
	_ "github.com/soapbucket/sbproxy/internal/modules/action/mcp"

	// Register all auth modules for E2E tests.
	_ "github.com/soapbucket/sbproxy/internal/modules/auth"

	// Register all policy modules for E2E tests.
	_ "github.com/soapbucket/sbproxy/internal/modules/policy"

	// Register all transform modules for E2E tests.
	_ "github.com/soapbucket/sbproxy/internal/modules/transform"
)

func TestMain(m *testing.M) {
	// Ensure all built-in transforms and actions are registered in the pkg/plugin registry
	// (done by the blank imports above) so that config loading can resolve them via
	// the plugin fallback path in Registry.LoadTransform / Registry.LoadAction.
	config.SetRegistry(config.DefaultRegistry())
	os.Exit(m.Run())
}
