package configloader

import (
	"time"

	"github.com/soapbucket/sbproxy/internal/cache/object"
)

// ResetCacheForTest resets the config cache and failsafe snapshots.
// This is exported for use by E2E tests in test/e2e/.
func ResetCacheForTest() {
	cache, _ = objectcache.NewObjectCache(10*time.Minute, 1*time.Minute, 1000, 100*1024*1024)
	failsafeSnapshots.resetForTests()
}
