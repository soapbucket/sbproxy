// test_helpers.go provides cache reset and access helpers for E2E and integration tests.
package configloader

import (
	"time"

	objectcache "github.com/soapbucket/sbproxy/internal/cache/object"
)

// ResetCacheForTest resets the config cache and failsafe snapshots on the default loader.
// This is exported for use by E2E tests in test/e2e/.
func ResetCacheForTest() {
	defaultLoader.ResetForTest()
}

// ResetForTest resets the Loader's cache and failsafe snapshots.
// Intended for use in tests to provide a clean state.
func (l *Loader) ResetForTest() {
	l.cache, _ = objectcache.NewObjectCache(10*time.Minute, 1*time.Minute, 1000, 100*1024*1024)
	l.failsafeSnapshots.resetForTests()
}

// Cache returns the Loader's object cache. Exposed for internal test access.
func (l *Loader) Cache() *objectcache.ObjectCache {
	return l.cache
}

// FailsafeSnapshots returns the Loader's failsafe snapshot store. Exposed for internal test access.
func (l *Loader) FailsafeSnapshots() *failsafeSnapshotStore {
	return l.failsafeSnapshots
}
