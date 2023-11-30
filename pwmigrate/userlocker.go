package pwmigrate

import (
	"sync/atomic"
	"time"

	"github.com/jellydator/ttlcache/v3"
)

var (
	lockCacheLoader = ttlcache.LoaderFunc[string, *lock](
		func(c *ttlcache.Cache[string, *lock], key string) *ttlcache.Item[string, *lock] {
			item := c.Set(key, &lock{lock: &atomic.Uint32{}}, ttlcache.DefaultTTL)
			return item
		},
	)
	lockCache = ttlcache.New[string, *lock](
		ttlcache.WithTTL[string, *lock](5*time.Minute),
		ttlcache.WithLoader[string, *lock](lockCacheLoader),
	)
)

func attemptLockUser(id string) bool {
	item := lockCache.Get(id)

	return item.Value().AttemptUnlock()
}

func unlockUser(id string) {
	item := lockCache.Get(id)

	item.Value().Lock()
}
