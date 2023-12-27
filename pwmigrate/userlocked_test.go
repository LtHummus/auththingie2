package pwmigrate

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUserLockBasicUsage(t *testing.T) {
	assert.True(t, attemptLockUser("abc"))
	assert.False(t, attemptLockUser("abc"))

	assert.Equal(t, locked, lockCache.Get("abc").Value().lock.Load())

	unlockUser("abc")

	assert.Equal(t, unlocked, lockCache.Get("abc").Value().lock.Load())
}

func TestMultipleUserLocks(t *testing.T) {
	assert.True(t, attemptLockUser("abc"))
	assert.True(t, attemptLockUser("def"))
	assert.False(t, attemptLockUser("abc"))
	assert.True(t, attemptLockUser("ghi"))

	unlockUser("abc")

	assert.True(t, attemptLockUser("abc"))
	unlockUser("def")
	unlockUser("abc")
	unlockUser("ghi")

	assert.Equal(t, unlocked, lockCache.Get("abc").Value().lock.Load())
	assert.Equal(t, unlocked, lockCache.Get("def").Value().lock.Load())
	assert.Equal(t, unlocked, lockCache.Get("ghi").Value().lock.Load())
}
