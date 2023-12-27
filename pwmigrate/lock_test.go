package pwmigrate

import (
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBasicUsage(t *testing.T) {
	l := &lock{
		lock: &atomic.Uint32{},
	}

	assert.Equal(t, unlocked, l.lock.Load())

	assert.True(t, l.AttemptLock())

	assert.Equal(t, locked, l.lock.Load())

	l.Unlock()

	assert.Equal(t, unlocked, l.lock.Load())
}

func TestAttemptLockWhenLockHeld(t *testing.T) {
	l := &lock{
		lock: &atomic.Uint32{},
	}

	assert.True(t, l.AttemptLock())
	assert.Equal(t, locked, l.lock.Load())

	assert.False(t, l.AttemptLock())
	assert.Equal(t, locked, l.lock.Load())

	l.Unlock()

	assert.Equal(t, unlocked, l.lock.Load())

	assert.True(t, l.AttemptLock())
	assert.Equal(t, locked, l.lock.Load())
}
