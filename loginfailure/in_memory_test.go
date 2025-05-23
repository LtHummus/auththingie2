package loginfailure

import (
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestInMemoryCounter_RecordFailure(t *testing.T) {
	t.Run("happy case", func(t *testing.T) {
		c := NewInMemoryCounter(15*time.Minute, 5, 15*time.Minute)

		c.RecordFailure("test")

		assert.Len(t, c.currentFailures["test"], 1)

		c.RecordFailure("test")
		c.RecordFailure("test")
		c.RecordFailure("test")

		assert.Len(t, c.currentFailures["test"], 4)

		c.RecordFailure("foo")
		c.RecordFailure("foo")

		assert.Len(t, c.currentFailures["foo"], 2)
		assert.Empty(t, c.currentFailures["baz"])
	})

	t.Run("expire old failures", func(t *testing.T) {
		synctest.Run(func() {
			// synctest and the background thread don't get along, so build this manually for now
			c := &InMemoryCounter{
				lock:                &sync.Mutex{},
				lockDuration:        30 * time.Minute,
				failuresBeforeLock:  5,
				failureLookbackTime: 15 * time.Minute,
				lockedAccounts:      make(map[string]time.Time),
				currentFailures:     make(map[string][]time.Time),
			}

			c.RecordFailure("test")
			assert.Len(t, c.currentFailures["test"], 1)

			c.RecordFailure("test")
			assert.Len(t, c.currentFailures["test"], 2)

			time.Sleep(20 * time.Minute)
			synctest.Wait()

			c.RecordFailure("test")
			assert.Len(t, c.currentFailures["test"], 1)
		})
	})
}

func TestInMemoryCounter_IsUserLocked(t *testing.T) {
	synctest.Run(func() {
		// synctest and the background thread don't get along, so build this manually for now
		c := &InMemoryCounter{
			lock:                &sync.Mutex{},
			lockDuration:        30 * time.Minute,
			failuresBeforeLock:  5,
			failureLookbackTime: 15 * time.Minute,
			lockedAccounts:      make(map[string]time.Time),
			currentFailures:     make(map[string][]time.Time),
		}

		assert.False(t, c.IsUserLocked("test"))

		c.RecordFailure("test")
		c.RecordFailure("test")
		c.RecordFailure("test")
		c.RecordFailure("test")
		c.RecordFailure("test")

		assert.True(t, c.IsUserLocked("test"))

		time.Sleep(15 * time.Minute)
		synctest.Wait()

		assert.True(t, c.IsUserLocked("test"))

		time.Sleep(16 * time.Minute)
		assert.False(t, c.IsUserLocked("test"))
	})

}

func TestInMemoryCounter_cleanup(t *testing.T) {
	synctest.Run(func() {
		c := &InMemoryCounter{
			lock:                &sync.Mutex{},
			lockDuration:        30 * time.Minute,
			failuresBeforeLock:  5,
			failureLookbackTime: 15 * time.Minute,
			lockedAccounts:      make(map[string]time.Time),
			currentFailures:     make(map[string][]time.Time),
		}

		c.RecordFailure("test")
		c.RecordFailure("test")

		assert.Len(t, c.currentFailures["test"], 2)

		c.cleanup()

		assert.Len(t, c.currentFailures["test"], 2)

		time.Sleep(20 * time.Minute)
		synctest.Wait()

		assert.Len(t, c.currentFailures["test"], 2)
		c.cleanup()
		assert.Len(t, c.currentFailures["test"], 0)

		c.RecordFailure("lock")
		c.RecordFailure("lock")
		c.RecordFailure("lock")
		c.RecordFailure("lock")
		c.RecordFailure("lock")

		assert.Empty(t, c.currentFailures["lock"])
		assert.True(t, c.IsUserLocked("lock"))

		time.Sleep(1 * time.Hour)
		synctest.Wait()

		assert.False(t, c.IsUserLocked("lock"))

		assert.Len(t, c.lockedAccounts, 1)
		c.cleanup()
		assert.Len(t, c.lockedAccounts, 0)
	})

}

func TestInMemoryCounter_ClearFailures(t *testing.T) {
	c := NewInMemoryCounter(10*time.Minute, 10, 10*time.Minute)

	c.RecordFailure("test")
	c.RecordFailure("test")

	assert.Len(t, c.currentFailures["test"], 2)

	c.ClearFailures("test")

	assert.Len(t, c.currentFailures["test"], 0)
}
