package loginlimit

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestInMemoryLoginLimiter_IsAccountLocked(t *testing.T) {
	synctest.Run(func() {
		l := constructLimiter(5, 15*time.Minute, 10*time.Minute)

		l.accountLocks["test"] = time.Now().Add(10 * time.Minute)

		assert.True(t, l.IsAccountLocked("test"))

		time.Sleep(11 * time.Minute)

		assert.False(t, l.IsAccountLocked("test"))
		assert.Len(t, l.accountLocks, 0)
	})

}

func TestInMemoryLoginLimiter_MarkFailedAttempt(t *testing.T) {
	t.Run("basic test", func(t *testing.T) {
		l := constructLimiter(5, 15*time.Minute, 15*time.Minute)

		remain, err := l.MarkFailedAttempt("test")
		assert.NoError(t, err)
		assert.Equal(t, 4, remain)
	})

	t.Run("basic test with multiple failures", func(t *testing.T) {
		l := constructLimiter(5, 15*time.Minute, 15*time.Minute)

		remain, err := l.MarkFailedAttempt("test")
		assert.NoError(t, err)
		assert.Equal(t, 4, remain)

		remain, err = l.MarkFailedAttempt("test")
		assert.NoError(t, err)
		assert.Equal(t, 3, remain)

		remain, err = l.MarkFailedAttempt("test")
		assert.NoError(t, err)
		assert.Equal(t, 2, remain)
	})

	t.Run("basic test with expiring failures", func(t *testing.T) {
		synctest.Run(func() {
			l := constructLimiter(5, 15*time.Minute, 15*time.Minute)

			remain, err := l.MarkFailedAttempt("test")
			assert.NoError(t, err)
			assert.Equal(t, 4, remain)

			remain, err = l.MarkFailedAttempt("test")
			assert.NoError(t, err)
			assert.Equal(t, 3, remain)

			time.Sleep(20 * time.Minute)

			remain, err = l.MarkFailedAttempt("test")
			assert.NoError(t, err)
			assert.Equal(t, 4, remain)
		})
	})

	t.Run("lock account after appropriate failures", func(t *testing.T) {
		l := constructLimiter(5, 15*time.Minute, 15*time.Minute)

		_, _ = l.MarkFailedAttempt("test")
		_, _ = l.MarkFailedAttempt("test")
		_, _ = l.MarkFailedAttempt("test")
		remain, err := l.MarkFailedAttempt("test")
		assert.NoError(t, err)
		assert.Equal(t, 1, remain)

		remain, err = l.MarkFailedAttempt("test")
		assert.Equal(t, 0, remain)
		assert.ErrorIs(t, err, ErrAccountLocked)
	})
}

func TestInMemoryLoginLimiter_cleanupRoutine(t *testing.T) {
	t.Run("basic test", func(t *testing.T) {
		synctest.Run(func() {
			l := constructLimiter(5, 15*time.Minute, 20*time.Minute)

			l.MarkFailedAttempt("test")
			l.lockAccount("test1")

			time.Sleep(10 * time.Minute)

			l.MarkFailedAttempt("test")
			l.MarkFailedAttempt("test")

			time.Sleep(6 * time.Minute)

			// at this point, "test" should have 2 failures and "test1" should still be locked
			l.cleanupRoutine()

			assert.Len(t, l.loginFailures["test"], 2)
			assert.True(t, l.IsAccountLocked("test1"))

			time.Sleep(10 * time.Minute)

			l.cleanupRoutine()

			assert.Empty(t, l.loginFailures["test"])
			assert.False(t, l.IsAccountLocked("test1"))
		})

	})
}
