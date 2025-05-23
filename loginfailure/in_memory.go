package loginfailure

import (
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"
)

type InMemoryCounter struct {
	lock *sync.Mutex

	lockDuration        time.Duration
	failuresBeforeLock  int
	failureLookbackTime time.Duration

	lockedAccounts  map[string]time.Time
	currentFailures map[string][]time.Time
}

var normalizer = transform.Chain(norm.NFC, cases.Lower(language.Und))

func NewInMemoryCounter(lockTime time.Duration, failuresBeforeLock int, failureLookbackTime time.Duration) *InMemoryCounter {
	c := &InMemoryCounter{
		lock: &sync.Mutex{},

		lockDuration:        lockTime,
		failuresBeforeLock:  failuresBeforeLock,
		failureLookbackTime: failureLookbackTime,

		lockedAccounts:  make(map[string]time.Time),
		currentFailures: make(map[string][]time.Time),
	}

	threadSleepTime := min(failureLookbackTime, lockTime)
	go func() {
		log.Debug().Dur("thread_sleep_time", threadSleepTime).Msg("starting lock check thread")

		for {
			time.Sleep(threadSleepTime)

			c.cleanup()
		}
	}()

	return c
}

func (c *InMemoryCounter) cleanup() {
	log.Debug().Msg("starting lock cleanup loop")
	c.lock.Lock()

	newFailures := make(map[string][]time.Time)
	newLocked := make(map[string]time.Time)

	for username, currentFailures := range c.currentFailures {
		newFailures[username] = c.filterOldFailures(currentFailures)
	}

	for username, unlockTime := range c.lockedAccounts {
		if unlockTime.After(time.Now()) {
			newLocked[username] = unlockTime
		}
	}

	c.lockedAccounts = newLocked
	c.currentFailures = newFailures
	c.lock.Unlock()
}

func normalizeUsername(username string) string {
	normalized, _, err := transform.String(normalizer, username)
	if err != nil {
		log.Panic().Err(err).Str("username", username).Msg("could not normalize string for locking")
	}
	return normalized
}

func (c *InMemoryCounter) lockUser(username string) {
	c.currentFailures[username] = nil
	c.lockedAccounts[username] = time.Now().Add(c.lockDuration)
}

func (c *InMemoryCounter) LoginsRemaining(username string) int {
	username = normalizeUsername(username)

	c.lock.Lock()
	defer c.lock.Unlock()

	failureCount := c.getFailures(username)

	return c.failuresBeforeLock - len(failureCount)
}

func (c *InMemoryCounter) IsUserLocked(username string) bool {
	username = normalizeUsername(username)

	c.lock.Lock()
	defer c.lock.Unlock()

	unlockTime, isLocked := c.lockedAccounts[username]
	if !isLocked {
		return false
	}

	return unlockTime.After(time.Now())
}

func (c *InMemoryCounter) filterOldFailures(x []time.Time) []time.Time {
	filtered := make([]time.Time, 0)
	for _, curr := range x {
		if time.Since(curr) < c.failureLookbackTime {
			filtered = append(filtered, curr)
		}
	}

	return filtered
}

func (c *InMemoryCounter) getFailures(username string) []time.Time {
	failures := c.currentFailures[username]
	if failures == nil {
		failures = make([]time.Time, 0)
	}

	filtered := c.filterOldFailures(failures)

	c.currentFailures[username] = filtered

	return filtered
}

func (c *InMemoryCounter) RecordFailure(username string) {
	username = normalizeUsername(username)

	c.lock.Lock()
	defer c.lock.Unlock()

	failures := c.getFailures(username)

	failures = append(failures, time.Now())
	c.currentFailures[username] = failures

	if len(failures) >= c.failuresBeforeLock {
		c.lockUser(username)
	}
}

func (c *InMemoryCounter) ClearFailures(username string) {
	username = normalizeUsername(username)

	c.lock.Lock()
	defer c.lock.Unlock()

	delete(c.currentFailures, username)
}
