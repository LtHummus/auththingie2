package loginlimit

import (
	"errors"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

type LoginLimiter interface {
	IsAccountLocked(key string) bool
	MarkFailedAttempt(key string) (int, error)
}

var (
	ErrAccountLocked = errors.New("loginlimit: account is locked")
)

const (
	ConfigKeyLoginFailureLimit = "security.account_lock.failure_limit"
	ConfigKeyLookbackTime      = "security.account_lock.lookback_time"
	ConfigKeyLockDuration      = "security.account_lock.lock_duration"

	DefaultFailureLimit        = 5
	DefaultLookbackTime        = 15 * time.Minute
	DefaultAccountLockDuration = 15 * time.Minute
)

type InMemoryLoginLimiter struct {
	failureLock *sync.Mutex
	lockLock    *sync.Mutex

	maxFailures         int
	failureLookbackTime time.Duration
	accountLockDuration time.Duration

	loginFailures map[string][]time.Time
	accountLocks  map[string]time.Time
}

func NewInMemoryLimiter() *InMemoryLoginLimiter {
	failureLimit := viper.GetInt(ConfigKeyLoginFailureLimit)
	lookbackTime := viper.GetDuration(ConfigKeyLookbackTime)
	lockDuration := viper.GetDuration(ConfigKeyLockDuration)

	// we do it this way so we don't mistakenly pollute the config file with our values
	if failureLimit == 0 {
		failureLimit = DefaultFailureLimit
	}

	if lookbackTime == 0 {
		lookbackTime = DefaultLookbackTime
	}

	if lockDuration == 0 {
		lockDuration = DefaultAccountLockDuration
	}

	log.Info().Int("failure_limit", failureLimit).Dur("lookback_time", lookbackTime).Dur("lock_duration", lockDuration).Msg("initializing account login failure locker")

	imll := constructLimiter(failureLimit, lookbackTime, lockDuration)

	go func() {
		for {
			sleepDuration := 2 * min(lookbackTime, lockDuration)

			for {
				time.Sleep(sleepDuration)

				imll.cleanupRoutine()
			}
		}
	}()

	return imll
}

func constructLimiter(failureLimit int, lookbackTime time.Duration, lockDuration time.Duration) *InMemoryLoginLimiter {
	return &InMemoryLoginLimiter{
		failureLock: &sync.Mutex{},
		lockLock:    &sync.Mutex{},

		maxFailures:         failureLimit,
		failureLookbackTime: lookbackTime,
		accountLockDuration: lockDuration,

		loginFailures: map[string][]time.Time{},
		accountLocks:  map[string]time.Time{},
	}
}

func (iml *InMemoryLoginLimiter) cleanupRoutine() {
	iml.lockLock.Lock()
	var locksToDelete []string

	for k, v := range iml.accountLocks {
		if v.Before(time.Now()) {
			locksToDelete = append(locksToDelete, k)
		}
	}

	for _, curr := range locksToDelete {
		delete(iml.accountLocks, curr)
	}
	iml.lockLock.Unlock()

	var failuresToDelete []string
	iml.failureLock.Lock()
	for k, v := range iml.loginFailures {
		var cleanedAccountLocks []time.Time
		for _, curr := range v {
			if curr.After(time.Now()) {
				cleanedAccountLocks = append(cleanedAccountLocks, curr)
			}
		}
		iml.loginFailures[k] = cleanedAccountLocks
		if len(cleanedAccountLocks) == 0 {
			failuresToDelete = append(failuresToDelete, k)
		}
	}

	for _, curr := range failuresToDelete {
		delete(iml.loginFailures, curr)
	}
	iml.failureLock.Unlock()
}

func (iml *InMemoryLoginLimiter) IsAccountLocked(key string) bool {
	iml.lockLock.Lock()
	defer iml.lockLock.Unlock()

	unlockTime := iml.accountLocks[key]

	if unlockTime.Before(time.Now()) {
		delete(iml.accountLocks, key)
	}

	return unlockTime.After(time.Now())
}

func (iml *InMemoryLoginLimiter) lockAccount(key string) {
	iml.lockLock.Lock()
	defer iml.lockLock.Unlock()

	iml.accountLocks[key] = time.Now().Add(iml.accountLockDuration)
}

func (iml *InMemoryLoginLimiter) MarkFailedAttempt(key string) (int, error) {
	if iml.IsAccountLocked(key) {
		return 0, ErrAccountLocked
	}

	iml.failureLock.Lock()
	defer iml.failureLock.Unlock()

	var cleanedAccountFailures []time.Time
	for _, curr := range iml.loginFailures[key] {
		if curr.After(time.Now()) {
			cleanedAccountFailures = append(cleanedAccountFailures, curr)
		}
	}

	cleanedAccountFailures = append(cleanedAccountFailures, time.Now().Add(iml.failureLookbackTime))
	if len(cleanedAccountFailures) >= iml.maxFailures {
		// delete failures and lock account
		delete(iml.loginFailures, key)
		iml.lockAccount(key)

		return 0, ErrAccountLocked
	}

	iml.loginFailures[key] = cleanedAccountFailures

	return iml.maxFailures - len(cleanedAccountFailures), nil
}
