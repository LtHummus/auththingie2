package loginlimit

import (
	"errors"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"sync"
	"time"
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

func (inl *InMemoryLoginLimiter) IsAccountLocked(key string) bool {
	inl.lockLock.Lock()
	defer inl.lockLock.Unlock()

	unlockTime := inl.accountLocks[key]

	if unlockTime.Before(time.Now()) {
		delete(inl.accountLocks, key)
	}

	return unlockTime.After(time.Now())
}

func (inl *InMemoryLoginLimiter) lockAccount(key string) {
	inl.lockLock.Lock()
	defer inl.lockLock.Unlock()

	inl.accountLocks[key] = time.Now().Add(inl.accountLockDuration)
}

func (inl *InMemoryLoginLimiter) MarkFailedAttempt(key string) (int, error) {
	if inl.IsAccountLocked(key) {
		return 0, ErrAccountLocked
	}

	inl.failureLock.Lock()
	defer inl.failureLock.Unlock()

	var cleanedAccountFailures []time.Time
	for _, curr := range inl.loginFailures[key] {
		if curr.After(time.Now()) {
			cleanedAccountFailures = append(cleanedAccountFailures, curr)
		}
	}

	cleanedAccountFailures = append(cleanedAccountFailures, time.Now().Add(inl.failureLookbackTime))
	if len(cleanedAccountFailures) >= inl.maxFailures {
		// delete failures and lock account
		delete(inl.loginFailures, key)
		inl.lockAccount(key)

		return 0, ErrAccountLocked
	}

	inl.loginFailures[key] = cleanedAccountFailures

	return inl.maxFailures - len(cleanedAccountFailures), nil
}
