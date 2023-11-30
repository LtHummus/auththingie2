package pwmigrate

import (
	"sync/atomic"
)

const (
	unlocked uint32 = 0
	locked   uint32 = 1
)

type lock struct {
	lock *atomic.Uint32
}

func (l *lock) AttemptUnlock() bool {
	swapped := l.lock.CompareAndSwap(unlocked, locked)
	return swapped
}

func (l *lock) Lock() {
	l.lock.Store(unlocked)
}
