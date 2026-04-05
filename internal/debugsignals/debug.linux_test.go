//go:build !windows

package debugsignals

import (
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListenAndAct(t *testing.T) {
	t.Run("basic case", func(t *testing.T) {
		stop := make(chan struct{})
		triggered := false
		action := func() {
			triggered = true
		}

		go listenAndAct(syscall.SIGUSR1, stop, action)

		// TODO: instead of all these sleeps, I would like to use synctest, but for some reason it keeps panicing with
		//       "fatal error: select on synctest channel from outside bubble" and I'm not sure why. Guessing sometihng
		//       inside `signal.Notify` breaks? I would like to use something like `signal.NotifyContext` but it doesn't
		//       look like it differentiates between "parent context cancelled" vs "signal came"
		time.Sleep(1 * time.Second)

		p, err := os.FindProcess(os.Getpid())
		require.NoError(t, err)

		err = p.Signal(syscall.SIGUSR1)
		require.NoError(t, err)

		assert.Eventually(t, func() bool { return triggered }, 10*time.Second, 500*time.Millisecond)
	})

	t.Run("try closing the stop channel", func(t *testing.T) {
		stop := make(chan struct{})
		triggered := false
		action := func() {
			triggered = true
		}

		go listenAndAct(syscall.SIGUSR1, stop, action)

		time.Sleep(1 * time.Second)

		close(stop)

		time.Sleep(1 * time.Second)
		p, err := os.FindProcess(os.Getpid())
		require.NoError(t, err)

		err = p.Signal(syscall.SIGUSR1)
		require.NoError(t, err)

		assert.Never(t, func() bool {
			return triggered
		}, 2*time.Second, 500*time.Millisecond)
	})

}
