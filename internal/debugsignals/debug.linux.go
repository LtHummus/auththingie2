//go:build !windows

package debugsignals

import (
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/lthummus/auththingie2/internal/config"
)

func ListenEnableDebugPage(stop <-chan struct{}) bool {
	if config.EnableDebugPage() {
		log.Trace().Msg("debug page already enabled")
		return false
	}

	go listenAndAct(syscall.SIGUSR1, stop, func() {
		log.Warn().Msg("enabling debug page at /debug")
		atomic.AddUint32(&config.DebugFlagOverride, 1)
	})

	return true
}

func ListenEnableDebugLogging(stop <-chan struct{}) bool {
	if zerolog.GlobalLevel() == zerolog.TraceLevel {
		return false
	}

	go listenAndAct(syscall.SIGUSR2, stop, func() {
		zerolog.SetGlobalLevel(zerolog.TraceLevel)
		log.Trace().Msg("trace logging enabled")
	})

	return true
}

func listenAndAct(sig os.Signal, stop <-chan struct{}, action func()) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, sig)
	defer signal.Stop(c)

	select {
	case <-c:
		action()
	case <-stop:
		return
	}
}
