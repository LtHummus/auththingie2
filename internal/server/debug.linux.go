//go:build !windows

package server

import (
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/lthummus/auththingie2/internal/config"
)

func listenEnableDebugPage() {
	go func() {
		if config.EnableDebugPage() {
			log.Trace().Msg("debug page already enabled")
			return
		}

		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGUSR1)

		<-c

		log.Warn().Msg("enabling debug page at /debug")

		atomic.AddUint32(&config.DebugFlagOverride, 1)
	}()
}

func listenEnableDebugLogging() {
	go func() {
		if zerolog.GlobalLevel() == zerolog.TraceLevel {
			return
		}

		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGUSR2)

		<-c

		zerolog.SetGlobalLevel(zerolog.TraceLevel)
		log.Trace().Msg("trace logging enabled")
	}()
}
