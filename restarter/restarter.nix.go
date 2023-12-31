//go:build !windows

package restarter

import (
	"os"
	"syscall"

	"github.com/rs/zerolog/log"
)

func innerRestart() {
	self, err := os.Executable()
	if err != nil {
		log.Fatal().Err(err).Msg("gould not get self")
	}

	args := os.Args
	env := os.Environ()

	err = syscall.Exec(self, args, env) // #nosec G204 -- variables are not user controlled
	if err != nil {
		log.Fatal().Err(err).Msg("could not restart process")
	}
}
