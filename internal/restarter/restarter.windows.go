//go:build windows

package restarter

import (
	"os"
	"os/exec"

	"github.com/rs/zerolog/log"
)

func innerRestart() {
	self, err := os.Executable()
	if err != nil {
		log.Fatal().Err(err).Msg("gould not get self")
	}

	args := os.Args
	env := os.Environ()

	cmd := exec.Command(self, args[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.Env = env

	// TODO: finish this
}
