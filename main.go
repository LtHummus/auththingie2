package main

import (
	"github.com/rs/zerolog/log"

	"github.com/lthummus/auththingie2/ainit"
	"github.com/lthummus/auththingie2/cmd"
)

func main() {
	log.Info().Bool("loaded", ainit.Loaded()).Msg("initializing services")
	cmd.Execute()
}
