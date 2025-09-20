package ainit

import (
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/lthummus/auththingie2/config"
)

func init() {
	var revision string
	info, _ := debug.ReadBuildInfo()
	for i := range info.Settings {
		if info.Settings[i].Key == "vcs.revision" {
			revision = info.Settings[i].Value
			break
		}
	}

	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})
	log.Info().
		Str("arch", runtime.GOARCH).
		Str("os", runtime.GOOS).
		Str("go_version", strings.TrimPrefix(runtime.Version(), "go")).
		Str("git_commit", revision).
		Msg("hello world")
	if !config.IsProductionMode() || config.IsDebugLoggingEnabled() {
		zerolog.SetGlobalLevel(zerolog.TraceLevel)
		log.Warn().Str("environment", os.Getenv("ENVIRONMENT")).Bool("docker_detected", config.IsDocker()).Msg("starting with debug logging enabled")
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
		log.Info().Str("environment", os.Getenv("ENVIRONMENT")).Bool("docker_detected", config.IsDocker()).Msg("starting in production mode")
	}
}
