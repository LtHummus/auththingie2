package cmd

import (
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/lthummus/auththingie2/config"
	"github.com/lthummus/auththingie2/healthcheck"
)

var (
	host           string
	useConfig      bool
	timeoutSeconds int
	ignoreBadTLS   bool
)

func init() {
	healthCheckCmd.Flags().StringVar(&host, "host", "", "host to check")
	healthCheckCmd.Flags().BoolVarP(&useConfig, "useconfig", "c", false, "read values from config file")
	healthCheckCmd.Flags().IntVarP(&timeoutSeconds, "timeout", "t", 3, "timeout (in seconds)")
	healthCheckCmd.Flags().BoolVar(&ignoreBadTLS, "ignore-bad-tls", false, "ignore bad certificates for HTTPS")
}

var healthCheckCmd = &cobra.Command{
	Use:   "healthcheck",
	Short: "checks the health of auththingie2",
	Long: "checks the health of a running auththingie2 instance. This is best used as a " +
		"defined healthcheck inside a docker container",
	RunE: func(cmd *cobra.Command, args []string) error {
		if !useConfig && host == "" {
			return fmt.Errorf("auththingie2: healthcheck: one of useconfig host must be specified")
		}

		var hostToCheck string

		if useConfig {
			err := config.Init()
			if err != nil {
				log.Error().Err(err).Msg("could not read config")
			}

			scheme := "http"
			if viper.GetBool("server.tls.enabled") {
				scheme = "https"
			}

			if viper.GetBool("healthcheck.tls.ignore_bad_tls") {
				ignoreBadTLS = true
			}

			hostToCheck = fmt.Sprintf("%s://localhost:%d", scheme, viper.GetInt("server.port"))
		} else {
			hostToCheck = host
		}

		err := healthcheck.CheckHealth(hostToCheck, time.Duration(timeoutSeconds)*time.Second, ignoreBadTLS)
		if err != nil {
			log.Error().Err(err).Str("host", hostToCheck).Msg("health check failed")
			return err
		}

		log.Info().Str("host", hostToCheck).Msg("health check ok")
		return nil
	},
}
