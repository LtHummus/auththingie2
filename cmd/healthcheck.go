package cmd

import (
	"fmt"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/lthummus/auththingie2/config"
)

var (
	host           string
	useConfig      bool
	timeoutSeconds int
)

func init() {
	healthCheckCmd.Flags().StringVar(&host, "host", "", "host to check")
	healthCheckCmd.Flags().BoolVarP(&useConfig, "useconfig", "c", false, "read values from config file")
	healthCheckCmd.Flags().IntVarP(&timeoutSeconds, "timeout", "t", 3, "timeout (in seconds)")
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

			hostToCheck = fmt.Sprintf("%s://localhost:%d", scheme, viper.GetInt("server.port"))
		} else {
			hostToCheck = host
		}

		log.Info().Str("host", hostToCheck).Msg("starting health check")

		c := http.Client{
			Timeout: time.Duration(timeoutSeconds) * time.Second,
		}

		req, err := http.NewRequest(http.MethodGet, hostToCheck, nil)
		if err != nil {
			return err
		}

		res, err := c.Do(req)
		if err != nil {
			return err
		}

		if res.StatusCode != http.StatusOK {
			log.Error().Str("host", hostToCheck).Str("status", res.Status).Msg("bad status from server")
			return fmt.Errorf("auththingie2: healthcheck: bad status from server: %s", res.Status)
		}

		log.Info().Str("host", hostToCheck).Msg("health check ok")

		return nil
	},
}
