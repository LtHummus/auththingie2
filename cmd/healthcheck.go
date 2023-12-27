package cmd

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/lthummus/auththingie2/ainit"
	"github.com/lthummus/auththingie2/config"
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
		ainit.InitLogger(false)
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

		log.Info().Str("host", hostToCheck).Msg("starting health check")

		c := http.Client{
			Timeout: time.Duration(timeoutSeconds) * time.Second,
		}

		if ignoreBadTLS {
			log.Warn().Msg("ignoring bad HTTPS certificates from server")
			c.Transport = &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true, // #nosec G402 -- doing this at user's option
				},
			}
		}

		req, err := http.NewRequest(http.MethodGet, hostToCheck, nil)
		if err != nil {
			return err
		}

		res, err := c.Do(req)
		if err != nil {
			return err
		}

		if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusFound {
			log.Error().Str("host", hostToCheck).Str("status", res.Status).Msg("bad status from server")
			return fmt.Errorf("auththingie2: healthcheck: bad status from server: %s", res.Status)
		}

		log.Info().Str("host", hostToCheck).Msg("health check ok")

		return nil
	},
}
