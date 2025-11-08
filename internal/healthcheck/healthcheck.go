package healthcheck

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"
)

var client = &http.Client{}

func CheckHealth(host string, timeout time.Duration, disableTLSCheck bool) error {
	log.Info().Str("host", host).Msg("starting health check")

	client.Timeout = timeout

	if disableTLSCheck {
		log.Warn().Msg("ignoring bad HTTPS certificates from server")
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // #nosec G402 -- doing this at user's option
			},
		}
	}

	req, err := http.NewRequest(http.MethodGet, host, nil)
	if err != nil {
		return err
	}

	res, err := client.Do(req)
	if err != nil {
		return err
	}

	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusFound {
		log.Error().Str("host", host).Str("status", res.Status).Msg("bad status from server")
		return fmt.Errorf("auththingie2: healthcheck: bad status from server: %s", res.Status)
	}

	return nil
}
