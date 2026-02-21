package healthcheck

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
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

	// for now, we enforce this to only be localhost since we want to make sure that we're not doing any odd probing
	// if this is too onerous of a restriction, i will think of something else
	if strings.ToLower(req.URL.Hostname()) != "localhost" && req.URL.Hostname() != "127.0.0.1" {
		return fmt.Errorf("healthcheck: CheckHealth: can only check health on localhost")
	}

	res, err := client.Do(req) // #nosec G704 -- we limit this to localhost only
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusFound {
		log.Error().Str("host", host).Str("status", res.Status).Msg("bad status from server")
		return fmt.Errorf("auththingie2: healthcheck: bad status from server: %s", res.Status)
	}

	return nil
}
