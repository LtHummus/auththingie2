package ftue

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog/log"
	"golang.org/x/net/publicsuffix"
)

const (
	forwardedProtoHeader = "X-Forwarded-Proto"
	forwardedHostHeader  = "X-Forwarded-Host"
)

func TestWrite(path string) error {
	testFile := filepath.Join(filepath.Dir(path), ".writetest")
	log.Debug().Str("path", testFile).Msg("testing write")
	err := os.WriteFile(testFile, []byte{}, 0600) // #nosec G703 -- path supplied by admin user
	if err != nil {
		log.Warn().Err(err).Str("path", testFile).Msg("could not write file")
		return err
	}
	err = os.Remove(testFile) // #nosec G703 -- path supplied by admin user
	if err != nil {
		log.Warn().Err(err).Str("path", testFile).Msg("could not remove test file")
	}

	return nil
}

func GetRootDomain(host string) string {
	// host may or may not carry a port; SplitHostPort errors when it doesn't ... trim brackets
	// after to catch a bracketed IPv6 literal that had no port
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(strings.TrimSuffix(strings.Trim(host, "[]"), "."))

	if isIPAddress(host) {
		return ""
	}

	etld, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return host // for things like "localhost"
	}

	return etld
}

func isIPAddress(host string) bool {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	return net.ParseIP(strings.Trim(host, "[]")) != nil
}

func forwardedValue(r *http.Request, name string) string {
	values := r.Header.Values(name)
	if len(values) == 0 {
		return ""
	}

	v := values[len(values)-1]
	if comma := strings.Index(v, ","); comma != -1 {
		v = v[:comma]
	}

	return strings.ToLower(strings.TrimSpace(v))
}

func RequestHost(r *http.Request) string {
	if h := forwardedValue(r, forwardedHostHeader); h != "" {
		return h
	}
	return r.Host
}

func RequestOrigin(r *http.Request) string {
	scheme := "https"
	if p := forwardedValue(r, forwardedProtoHeader); p == "http" || p == "https" {
		scheme = p
	}

	return fmt.Sprintf("%s://%s", scheme, RequestHost(r))
}
