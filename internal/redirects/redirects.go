package redirects

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"golang.org/x/net/idna"
)

const (
	AllowAllKey       = "security.redirects.allow_all"
	FallbackURLKey    = "security.redirects.fallback_url"
	AllowedDomainsKey = "security.redirects.allowed_domains"
	ServerDomainKey   = "server.domain"

	DefaultFallbackURL = "/"
)

type Validator struct {
	allowAll       bool
	fallbackURL    string
	allowedDomains []string
}

func NewFromConfig(v *viper.Viper) (*Validator, error) {
	if v.GetBool(AllowAllKey) {
		log.Warn().Msg("redirect checking is disabled. this can be insecure!")
		return &Validator{allowAll: true}, nil
	}

	fallback := DefaultFallbackURL
	if customFallback := v.GetString(FallbackURLKey); customFallback != "" {
		log.Info().Str("fallback_url", customFallback).Msg("using custom fallback url for redirect uri filtering")
		fallback = customFallback
	}

	// by default, allow the server domain only as an allowed redirect domain. This should be safe and backwards
	// compatible as this needs to be set in other places for AT2 to work in the first place
	allowedDomains := []string{v.GetString(ServerDomainKey)}
	if customDomains := v.GetStringSlice(AllowedDomainsKey); customDomains != nil {
		log.Info().Strs("custom_domains", customDomains).Msg("using domain allow-list for redirect uri filtering")
		allowedDomains = customDomains
	}

	for i := range allowedDomains {
		sanitizedDomain, err := idna.Lookup.ToASCII(strings.ToLower(allowedDomains[i]))
		if err != nil {
			return nil, fmt.Errorf("redirects: NewFromConfig: could not parse domain %s: %w", allowedDomains[i], err)
		}
		allowedDomains[i] = sanitizedDomain
	}

	return &Validator{
		fallbackURL:    fallback,
		allowedDomains: allowedDomains,
	}, nil
}

func onDomain(hostname string, domain string) bool {
	return hostname == domain || strings.HasSuffix(hostname, fmt.Sprintf(".%s", domain))
}

func (v *Validator) IsAllowed(rawURL string) bool {
	if v.allowAll {
		return true
	}

	if rawURL == "" {
		return false
	}

	if strings.HasPrefix(rawURL, "//") {
		// do not allow relative protocol URLs
		return false
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		log.Warn().Err(err).Str("redirect_uri", rawURL).Msg("could not parse URL")
		return false
	}

	if !parsed.IsAbs() {
		// only allow absolute URLs
		return false
	}

	// TODO: do we want to filter on schemes here?

	hostname := strings.ToLower(parsed.Hostname())
	if hostname == "" {
		return false
	}

	hostname, err = idna.Lookup.ToASCII(hostname)
	if err != nil {
		log.Warn().Str("domain", hostname).Err(err).Msg("could not sanitize domain")
		return false
	}

	for _, curr := range v.allowedDomains {
		if onDomain(hostname, curr) {
			return true
		}
	}

	return false
}

func (v *Validator) Sanitize(rawURL string) (string, bool) {
	if v.IsAllowed(rawURL) {
		return rawURL, false
	}

	return v.fallbackURL, true
}
