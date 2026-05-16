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

type ViperValidator struct {
	allowAll       bool
	fallbackURL    string
	allowedDomains []string
}

func NewFromConfig(v *viper.Viper) (*ViperValidator, error) {
	if v.GetBool(AllowAllKey) {
		log.Warn().Msg("redirect checking is disabled. this can be insecure!")
		return &ViperValidator{allowAll: true}, nil
	}

	fallback := DefaultFallbackURL
	if customFallback := v.GetString(FallbackURLKey); customFallback != "" {
		log.Info().Str("fallback_url", customFallback).Msg("using custom fallback url for redirect uri filtering")
		fallback = customFallback
	}

	// by default, allow the server domain only as an allowed redirect domain. This should be safe and backwards
	// compatible as this needs to be set in other places for AT2 to work in the first place
	allowedDomains := []string{v.GetString(ServerDomainKey)}
	if customDomains := v.GetStringSlice(AllowedDomainsKey); len(customDomains) > 0 {
		log.Info().Strs("custom_domains", customDomains).Msg("using domain allow-list for redirect uri filtering")
		allowedDomains = customDomains
	} else {
		log.Warn().Strs("allowed_domain", allowedDomains).Msg("redirect uri validator not set, defaulting to server domain")
	}

	for i := range allowedDomains {
		sanitizedDomain, err := idna.Lookup.ToASCII(strings.ToLower(allowedDomains[i]))
		if err != nil {
			return nil, fmt.Errorf("redirects: NewFromConfig: could not parse domain %s: %w", allowedDomains[i], err)
		}
		allowedDomains[i] = sanitizedDomain
	}

	return &ViperValidator{
		fallbackURL:    fallback,
		allowedDomains: allowedDomains,
	}, nil
}

func onDomain(hostname string, domain string) bool {
	return hostname == domain || strings.HasSuffix(hostname, fmt.Sprintf(".%s", domain))
}

func (v *ViperValidator) IsAllowed(rawURL string) bool {
	if v.allowAll {
		return true
	}

	if rawURL == "" {
		return false
	}

	if strings.HasPrefix(rawURL, "//") {
		// do not allow relative protocol URLs
		log.Warn().Str("redirect_uri", rawURL).Msg("rejecting redirect uri for being open-scheme")
		return false
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		log.Warn().Err(err).Str("redirect_uri", rawURL).Msg("could not parse URL")
		return false
	}

	if !parsed.IsAbs() {
		// only allow absolute URLs
		log.Warn().Str("redirect_uri", rawURL).Msg("rejecting redirect uri for being non-absolute")
		return false
	}

	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		log.Warn().Str("redirect_uri", rawURL).Msg("rejecting redirect uri for being non-http/non-https")
		return false
	}

	hostname := strings.ToLower(parsed.Hostname())
	if hostname == "" {
		log.Warn().Str("redirect_uri", rawURL).Msg("rejecting redirect uri for empty hostname")
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

	log.Warn().Str("redirect_uri", rawURL).Msg("rejecting redirect_uri for not being on allowed list")
	return false
}

func (v *ViperValidator) Sanitize(rawURL string) (string, bool) {
	if v.IsAllowed(rawURL) {
		return rawURL, false
	}

	return v.fallbackURL, true
}
