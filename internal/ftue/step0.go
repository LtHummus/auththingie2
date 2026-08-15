package ftue

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/gorilla/securecookie"
	"github.com/rs/zerolog/log"

	"github.com/lthummus/auththingie2/internal/config"
	"github.com/lthummus/auththingie2/internal/db/sqlite"
	"github.com/lthummus/auththingie2/internal/ftue/docker"
	"github.com/lthummus/auththingie2/internal/ftue/iprange"
	"github.com/lthummus/auththingie2/internal/render"
	"github.com/lthummus/auththingie2/internal/rules"
)

const (
	DefaultDBFilePath     = "/config/at2.db"
	DefaultConfigFilePath = "/config/auththingie2.yaml"
	DefaultPort           = 9000
)

type step0Params struct {
	Port                 string
	ServerDomain         string
	AuthURL              string
	DefaultSlashConfig   bool
	DefaultPWD           bool
	DefaultCustom        bool
	PWD                  string // #nosec G117, this is working directory, not password :)
	CustomConfigPath     string
	CustomDBPath         string
	Errors               []string
	DockerEndpoint       string
	DetectedContainers   []docker.FoundContainer
	DockerDetectionError error
	CandidateIPRanges    []iprange.CandidateRange
	SelectedNetworks     map[string]bool
	CustomTrustedNetwork string
}

func getCwd() string {
	pwd, err := os.Getwd()
	if err != nil {
		log.Warn().Err(err).Msg("could not get current working directory")
		pwd = ""
	}
	return pwd
}

func safeTrustedNetwork(s string) error {
	if _, err := netip.ParseAddr(s); err == nil {
		return nil
	}

	p, err := netip.ParsePrefix(s)
	if err != nil {
		return fmt.Errorf("invalid trusted network: %v", err)
	}

	// Reject every IPv4 /0 CIDR, which means all IPv4 addresses.
	if p.Bits() == 0 {
		return fmt.Errorf("global-trust is not allowed (e.g. 0.0.0.0/0 or ::/0)")
	}

	return nil
}

func detectContainers(ctx context.Context) (string, []docker.FoundContainer, error) {
	dockerEndpoint := docker.DefaultDockerEndpoint
	if customEndpoint := os.Getenv("SETUP_DOCKER_ENDPOINT"); customEndpoint != "" {
		dockerEndpoint = customEndpoint
	}
	detectedContainers, err := docker.DetectDocker(ctx, dockerEndpoint)
	if err != nil {
		log.Warn().Err(err).Msg("error attempting to detect docker containers")
	}

	return dockerEndpoint, detectedContainers, err
}

func validateURL(x string) error {
	parsed, err := url.Parse(x)
	if err != nil {
		return err
	}

	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("invalid scheme: must be http or https")
	}

	if parsed.Host == "" {
		return fmt.Errorf("invalid host: can not be empty")
	}

	if parsed.User != nil {
		return fmt.Errorf("invalid url: can not have credentials (username:password) in URL")
	}

	if parsed.RawQuery != "" {
		return fmt.Errorf("invalid url: can not have query string")
	}

	if parsed.Fragment != "" {
		return fmt.Errorf("invalid url: can not have a URL fragment in it")
	}

	return nil
}

func (fe *ftueEnv) HandleFTUEStep0GET(w http.ResponseWriter, r *http.Request) {
	dockerEndpoint, detectedContainers, dockerErr := detectContainers(r.Context())

	ipNetworks, err := iprange.DetectInternalIPRange()
	if err != nil {
		log.Warn().Err(err).Msg("could not detect a reasonable private IP range")
	}

	render.Render(w, "ftue_step0.gohtml", &step0Params{
		ServerDomain:         GetRootDomain(RequestHost(r)),
		AuthURL:              RequestOrigin(r),
		DefaultSlashConfig:   config.IsDocker(),
		DefaultPWD:           !config.IsDocker(),
		PWD:                  getCwd(),
		Port:                 strconv.Itoa(DefaultPort),
		DockerEndpoint:       dockerEndpoint,
		DetectedContainers:   detectedContainers,
		DockerDetectionError: dockerErr,
		CandidateIPRanges:    ipNetworks,
	})
}

func (fe *ftueEnv) HandleFTUEStep0POST(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		log.Error().Err(err).Msg("could not parse form")
		http.Error(w, "could not parse input", http.StatusBadRequest)
		return
	}

	portStr := r.FormValue("port")
	domain := r.FormValue("domain")
	authURL := r.FormValue("auth_url")
	pathPreset := r.FormValue("config_file_preset")
	dockerDetected := r.FormValue("docker_detected") == "true"
	containersFound := r.FormValue("containers_found") == "true"
	dockerEndpoint := r.FormValue("docker_endpoint")
	checkedNetworks := r.Form["trusted_networks"]
	customTrustedNetwork := strings.TrimSpace(r.FormValue("custom_trusted_network"))

	var errors []string

	var configFilePath string
	var dbFilePath string
	if pathPreset == "slashconfig" {
		if runtime.GOOS == "windows" {
			log.Warn().Msg("user selected *nix style path on a windows system ... it's their funeral")
		}
		configFilePath = filepath.Join("/config", "auththingie2.yaml")
		dbFilePath = filepath.Join("/config", "at2.db")
	} else if pathPreset == "pwd" {
		configFilePath = filepath.Join(getCwd(), "auththingie2.yaml")
		dbFilePath = filepath.Join(getCwd(), "at2.db")
	} else {
		configFilePath = r.FormValue("config_path")
		dbFilePath = r.FormValue("db_path")
	}

	log.Info().Str("config_file_path", configFilePath).Str("db_file_path", dbFilePath).Msg("got paths")

	if configFilePath != "" {
		if err := TestWrite(configFilePath); err != nil {
			errors = append(errors, "Could not write to config file paths")
		}
	} else {
		errors = append(errors, "Config file path is empty")
	}

	if dbFilePath != "" {
		if err := TestWrite(dbFilePath); err != nil {
			errors = append(errors, "Could not write to config file paths")
		}
	} else {
		errors = append(errors, "DB file path is empty")
	}

	if domain == "" {
		errors = append(errors, "Invalid domain")
	} else if isIPAddress(domain) {
		errors = append(errors, "Invalid domain: an IP address can not be used as the server domain. Use a real domain name, otherwise passkeys and session cookies will not work")
	}

	if authURL == "" {
		errors = append(errors, "Auth URL can not be blank")
	} else {
		authURL = strings.TrimSuffix(authURL, "/")
		err = validateURL(authURL)
		if err != nil {
			errors = append(errors, fmt.Sprintf("Invalid auth URL: %s", err.Error()))
		}
	}

	var port int64
	port, err = strconv.ParseInt(portStr, 10, 64)
	if err != nil {
		errors = append(errors, fmt.Sprintf("Invalid port: %s", err.Error()))
	} else if port < 1 || port > 65535 {
		errors = append(errors, "Invalid port. Ports must be between 1 and 65535")
	}

	var allTrustedNetworks []string
	if customTrustedNetwork != "" {
		allTrustedNetworks = append(allTrustedNetworks, customTrustedNetwork)
	}
	if len(checkedNetworks) > 0 {
		allTrustedNetworks = append(allTrustedNetworks, checkedNetworks...)
	}

	for _, curr := range allTrustedNetworks {
		if err := safeTrustedNetwork(curr); err != nil {
			errors = append(errors, err.Error())
		}
	}

	if len(allTrustedNetworks) == 0 && !containersFound {
		errors = append(errors, "You must configure some sort of trusted proxy setup -- either docker or trusted networks")
	}

	if len(errors) > 0 {
		detectedEndpoint, detectedContainers, dockerErr := detectContainers(r.Context())

		ipNetworks, err := iprange.DetectInternalIPRange()
		if err != nil {
			log.Warn().Err(err).Msg("could not detect a reasonable private IP range")
		}

		// keep the networks that the user checked so they don't accidentally lose them
		selectedNetworks := make(map[string]bool, len(checkedNetworks))
		for _, curr := range checkedNetworks {
			selectedNetworks[curr] = true
		}

		render.Render(w, "ftue_step0.gohtml", &step0Params{
			ServerDomain:         domain,
			AuthURL:              authURL,
			Port:                 portStr,
			DefaultSlashConfig:   pathPreset == "slashconfig",
			DefaultPWD:           pathPreset == "pwd",
			DefaultCustom:        pathPreset == "custom",
			CustomConfigPath:     configFilePath,
			CustomDBPath:         dbFilePath,
			PWD:                  getCwd(),
			Errors:               errors,
			DockerEndpoint:       detectedEndpoint,
			DetectedContainers:   detectedContainers,
			DockerDetectionError: dockerErr,
			CandidateIPRanges:    ipNetworks,
			SelectedNetworks:     selectedNetworks,
			CustomTrustedNetwork: customTrustedNetwork,
		})
		return
	}

	log.Info().Str("config_file_path", configFilePath).Str("db_file_path", dbFilePath).Int64("port", port).Msg("got initial config")

	fe.config.SetConfigFile(configFilePath)
	fe.config.SetConfigType("yaml")
	fe.config.Set(config.ConfigKeyDBFile, dbFilePath)
	fe.config.Set(config.ConfigKeyDBKind, "sqlite")
	fe.config.Set(config.ConfigKeyServerPort, port)
	fe.config.Set(config.ConfigKeyServerSecretKey, base64.RawURLEncoding.EncodeToString(securecookie.GenerateRandomKey(32)))
	fe.config.Set(config.ConfigKeyServerAuthURL, authURL)
	fe.config.Set(config.ConfigKeyRedirectsAllowedDomainsKey, []string{domain})
	fe.config.Set(config.ConfigKeyServerDomain, domain)
	if len(allTrustedNetworks) > 0 {
		fe.config.Set(config.ConfigKeyTrustedProxyNetwork, allTrustedNetworks)
	}

	if dockerDetected {
		fe.config.Set(config.ConfigKeyTrustedProxyDockerEnabled, true)
		if dockerEndpoint != docker.DefaultDockerEndpoint {
			fe.config.Set(config.ConfigKeyTrustedProxyDockerEndpoint, dockerEndpoint)
		}
	}

	err = fe.config.WriteConfig()
	if err != nil {
		log.Error().Err(err).Str("config_file_path", configFilePath).Msg("could not write config file")
		http.Error(w, "could not write config file path -- see logs", http.StatusInternalServerError)
		return
	}

	analyzer, err := rules.NewFromConfig(fe.config)
	if err != nil {
		log.Error().Err(err).Msg("could not initialize rules engine")
		http.Error(w, "could not initialize rules engine -- see logs", http.StatusInternalServerError)
		return
	}

	newDatabase, err := sqlite.NewSQLiteFromConfig(fe.config)
	if err != nil {
		log.Error().Err(err).Str("db_file", dbFilePath).Msg("could not initialize sqlite database")
		http.Error(w, "could not initialize database -- see logs", http.StatusInternalServerError)
		return
	}

	fe.database = newDatabase
	fe.analyzer = analyzer

	http.Redirect(w, r, "/ftue/step1", http.StatusFound)
}
