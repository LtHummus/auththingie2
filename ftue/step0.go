package ftue

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"

	"github.com/gorilla/securecookie"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"

	"github.com/lthummus/auththingie2/config"
	"github.com/lthummus/auththingie2/db/sqlite"
	"github.com/lthummus/auththingie2/render"
	"github.com/lthummus/auththingie2/rules"
	"github.com/lthummus/auththingie2/util"
)

const (
	DefaultDBFilePath     = "/config/at2.db"
	DefaultConfigFilePath = "/config/auththingie2.yaml"
	DefaultPort           = 9000
)

type step0Params struct {
	Port               int
	ServerDomain       string
	AuthURL            string
	DefaultSlashConfig bool
	DefaultPWD         bool
	DefaultCustom      bool
	PWD                string
	CustomConfigPath   string
	CustomDBPath       string
	Errors             []string
}

func getCwd() string {
	pwd, err := os.Getwd()
	if err != nil {
		log.Warn().Err(err).Msg("could not get current working directory")
		pwd = ""
	}
	return pwd
}

func (fe *ftueEnv) HandleFTUEStep0GET(w http.ResponseWriter, r *http.Request) {

	render.Render(w, "ftue_step0.gohtml", &step0Params{
		ServerDomain:       GetRootDomain(r.URL),
		AuthURL:            r.Host,
		DefaultSlashConfig: config.IsDocker(),
		DefaultPWD:         !config.IsDocker(),
		PWD:                getCwd(),
		Port:               DefaultPort,
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
	}

	if authURL == "" {
		errors = append(errors, "Auth URL can not be blank")
	} else {
		_, err = url.Parse(authURL)
		if err != nil {
			errors = append(errors, fmt.Sprintf("Invalid auth URL: %s", err.Error()))
		}
	}

	var port int64
	port, err = strconv.ParseInt(portStr, 10, 64)
	if err != nil {
		errors = append(errors, fmt.Sprintf("Invalid port: %s", err.Error()))
	}

	if len(errors) > 0 {
		render.Render(w, "ftue_step0.gohtml", &step0Params{
			ServerDomain:       domain,
			AuthURL:            authURL,
			Port:               int(port),
			DefaultSlashConfig: pathPreset == "slashconfig",
			DefaultPWD:         pathPreset == "pwd",
			DefaultCustom:      pathPreset == "custom",
			CustomConfigPath:   configFilePath,
			CustomDBPath:       dbFilePath,
			PWD:                getCwd(),
			Errors:             errors,
		})
		return
	}

	log.Info().Str("config_file_path", configFilePath).Str("db_file_path", dbFilePath).Int64("port", port).Msg("got initial config")

	viper.SetConfigFile(configFilePath)
	viper.SetConfigType("yaml")
	viper.Set("db.file", dbFilePath)
	viper.Set("db.kind", "sqlite")
	viper.Set("server.port", port)
	viper.Set("server.secret_key", util.Base64Encoder.EncodeToString(securecookie.GenerateRandomKey(32)))
	viper.Set("server.auth_url", authURL)
	viper.Set("server.domain", domain)
	err = viper.WriteConfig()
	if err != nil {
		log.Error().Err(err).Str("config_file_path", configFilePath).Msg("could not write config file")
		http.Error(w, "could not write config file path -- see logs", http.StatusInternalServerError)
		return
	}

	analyzer, err := rules.NewFromConfig()
	if err != nil {
		log.Error().Err(err).Msg("could not initialize rules engine")
		http.Error(w, "could not initialize rules engine -- see logs", http.StatusInternalServerError)
		return
	}

	newDatabase, err := sqlite.NewSQLiteFromConfig()
	if err != nil {
		log.Error().Err(err).Str("db_file", dbFilePath).Msg("could not initialize sqlite database")
		http.Error(w, "could not initialize database -- see logs", http.StatusInternalServerError)
		return
	}

	fe.database = newDatabase
	fe.analyzer = analyzer

	http.Redirect(w, r, "/ftue/step1", http.StatusFound)
}
