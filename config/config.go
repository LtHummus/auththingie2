package config

import (
	"errors"
	"net/url"
	"os"
	"sync"
	"sync/atomic"

	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"

	"github.com/lthummus/auththingie2/argon"
)

var (
	Lock sync.RWMutex

	initLock  sync.Mutex
	hasInit   bool
	initError error

	DebugFlagOverride uint32
)

type WriteOverride struct {
	Key   string
	Value any
}

func IsDocker() bool {
	return os.Getenv("AT2_MODE") == "docker"
}

func IsProductionMode() bool {
	return os.Getenv("ENVIRONMENT") == "prod"
}

func IsDebugLoggingEnabled() bool {
	return os.Getenv("DEBUG_LOG") == "true"
}

func EnableDebugPage() bool {
	if os.Getenv("ENABLE_DEBUG_PAGE") == "true" {
		return true
	}

	if !IsProductionMode() {
		return true
	}

	if atomic.LoadUint32(&DebugFlagOverride) > 0 {
		return true
	}

	return false
}

func Init() error {
	initLock.Lock()
	defer initLock.Unlock()

	if hasInit {
		return initError
	}

	Lock.Lock()
	defer Lock.Unlock()

	configFilePath := os.Getenv("CONFIG_FILE_PATH")
	if configFilePath == "" {
		viper.SetConfigName("auththingie2")
		viper.SetConfigType("yaml")
		viper.AddConfigPath("/config")
		viper.AddConfigPath(".")
	} else {
		viper.SetConfigFile(configFilePath)
	}

	err := viper.ReadInConfig()
	if err != nil {
		var configFileNotFoundError viper.ConfigFileNotFoundError
		if errors.As(err, &configFileNotFoundError) {
			initError = err
			return initError
		}

		log.Fatal().Str("config_file", viper.ConfigFileUsed()).Err(err).Msg("could not read config")
	}
	log.Info().Str("config_file_path", viper.ConfigFileUsed()).Msg("initialized configuration")
	viper.WatchConfig()

	return nil
}

func ValidateConfig() []string {
	var errorsFound []string

	if dbKind := viper.GetString("db.kind"); dbKind != "sqlite" {
		log.Error().Str("db.kind", dbKind).Msg("invalid db kind; must be sqlite")
		errorsFound = append(errorsFound, "invalid `db.kind`; must be `sqlite`")
	}

	authURL := viper.GetString("server.auth_url")
	if authURL == "" {
		log.Error().Msg("server.auth_url is not set")
		errorsFound = append(errorsFound, "`server.auth_url` is not set")
	} else if _, err := url.Parse(authURL); err != nil {
		log.Error().Str("auth_url", authURL).Err(err).Msg("server.auth_url is not a valid URL")
		errorsFound = append(errorsFound, "`server.auth_url` is not a valid URL")
	}

	if domain := viper.GetString("server.domain"); domain == "" {
		log.Error().Msg("server.domain is not set. This should be set to the naked domain of your server")
		errorsFound = append(errorsFound, "server.domain is not set")
	}

	return errorsFound
}

func cleanDefaultArgon(everything map[string]any) {
	securityBlock, found := everything["security"].(map[string]any)
	if !found {
		return
	}

	argonBlock, found := securityBlock["argon2"].(map[string]any)
	if !found {
		return
	}

	if argonBlock["memory"] == argon.DefaultMemory {
		delete(argonBlock, "memory")
	}

	if argonBlock["iterations"] == argon.DefaultIterations {
		delete(argonBlock, "iterations")
	}

	if argonBlock["parallelism"] == argon.DefaultParallelism {
		delete(argonBlock, "parallelism")
	}

	if argonBlock["saltlength"] == argon.DefaultSaltLength {
		delete(argonBlock, "saltlength")
	}

	if argonBlock["keylength"] == argon.DefaultKeyLength {
		delete(argonBlock, "keylength")
	}

	if len(argonBlock) == 0 {
		delete(securityBlock, "argon2")
	}

	if len(securityBlock) == 0 {
		delete(everything, "security")
	}
}

func WriteCurrentConfigState(overrides ...WriteOverride) error {
	Lock.Lock()
	defer Lock.Unlock()
	configFileName := viper.ConfigFileUsed()
	stats, err := os.Stat(configFileName)
	if err != nil {
		log.Error().Err(err).Msg("could not stat file")
		return err
	}

	everything := viper.AllSettings()

	for _, curr := range overrides {
		everything[curr.Key] = curr.Value
	}

	cleanDefaultArgon(everything)

	data, err := yaml.Marshal(everything)
	if err != nil {
		log.Error().Err(err).Msg("could not marshall")
		return err
	}

	err = os.WriteFile(configFileName, data, stats.Mode())
	if err != nil {
		log.Error().Err(err).Msg("could not write file")
		return err
	}

	log.Info().Str("config_file_path", configFileName).Int("bytes_written", len(data)).Msg("wrote config file")

	return nil

}
