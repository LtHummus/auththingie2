package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"sync"
	"sync/atomic"

	"github.com/fsnotify/fsnotify"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"

	"github.com/lthummus/auththingie2/internal/argon"
)

type UpdateListener func(event fsnotify.Event)

var (
	Lock sync.RWMutex

	initLock  sync.Mutex
	hasInit   bool
	initError error

	DebugFlagOverride atomic.Uint32

	updateListenerLock sync.RWMutex
	updateListeners    []UpdateListener
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

	if DebugFlagOverride.Load() > 0 {
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
		if _, ok := errors.AsType[viper.ConfigFileNotFoundError](err); ok {
			initError = err
			return initError
		}

		log.Fatal().Str("config_file", viper.ConfigFileUsed()).Err(err).Msg("could not read config")
	}
	log.Info().Str("config_file_path", viper.ConfigFileUsed()).Msg("initialized configuration")
	viper.WatchConfig()

	viper.OnConfigChange(func(in fsnotify.Event) {
		updateListenerLock.RLock()
		defer updateListenerLock.RUnlock()

		for _, curr := range updateListeners {
			go curr(in)
		}
	})

	return nil
}

func RegisterForUpdates(listener UpdateListener) {
	updateListenerLock.Lock()
	defer updateListenerLock.Unlock()

	updateListeners = append(updateListeners, listener)
}

func ValidateConfig() []string {
	var errorsFound []string

	if dbKind := viper.GetString(ConfigKeyDBKind); dbKind != "sqlite" {
		log.Error().Str(ConfigKeyDBKind, dbKind).Msgf("invalid %s; must be sqlite", ConfigKeyDBKind)
		errorsFound = append(errorsFound, fmt.Sprintf("invalid `%s`; must be `sqlite`", ConfigKeyDBKind))
	}

	authURL := viper.GetString(ConfigKeyServerAuthURL)
	if authURL == "" {
		log.Error().Msgf("%s is not set", ConfigKeyServerAuthURL)
		errorsFound = append(errorsFound, fmt.Sprintf("`%s` is not set", ConfigKeyServerAuthURL))
	} else if _, err := url.Parse(authURL); err != nil {
		log.Error().Str("auth_url", authURL).Err(err).Msgf("%s is not a valid URL", ConfigKeyServerAuthURL)
		errorsFound = append(errorsFound, fmt.Sprintf("`%s` is not a valid URL", ConfigKeyServerAuthURL))
	}

	if domain := viper.GetString(ConfigKeyServerDomain); domain == "" {
		log.Error().Msgf("%s is not set. This should be set to the naked domain of your server", ConfigKeyServerDomain)
		errorsFound = append(errorsFound, fmt.Sprintf("%s is not set", ConfigKeyServerDomain))
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
