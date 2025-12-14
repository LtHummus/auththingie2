package salt

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"golang.org/x/crypto/pbkdf2"
)

const (
	saltLength = 32
	version    = 1

	defaultIterations     = 600000
	defaultIterationsTest = 15
)

func getSaltPath() string {
	var saltPath string

	saltPath = os.Getenv("SALT_FILE")
	if saltPath != "" {
		return saltPath
	}

	saltPath = viper.GetString("salt_file")
	if saltPath != "" {
		return saltPath
	}

	return filepath.Join(filepath.Dir(viper.ConfigFileUsed()), ".auththingie2_salt")

}

var (
	salt     *payload
	saltFile string

	signingKey    []byte
	encryptionKey []byte

	lock sync.Mutex
)

func CheckOrMakeSalt() {
	lock.Lock()
	defer lock.Unlock()
	if salt != nil {
		return
	}

	saltPath := getSaltPath()
	saltStats, err := os.Stat(saltPath)
	if errors.Is(err, os.ErrNotExist) {
		createSalt(saltPath)
	} else if err != nil {
		log.Warn().Str("salt_path", saltPath).Msg("could not stat salt file. trying to regenerate")
		createSalt(saltPath)
	} else if saltStats.Mode().Perm() != 0600 {
		log.Warn().Str("salt_path", saltPath).Msg("salt file has improper permissions -- should be 0600")
	}
	readSalt(saltPath)

	saltFile = saltPath

	iterationCount := getIterationCount()

	start := time.Now()
	signingKey = pbkdf2.Key([]byte(viper.GetString("server.secret_key")), salt.Signing, iterationCount, 32, sha256.New)
	encryptionKey = pbkdf2.Key([]byte(viper.GetString("server.secret_key")), salt.Encryption, iterationCount, 32, sha256.New)

	log.Info().Int("iteration_count", iterationCount).Dur("key_generation_time", time.Since(start)).Msg("generated signing and encryption keys")
}

func GetSaltPath() string {
	CheckOrMakeSalt()
	return saltFile
}

func createSalt(path string) {
	signingSalt := securecookie.GenerateRandomKey(saltLength)
	if signingSalt == nil {
		log.Fatal().Msg("could not generate signing salt")
	}

	encryptionSalt := securecookie.GenerateRandomKey(saltLength)
	if encryptionSalt == nil {
		log.Fatal().Msg("could not generate encryption salt")
	}

	p := &payload{
		Version:    version,
		Signing:    signingSalt,
		Encryption: encryptionSalt,
	}

	encoded, _ := json.Marshal(p)

	err := os.MkdirAll(filepath.Dir(path), 0700)
	if err != nil {
		log.Warn().Err(err).Str("salt_directory", filepath.Dir(path)).Str("salt_path", path).Msg("could not create parent directories for salt file. Continuing anyway, but this will make sessions not work across restarts")
	}

	err = os.WriteFile(path, encoded, 0600)
	if err != nil {
		log.Warn().Err(err).Str("salt_path", path).Msg("could not write salt file. Continuing anyway, but this will make sessions not work across restarts")
	} else {
		log.Info().Str("salt_path", path).Msg("generated and wrote salt")
	}

	salt = p
}

func readSalt(path string) {
	data, err := os.ReadFile(path) // #nosec G304 -- has to be read from variable, since this is configurable
	if err != nil {
		log.Warn().Err(err).Str("salt_path", path).Msg("could not read salt, generating new one")
		createSalt(path)
		return
	}

	var read payload
	err = json.Unmarshal(data, &read)
	if err != nil {
		log.Warn().Err(err).Msg("could not unmarshal salt")
		createSalt(path)
		return
	}

	if read.Version != version {
		log.Warn().Int("version", read.Version).Int("expected_version", version).Msg("version mismatch")
		// in the future, we should upgrade in place
		createSalt(path)
		return
	}

	log.Debug().Str("salt_path", path).Msg("loaded salt")

	salt = &read
}

func getIterationCount() int {
	if testing.Testing() {
		return defaultIterationsTest
	}
	return defaultIterations
}

func GenerateSigningKey() []byte {
	CheckOrMakeSalt()
	return signingKey
}

func GenerateEncryptionKey() []byte {
	CheckOrMakeSalt()
	return encryptionKey
}
