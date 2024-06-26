package salt

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"github.com/gorilla/securecookie"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"golang.org/x/crypto/pbkdf2"
)

const (
	saltLength = 32
	version    = 1
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

	lock sync.Mutex
)

func CheckOrMakeSalt() {
	lock.Lock()
	defer lock.Unlock()
	if salt != nil {
		return
	}

	saltPath := getSaltPath()
	_, err := os.Stat(saltPath)
	if errors.Is(err, os.ErrNotExist) {
		createSalt(saltPath)
	} else {
		readSalt(saltPath)
	}
	saltFile = saltPath
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

	csrfSalt := securecookie.GenerateRandomKey(saltLength)
	if csrfSalt == nil {
		log.Fatal().Msg("could not generate CSRF salt")
	}
	p := &payload{
		Version:    version,
		Signing:    signingSalt,
		Encryption: encryptionSalt,
		CSRF:       csrfSalt,
	}

	encoded, _ := json.Marshal(p)

	err := os.WriteFile(path, encoded, 0600)
	if err != nil {
		log.Fatal().Err(err).Str("salt_path", path).Msg("could not write salt file")
	}

	log.Info().Str("salt_path", path).Msg("generated and wrote salt")

	salt = p
}

func readSalt(path string) {
	data, err := os.ReadFile(path) // #nosec G304 -- has to be read from variable, since this is configurable
	if err != nil {
		log.Warn().Err(err).Str("salt_path", path).Msg("could not read salt, generating new one")
		createSalt(path)
	}

	var read payload
	err = json.Unmarshal(data, &read)
	if err != nil {
		log.Warn().Err(err).Msg("could not unmarshal salt")
		createSalt(path)
	}

	if read.Version != version {
		log.Warn().Int("version", read.Version).Int("expected_version", version).Msg("version mismatch")
		// in the future, we should upgrade in place
		createSalt(path)
	}

	log.Debug().Str("salt_path", path).Msg("loaded salt")

	salt = &read
}

func GenerateSigningKey() []byte {
	CheckOrMakeSalt()
	return pbkdf2.Key([]byte(viper.GetString("server.secret_key")), salt.Signing, 15, 32, sha256.New)
}

func GenerateEncryptionKey() []byte {
	CheckOrMakeSalt()
	return pbkdf2.Key([]byte(viper.GetString("server.secret_key")), salt.Encryption, 15, 32, sha256.New)
}

func GenerateCSRFKey() []byte {
	CheckOrMakeSalt()
	return pbkdf2.Key([]byte(viper.GetString("server.secret_key")), salt.CSRF, 15, 32, sha256.New)
}
