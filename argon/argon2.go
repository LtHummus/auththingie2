package argon

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/gorilla/securecookie"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"golang.org/x/crypto/argon2"
)

const (
	memoryKey      = "security.argon2.memory"
	iterationKey   = "security.argon2.iterations"
	parallelismKey = "security.argon2.parallelism"
	saltLengthKey  = "security.argon2.saltLength"
	keyLengthKey   = "security.argon2.keyLength"

	defaultMemory      = 64 * 1024
	defaultIterations  = 3
	defaultParallelism = 2
	defaultSaltLength  = 16
	defaultKeyLength   = 32
)

var (
	ErrInvalidHash    = errors.New("argon2: ValidatePassword: invalid password hash")
	ErrInvalidVersion = errors.New("argon2: ValidatePassword: incorrect version of argon2")
	ErrWrongPassword  = errors.New("argon2: ValidatePassword: wrong password")
)

func init() {
	viper.SetDefault(memoryKey, defaultMemory)
	viper.SetDefault(iterationKey, defaultIterations)
	viper.SetDefault(parallelismKey, defaultParallelism)
	viper.SetDefault(saltLengthKey, defaultSaltLength)
	viper.SetDefault(keyLengthKey, defaultKeyLength)
}

func GenerateFromPassword(password string) (string, error) {
	iterationCount := viper.GetUint32(iterationKey)
	memoryCount := viper.GetUint32(memoryKey)
	parallelismCount, err := safeCastUint8(viper.GetInt(parallelismKey))
	if err != nil {
		return "", fmt.Errorf("argon2: GenerateFromPassword: invalid argon configuration: %w", err)
	}
	keyLength := viper.GetUint32(keyLengthKey)
	saltLength := viper.GetInt(saltLengthKey)

	log.Debug().
		Uint32("iteration_count", iterationCount).
		Uint32("memory_count", memoryCount).
		Uint8("parallelism_count", parallelismCount).
		Uint32("key_length", keyLength).
		Int("salt_length", saltLength).
		Msg("hashing password with argon2")

	generatedSalt := securecookie.GenerateRandomKey(saltLength)
	if generatedSalt == nil {
		log.Error().Int("salt_length_bytes", viper.GetInt(saltLengthKey)).Msg("could not generate random salt")
		return "", errors.New("could not generate salt")
	}

	hash := argon2.IDKey([]byte(password), generatedSalt, iterationCount, memoryCount, parallelismCount, keyLength)

	encodedSalt := base64.RawStdEncoding.EncodeToString(generatedSalt)
	encodedHash := base64.RawStdEncoding.EncodeToString(hash)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		memoryCount,
		iterationCount,
		parallelismCount,
		encodedSalt,
		encodedHash), nil
}

func NeedsMigration(encodedHash string) bool {
	if viper.GetBool("security.disable_migrate_on_login") {
		return false
	}

	if !strings.HasPrefix(encodedHash, "$argon2id$") {
		return true
	}

	memory, iterations, parallelism, _, saltLength, _, keyLength, err := decodeHashParts(encodedHash)
	if err != nil {
		log.Warn().Err(err).Msg("invalid argon2 hash")
		return true
	}

	wantedParallism, err := safeCastUint8(viper.GetInt(parallelismKey))
	if err != nil {
		log.Warn().Err(err).Msg("invalid argon configuration. parallelism must fit in to a uint8")
	}

	return memory != viper.GetUint32(memoryKey) ||
		iterations != viper.GetUint32(iterationKey) ||
		parallelism != wantedParallism ||
		saltLength != viper.GetUint32(saltLengthKey) ||
		keyLength != viper.GetUint32(keyLengthKey)
}

func decodeHashParts(encodedHash string) (uint32, uint32, uint8, []byte, uint32, []byte, uint32, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return 0, 0, 0, nil, 0, nil, 0, ErrInvalidHash
	}

	var version int
	_, err := fmt.Sscanf(parts[2], "v=%d", &version)
	if err != nil {
		return 0, 0, 0, nil, 0, nil, 0, ErrInvalidHash
	}

	if version != argon2.Version {
		log.Warn().Int("expected_version", argon2.Version).Int("hash_version", version).Msg("invalid argon2 version")
		return 0, 0, 0, nil, 0, nil, 0, ErrInvalidVersion
	}

	var memory, iterations uint32
	var parallelism uint8

	_, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism)
	if err != nil {
		return 0, 0, 0, nil, 0, nil, 0, err
	}

	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil {
		return 0, 0, 0, nil, 0, nil, 0, err
	}
	saltLength, err := safeCastUint32(len(salt))
	if err != nil {
		return 0, 0, 0, nil, 0, nil, 0, fmt.Errorf("argon2: decodeHashParts: invalid salt length: %w", err)
	}

	hash, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil {
		return 0, 0, 0, nil, 0, nil, 0, err
	}
	keyLength, err := safeCastUint32(len(hash))
	if err != nil {
		return 0, 0, 0, nil, 0, nil, 0, fmt.Errorf("argon2: decodeHashParts: invalid key length: %w", err)
	}

	return memory, iterations, parallelism, salt, saltLength, hash, keyLength, nil

}

func ValidatePassword(password, encodedHash string) error {
	memory, iterations, parallelism, salt, _, hash, keyLength, err := decodeHashParts(encodedHash)
	if err != nil {
		return err
	}

	calcedHash := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, keyLength)

	if subtle.ConstantTimeCompare(hash, calcedHash) != 1 {
		return ErrWrongPassword
	}

	return nil
}
