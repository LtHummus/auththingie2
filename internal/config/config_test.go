package config

import (
	"strings"
	"sync/atomic"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lthummus/auththingie2/internal/argon"
)

func prepareViper(t *testing.T, config string) {
	viper.SetConfigType("yaml")
	err := viper.ReadConfig(strings.NewReader(config))
	require.NoError(t, err)
	t.Cleanup(func() {
		viper.Reset()
	})
}

func TestValidateConfig(t *testing.T) {
	t.Run("everything is good", func(t *testing.T) {
		prepareViper(t, `
db:
    kind: sqlite
server:
    auth_url: https://auth.example.com
    domain: example.com
`)

		errors := ValidateConfig()
		assert.Empty(t, errors)
	})

	t.Run("wrong db kind", func(t *testing.T) {
		prepareViper(t, `
db:
    kind: postgresql
server:
    auth_url: https://auth.example.com
    domain: example.com
`)
		errors := ValidateConfig()
		assert.Len(t, errors, 1)

		assert.Equal(t, "invalid `db.kind`; must be `sqlite`", errors[0])
	})

	t.Run("missing auth_url", func(t *testing.T) {
		prepareViper(t, `
db:
    kind: sqlite
server:
    domain: example.com
`)
		errors := ValidateConfig()
		assert.Len(t, errors, 1)

		assert.Equal(t, "`server.auth_url` is not set", errors[0])
	})

	t.Run("invalid auth_url", func(t *testing.T) {
		prepareViper(t, `
db:
    kind: sqlite
server:
    auth_url: :aaa
    domain: example.com
`)
		errors := ValidateConfig()
		assert.Len(t, errors, 1)

		assert.Equal(t, "`server.auth_url` is not a valid URL", errors[0])
	})

	t.Run("missing domain", func(t *testing.T) {
		prepareViper(t, `
db:
    kind: sqlite
server:
    auth_url: https://auth.example.com
`)
		errors := ValidateConfig()
		assert.Len(t, errors, 1)

		assert.Equal(t, "server.domain is not set", errors[0])
	})

	t.Run("multiple things wrong", func(t *testing.T) {
		prepareViper(t, `
db:
    kind: mysql
server:
    auth_url: :bad
`)
		errors := ValidateConfig()
		assert.Len(t, errors, 3)
	})
}

func TestIsDocker(t *testing.T) {
	t.Run("env var is unset", func(t *testing.T) {
		assert.False(t, IsDocker())
	})

	t.Run("env var is set", func(t *testing.T) {
		t.Setenv("AT2_MODE", "docker")
		assert.True(t, IsDocker())
	})
}

func TestIsProductionMode(t *testing.T) {
	t.Run("env var is unset", func(t *testing.T) {
		assert.False(t, IsProductionMode())
	})

	t.Run("env var is set to something non-prod", func(t *testing.T) {
		t.Setenv("ENVIRONMENT", "test")
		assert.False(t, IsProductionMode())
	})

	t.Run("env var indicates prod mode", func(t *testing.T) {
		t.Setenv("ENVIRONMENT", "prod")
		assert.True(t, IsProductionMode())
	})
}

func TestIsDebugLoggingEnabled(t *testing.T) {
	t.Run("env var is unset", func(t *testing.T) {
		assert.False(t, IsDebugLoggingEnabled())
	})

	t.Run("env var is set to something else", func(t *testing.T) {
		t.Setenv("DEBUG_LOG", "false")
		assert.False(t, IsDebugLoggingEnabled())
	})

	t.Run("env var says yes", func(t *testing.T) {
		t.Setenv("DEBUG_LOG", "true")
		assert.True(t, IsDebugLoggingEnabled())
	})
}

func TestEnableDebugPage(t *testing.T) {
	t.Cleanup(func() {
		atomic.StoreUint32(&DebugFlagOverride, 0)
	})

	t.Run("defaults for prod mode", func(t *testing.T) {
		t.Setenv("ENVIRONMENT", "prod")
		assert.False(t, EnableDebugPage())
	})

	t.Run("defaults for non-prod", func(t *testing.T) {
		assert.True(t, EnableDebugPage())
	})

	t.Run("explicitly enable in prod", func(t *testing.T) {
		t.Setenv("ENVIRONMENT", "prod")
		t.Setenv("ENABLE_DEBUG_PAGE", "true")
		assert.True(t, EnableDebugPage())
	})

	t.Run("prod mode and flag is set", func(t *testing.T) {
		t.Setenv("ENVIRONMENT", "prod")
		atomic.StoreUint32(&DebugFlagOverride, 1)
		assert.True(t, EnableDebugPage())
	})

}

func TestCleanupDefaultArgon(t *testing.T) {
	t.Run("complete cleanup", func(t *testing.T) {
		t.Cleanup(func() {
			viper.Reset()
		})

		viper.SetDefault(argon.MemoryKey, argon.DefaultMemory)
		viper.SetDefault(argon.IterationKey, argon.DefaultIterations)
		viper.SetDefault(argon.ParallelismKey, argon.DefaultParallelism)
		viper.SetDefault(argon.SaltLengthKey, argon.DefaultSaltLength)
		viper.SetDefault(argon.KeyLengthKey, argon.DefaultKeyLength)

		everything := viper.AllSettings()

		cleanDefaultArgon(everything)

		assert.Len(t, everything, 0)
	})

	t.Run("leave only non-default keys", func(t *testing.T) {
		t.Cleanup(func() {
			viper.Reset()
		})

		viper.SetDefault(argon.MemoryKey, argon.DefaultMemory)
		viper.SetDefault(argon.IterationKey, argon.DefaultIterations)
		viper.SetDefault(argon.ParallelismKey, 56)
		viper.SetDefault(argon.SaltLengthKey, argon.DefaultSaltLength)
		viper.SetDefault(argon.KeyLengthKey, 952348)

		everything := viper.AllSettings()

		cleanDefaultArgon(everything)

		assert.Len(t, everything, 1)

		securityBlock := everything["security"].(map[string]any)
		assert.Len(t, securityBlock, 1)

		argonBlock := securityBlock["argon2"].(map[string]any)
		assert.Len(t, argonBlock, 2)

		assert.Equal(t, 952348, argonBlock["keylength"])
		assert.Equal(t, 56, argonBlock["parallelism"])
	})

	t.Run("leave other security things alone", func(t *testing.T) {
		t.Cleanup(func() {
			viper.Reset()
		})

		viper.SetDefault(argon.MemoryKey, argon.DefaultMemory)
		viper.SetDefault(argon.IterationKey, argon.DefaultIterations)
		viper.SetDefault(argon.ParallelismKey, argon.DefaultParallelism)
		viper.SetDefault(argon.SaltLengthKey, argon.DefaultSaltLength)
		viper.SetDefault(argon.KeyLengthKey, argon.DefaultKeyLength)

		viper.Set("security.foo", "hello")

		everything := viper.AllSettings()

		cleanDefaultArgon(everything)

		assert.Len(t, everything, 1)
	})
}
