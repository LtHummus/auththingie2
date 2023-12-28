package config

import (
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func prepareViper(t *testing.T, config string) {
	viper.SetConfigType("yaml")
	viper.ReadConfig(strings.NewReader(config))
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
