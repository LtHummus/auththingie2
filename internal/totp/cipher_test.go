package totp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncryptDecrypt(t *testing.T) {
	setupSalts(t)

	t.Run("basic example", func(t *testing.T) {
		payload := []byte{0x00, 0x01, 0x02, 0x03}

		enc, err := encrypt(payload, []byte{'s', 'a', 'm', 'p', 'l', 'e'})
		assert.NoError(t, err)

		dec, err := decrypt(enc, []byte{'s', 'a', 'm', 'p', 'l', 'e'})
		assert.NoError(t, err)

		assert.Equal(t, payload, dec)
	})
}
