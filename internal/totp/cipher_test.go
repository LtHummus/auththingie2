package totp

import (
	"encoding/base64"
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

	t.Run("do not panic on too short ciphertexts", func(t *testing.T) {
		shortCiphertext := base64.RawURLEncoding.EncodeToString([]byte{0x00, 0x01, 0x02})

		dec, err := decrypt(shortCiphertext, []byte{'s', 'a', 'm', 'p', 'e', 'e'})
		assert.Error(t, err)
		assert.Nil(t, dec)
	})
}
