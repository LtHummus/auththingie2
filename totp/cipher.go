package totp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"

	"github.com/lthummus/auththingie2/salt"
)

func encrypt(payload []byte, kind []byte) (string, error) {
	block, err := aes.NewCipher(salt.GenerateEncryptionKey())
	if err != nil {
		return "", fmt.Errorf("totp: encrypt: could not initialze AES: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("totp: encrypt: could not initialze AEAD: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("totp: encrypt: could not generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, payload, kind)
	completePayload := append(nonce, ciphertext...)

	return base64.RawURLEncoding.EncodeToString(completePayload), nil
}

func decrypt(encodedCiphertext string, kind []byte) ([]byte, error) {
	bulkCiphertext, err := base64.RawURLEncoding.DecodeString(encodedCiphertext)
	if err != nil {
		return nil, fmt.Errorf("totp: decrypt: could not decode base64: %w", err)
	}

	block, err := aes.NewCipher(salt.GenerateEncryptionKey())
	if err != nil {
		return nil, fmt.Errorf("totp: decrypt: could not initialize AES: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("totp: decrypt: could not initialize AEAD: %w", err)
	}

	nonce := bulkCiphertext[:gcm.NonceSize()]
	ciphertext := bulkCiphertext[gcm.NonceSize():]

	decoded, err := gcm.Open(nil, nonce, ciphertext, kind)
	if err != nil {
		return nil, fmt.Errorf("totp: decrypt: could not decrypt: %w", err)
	}

	return decoded, nil
}
