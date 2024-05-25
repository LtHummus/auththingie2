package totp

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lthummus/auththingie2/salt"
)

func setupSalts(t *testing.T) {
	saltDir, err := os.MkdirTemp("", "attestsalt")
	require.NoError(t, err)

	t.Cleanup(func() {
		os.RemoveAll(saltDir)
	})

	t.Setenv("SALT_FILE", filepath.Join(saltDir, "attestsalt"))

	salt.CheckOrMakeSalt()
}

func TestEnrollmentTicket_Encode(t *testing.T) {
	setupSalts(t)

	t.Run("simple case", func(t *testing.T) {
		et := GenerateEnrollmentTicket("sampleuserID", "sampleseed")
		encoded, err := et.Encode()
		assert.NoError(t, err)

		et2, err := DecodeEnrollmentTicket(encoded)
		assert.NoError(t, err)
		assert.Equal(t, "sampleuserID", et2.UserID)
		assert.Equal(t, "sampleseed", et2.Seed)
	})
}

func TestDecodeEnrollmentTicket(t *testing.T) {
	setupSalts(t)

	t.Run("error when decoding non-enrollment ticket", func(t *testing.T) {
		lt := GenerateLoginTicket("sample", "https://example.com")
		encoded, err := lt.Encode()
		require.NoError(t, err)

		_, err = DecodeEnrollmentTicket(encoded)
		assert.Error(t, err)
	})
}
