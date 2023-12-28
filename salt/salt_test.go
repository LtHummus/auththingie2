package salt

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetSaltPath(t *testing.T) {
	t.Run("get from env var overriding viper", func(t *testing.T) {
		viper.Set("salt_file", "/test")
		t.Cleanup(func() {
			viper.Set("salt_file", "")
		})
		t.Setenv("SALT_FILE", "/env")

		assert.Equal(t, "/env", getSaltPath())
	})

	t.Run("fallback to viper", func(t *testing.T) {
		viper.Set("salt_file", "/viper")
		t.Setenv("SALT_FILE", "")
		t.Cleanup(func() {
			viper.Set("salt_file", "")
		})

		assert.Equal(t, "/viper", getSaltPath())
	})

	t.Run("fallback to config file path", func(t *testing.T) {
		dir, err := os.MkdirTemp("", "at2testconfig")
		require.NoError(t, err)
		defer os.RemoveAll(dir)

		cfgFile := filepath.Join(dir, "at2.yaml")
		viper.SetConfigFile(cfgFile)

		path := getSaltPath()
		wantedPath := filepath.Join(dir, ".auththingie2_salt")

		assert.Equal(t, wantedPath, path)
	})
}

func TestCheckOrMakeSalt(t *testing.T) {
	t.Run("create new salt file if doesn't exist", func(t *testing.T) {
		salt = nil
		saltDir, err := os.MkdirTemp("", "at2salttest")
		require.NoError(t, err)
		defer os.RemoveAll(saltDir)

		saltFile := filepath.Join(saltDir, "at2testsalt.json")
		t.Setenv("SALT_FILE", saltFile)

		_, err = os.Stat(saltFile)
		assert.ErrorIs(t, err, os.ErrNotExist)

		CheckOrMakeSalt()

		_, err = os.Stat(saltFile)
		assert.NoError(t, err)

		var saltData payload
		f, err := os.Open(saltFile)
		require.NoError(t, err)
		defer f.Close()

		err = json.NewDecoder(f).Decode(&saltData)
		assert.NoError(t, err)

		assert.NotEmpty(t, saltData.CSRF)
		assert.NotEmpty(t, saltData.Signing)
		assert.NotEmpty(t, saltData.Encryption)
		assert.Equal(t, 1, saltData.Version)
	})

	t.Run("read salt from file that exists", func(t *testing.T) {
		salt = nil
		saltDir, err := os.MkdirTemp("", "at2salttest")
		require.NoError(t, err)
		defer os.RemoveAll(saltDir)

		saltFile := filepath.Join(saltDir, "at2testsalt.json")
		t.Setenv("SALT_FILE", saltFile)

		data := `{"version":1,"signing":"sO6neG1lW_mYqH6jLaq3uBHsTxaH2ig201UEYXOIHJo","encryption":"JI1__-bfAy52ieVtSYRK9R8qpVo8MvU7P6uPrG5Wa0Y","csrf":"rfMB_QJW1D4ceVQq-SZoVLHb2yMuAEbSrMP8Zz2Kln4"}`
		err = os.WriteFile(saltFile, []byte(data), 0600)
		require.NoError(t, err)

		CheckOrMakeSalt()

		viper.Set("server.secret_key", "test")
		t.Cleanup(func() {
			viper.Set("server.secret_key", "")
		})

		assert.Equal(t, "297a0fa07e6b51111c25d01b51ea359bf7b81544eb0e79361b3f979cbc21fd3c", hex.EncodeToString(GenerateSigningKey()))
		assert.Equal(t, "1b35bb894cfffd8128840444a15840d29c72deeb2a0d6bd24b497fe8c3a39cf2", hex.EncodeToString(GenerateCSRFKey()))
		assert.Equal(t, "41a1f86617b05c33bdff87b2504873cdc2db58d576d6ca846f88201bda9ba796", hex.EncodeToString(GenerateEncryptionKey()))
	})

	t.Run("recreate salt file on wrong version", func(t *testing.T) {
		salt = nil
		saltDir, err := os.MkdirTemp("", "at2salttest")
		require.NoError(t, err)
		defer os.RemoveAll(saltDir)

		saltFile := filepath.Join(saltDir, "at2testsalt.json")
		t.Setenv("SALT_FILE", saltFile)

		data := `{"version":0,"signing":"sO6neG1lW_mYqH6jLaq3uBHsTxaH2ig201UEYXOIHJo","encryption":"JI1__-bfAy52ieVtSYRK9R8qpVo8MvU7P6uPrG5Wa0Y","csrf":"rfMB_QJW1D4ceVQq-SZoVLHb2yMuAEbSrMP8Zz2Kln4"}`
		err = os.WriteFile(saltFile, []byte(data), 0600)
		require.NoError(t, err)

		CheckOrMakeSalt()

		changedData, err := os.ReadFile(saltFile)
		require.NoError(t, err)

		var payload struct {
			Version int `json:"version"`
		}
		err = json.Unmarshal(changedData, &payload)
		assert.NoError(t, err)

		assert.Equal(t, 1, payload.Version)

	})

}
