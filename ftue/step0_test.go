package ftue

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lthummus/auththingie2/render"
)

func TestFtueEnv_HandleFTUEStep0GET(t *testing.T) {
	render.Init()

	t.Run("basic case in docker", func(t *testing.T) {
		_, _, e := makeTestEnv(t)

		t.Setenv("AT2_MODE", "docker")

		r := httptest.NewRequest(http.MethodGet, "https://auth.example.com/ftue/step0", nil)
		w := httptest.NewRecorder()

		e.buildMux(StepStartFromBeginning).ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), `<input type="text" name="port" id="port-field" required aria-label="Server Port" value="9000" />`)
		assert.Contains(t, w.Body.String(), `<input type="radio" id="slash-config-radio" name="config_file_preset" value="slashconfig"  checked  />`)
		assert.Contains(t, w.Body.String(), `<input type="radio" id="cwd-radio" name="config_file_preset" value="pwd"  />`)
		assert.Contains(t, w.Body.String(), `<input type="text" name="domain" id="domain-field" required aria-label="Server Domain" value="example.com" autocomplete="off" autocorrect="off" spellcheck="off" />`)
		assert.Contains(t, w.Body.String(), `<input type="text" name="auth_url" id="auth-url-field" required aria-label="Auth URL Field" value="auth.example.com" autocomplete="off" autocorrect="off" spellcheck="off" />`)
	})

	t.Run("basic case outside docker", func(t *testing.T) {
		_, _, e := makeTestEnv(t)

		r := httptest.NewRequest(http.MethodGet, "https://auth.example.com/ftue/step0", nil)
		w := httptest.NewRecorder()

		e.buildMux(StepStartFromBeginning).ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), `<input type="text" name="port" id="port-field" required aria-label="Server Port" value="9000" />`)
		assert.Contains(t, w.Body.String(), `<input type="radio" id="slash-config-radio" name="config_file_preset" value="slashconfig"  />`)
		assert.Contains(t, w.Body.String(), `<input type="radio" id="cwd-radio" name="config_file_preset" value="pwd"  checked  />`)
		assert.Contains(t, w.Body.String(), `<input type="text" name="domain" id="domain-field" required aria-label="Server Domain" value="example.com" autocomplete="off" autocorrect="off" spellcheck="off" />`)
		assert.Contains(t, w.Body.String(), `<input type="text" name="auth_url" id="auth-url-field" required aria-label="Auth URL Field" value="auth.example.com" autocomplete="off" autocorrect="off" spellcheck="off" />`)

	})

	t.Run("make sure we've attached security headers", func(t *testing.T) {
		_, _, e := makeTestEnv(t)

		t.Setenv("AT2_MODE", "docker")

		r := httptest.NewRequest(http.MethodGet, "https://auth.example.com/ftue/step0", nil)
		w := httptest.NewRecorder()

		e.buildMux(StepStartFromBeginning).ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Equal(t, "DENY", w.Result().Header.Get("X-Frame-Options"))
		assert.Equal(t, "nosniff", w.Result().Header.Get("X-Content-Type-Options"))
		assert.Equal(t, "strict-origin-when-cross-origin", w.Result().Header.Get("Referrer-Policy"))
	})
}

func TestFtueEnv_HandleFTUEStep0POST(t *testing.T) {
	render.Init()

	t.Run("CSRF detection", func(t *testing.T) {
		_, _, e := makeTestEnv(t)

		tmpDir, err := os.MkdirTemp("", "testdatadb")
		require.NoError(t, err)

		t.Cleanup(func() {
			os.RemoveAll(tmpDir)
			viper.Reset()
		})

		configFilePath := filepath.Join(tmpDir, "auththingie2.yaml")
		dbPath := filepath.Join(tmpDir, "at2.db")

		v := url.Values{}
		v.Add("port", "9000")
		v.Add("domain", "example.com")
		v.Add("auth_url", "auth.example.com")
		v.Add("config_file_preset", "custom")
		v.Add("config_path", configFilePath)
		v.Add("db_path", dbPath)

		r, err := http.NewRequest(http.MethodPost, "https://auth.example.com/ftue/step0", strings.NewReader(v.Encode()))
		require.NoError(t, err)
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Sec-Fetch-Site", "cross-origin")
		w := httptest.NewRecorder()

		e.buildMux(StepStartFromBeginning).ServeHTTP(w, r)

		assert.Equal(t, http.StatusForbidden, w.Result().StatusCode)
	})

	t.Run("a case with everything", func(t *testing.T) {
		_, _, e := makeTestEnv(t)

		tmpDir, err := os.MkdirTemp("", "testdatadb")
		require.NoError(t, err)

		t.Cleanup(func() {
			os.RemoveAll(tmpDir)
			viper.Reset()
		})

		configFilePath := filepath.Join(tmpDir, "auththingie2.yaml")
		dbPath := filepath.Join(tmpDir, "at2.db")

		v := url.Values{}
		v.Add("port", "9000")
		v.Add("domain", "example.com")
		v.Add("auth_url", "auth.example.com")
		v.Add("config_file_preset", "custom")
		v.Add("config_path", configFilePath)
		v.Add("db_path", dbPath)

		r, err := http.NewRequest(http.MethodPost, "https://auth.example.com/ftue/step0", strings.NewReader(v.Encode()))
		require.NoError(t, err)
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		e.buildMux(StepStartFromBeginning).ServeHTTP(w, r)

		assert.Equal(t, http.StatusFound, w.Result().StatusCode)
		redirectURL, err := w.Result().Location()
		require.NoError(t, err)
		assert.Equal(t, "/ftue/step1", redirectURL.Path)

		assert.FileExists(t, configFilePath)
		assert.FileExists(t, dbPath)

		assert.Equal(t, dbPath, viper.GetString("db.file"))
		assert.Equal(t, "sqlite", viper.GetString("db.kind"))
		assert.Equal(t, "example.com", viper.GetString("server.domain"))
		assert.Equal(t, "auth.example.com", viper.GetString("server.auth_url"))
		assert.Equal(t, uint64(9000), viper.GetUint64("server.port"))

		assert.NotNil(t, e.database)
		assert.NotNil(t, e.analyzer)
	})
}
