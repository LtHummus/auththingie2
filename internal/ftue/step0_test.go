package ftue

import (
	"fmt"
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

	"github.com/lthummus/auththingie2/internal/config"
	"github.com/lthummus/auththingie2/internal/ftue/iprange"
	"github.com/lthummus/auththingie2/internal/render"
)

func TestFtueEnv_HandleFTUEStep0GET(t *testing.T) {
	render.Init()

	t.Run("basic case in docker", func(t *testing.T) {
		_, _, _, e := makeTestEnv(t)

		t.Setenv("AT2_MODE", "docker")

		r := httptest.NewRequest(http.MethodGet, "https://auth.example.com/ftue/step0", nil)
		attachSetupAuthCookie(r, e)
		w := httptest.NewRecorder()

		e.buildMux(StepStartFromBeginning).ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), `<input type="text" name="port" id="port-field" required aria-label="Server Port" value="9000" />`)
		assert.Contains(t, w.Body.String(), `<input type="radio" id="slash-config-radio" name="config_file_preset" value="slashconfig"  checked  />`)
		assert.Contains(t, w.Body.String(), `<input type="radio" id="cwd-radio" name="config_file_preset" value="pwd"  />`)
		assert.Contains(t, w.Body.String(), `<input type="text" name="domain" id="domain-field" required aria-label="Server Domain" value="example.com" autocomplete="off" autocorrect="off" spellcheck="off" />`)
		assert.Contains(t, w.Body.String(), `<input type="text" name="auth_url" id="auth-url-field" required aria-label="Auth URL Field" value="https://auth.example.com" autocomplete="off" autocorrect="off" spellcheck="off" />`)
	})

	t.Run("basic case outside docker", func(t *testing.T) {
		_, _, _, e := makeTestEnv(t)

		r := httptest.NewRequest(http.MethodGet, "https://auth.example.com/ftue/step0", nil)
		attachSetupAuthCookie(r, e)
		w := httptest.NewRecorder()

		e.buildMux(StepStartFromBeginning).ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), `<input type="text" name="port" id="port-field" required aria-label="Server Port" value="9000" />`)
		assert.Contains(t, w.Body.String(), `<input type="radio" id="slash-config-radio" name="config_file_preset" value="slashconfig"  />`)
		assert.Contains(t, w.Body.String(), `<input type="radio" id="cwd-radio" name="config_file_preset" value="pwd"  checked  />`)
		assert.Contains(t, w.Body.String(), `<input type="text" name="domain" id="domain-field" required aria-label="Server Domain" value="example.com" autocomplete="off" autocorrect="off" spellcheck="off" />`)
		assert.Contains(t, w.Body.String(), `<input type="text" name="auth_url" id="auth-url-field" required aria-label="Auth URL Field" value="https://auth.example.com" autocomplete="off" autocorrect="off" spellcheck="off" />`)

	})

	t.Run("make sure we've attached security headers", func(t *testing.T) {
		_, _, _, e := makeTestEnv(t)

		t.Setenv("AT2_MODE", "docker")

		r := httptest.NewRequest(http.MethodGet, "https://auth.example.com/ftue/step0", nil)
		attachSetupAuthCookie(r, e)
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
		_, _, _, e := makeTestEnv(t)

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
		v.Add("auth_url", "https://auth.example.com")
		v.Add("config_file_preset", "custom")
		v.Add("config_path", configFilePath)
		v.Add("db_path", dbPath)

		r, err := http.NewRequest(http.MethodPost, "https://auth.example.com/ftue/step0", strings.NewReader(v.Encode()))
		require.NoError(t, err)
		attachSetupAuthCookie(r, e)
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Sec-Fetch-Site", "cross-origin")
		w := httptest.NewRecorder()

		e.buildMux(StepStartFromBeginning).ServeHTTP(w, r)

		assert.Equal(t, http.StatusForbidden, w.Result().StatusCode)
	})

	t.Run("0.0.0.0/0 is not allowed as a trusted network", func(t *testing.T) {
		_, _, _, e := makeTestEnv(t)

		tmpDir, err := os.MkdirTemp("", "testdatadb")
		require.NoError(t, err)

		t.Cleanup(func() {
			os.RemoveAll(tmpDir)
		})

		configFilePath := filepath.Join(tmpDir, "auththingie2.yaml")
		dbPath := filepath.Join(tmpDir, "at2.db")

		v := url.Values{}
		v.Add("port", "9000")
		v.Add("domain", "example.com")
		v.Add("auth_url", "https://auth.example.com")
		v.Add("config_file_preset", "custom")
		v.Add("config_path", configFilePath)
		v.Add("db_path", dbPath)
		v.Add("custom_trusted_network", "0.0.0.0/0")

		r, err := http.NewRequest(http.MethodPost, "https://auth.example.com/ftue/step0", strings.NewReader(v.Encode()))
		require.NoError(t, err)
		attachSetupAuthCookie(r, e)
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		e.buildMux(StepStartFromBeginning).ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "global-trust is not allowed (e.g. 0.0.0.0/0 or ::/0)")
	})

	t.Run("no trusted configuration", func(t *testing.T) {
		_, _, _, e := makeTestEnv(t)

		tmpDir, err := os.MkdirTemp("", "testdatadb")
		require.NoError(t, err)

		t.Cleanup(func() {
			os.RemoveAll(tmpDir)
		})

		configFilePath := filepath.Join(tmpDir, "auththingie2.yaml")
		dbPath := filepath.Join(tmpDir, "at2.db")

		v := url.Values{}
		v.Add("port", "9000")
		v.Add("domain", "example.com")
		v.Add("auth_url", "https://auth.example.com")
		v.Add("config_file_preset", "custom")
		v.Add("config_path", configFilePath)
		v.Add("db_path", dbPath)

		r, err := http.NewRequest(http.MethodPost, "https://auth.example.com/ftue/step0", strings.NewReader(v.Encode()))
		require.NoError(t, err)
		attachSetupAuthCookie(r, e)
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		e.buildMux(StepStartFromBeginning).ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "You must configure some sort of trusted proxy setup -- either docker or trusted networks")
	})

	t.Run("hands the user's input back when validation fails", func(t *testing.T) {
		_, _, _, e := makeTestEnv(t)

		tmpDir, err := os.MkdirTemp("", "testdatadb")
		require.NoError(t, err)

		t.Cleanup(func() {
			os.RemoveAll(tmpDir)
		})

		v := url.Values{}
		v.Add("port", "not-a-port") // forces a validation error
		v.Add("domain", "example.com")
		v.Add("auth_url", "https://auth.example.com")
		v.Add("config_file_preset", "custom")
		v.Add("config_path", filepath.Join(tmpDir, "auththingie2.yaml"))
		v.Add("db_path", filepath.Join(tmpDir, "at2.db"))
		v.Add("custom_trusted_network", "10.0.0.0/16")

		r, err := http.NewRequest(http.MethodPost, "https://auth.example.com/ftue/step0", strings.NewReader(v.Encode()))
		require.NoError(t, err)
		attachSetupAuthCookie(r, e)
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		e.buildMux(StepStartFromBeginning).ServeHTTP(w, r)

		body := w.Body.String()
		assert.Equal(t, http.StatusOK, w.Result().StatusCode)

		assert.Contains(t, body, `aria-label="Server Port" value="not-a-port"`)
		assert.NotContains(t, body, `aria-label="Server Port" value="0"`)
		assert.Contains(t, body, `id="custom-trusted-network" value="10.0.0.0/16"`)
		assert.NotContains(t, body, "You must configure some sort of trusted proxy setup")
	})

	t.Run("re-checks previously selected networks when validation fails", func(t *testing.T) {
		// this uses the system IP ranges...which I'm not crazy about.... will this even work on GitHub runners? If this
		// comment is still here ... then yes, it will
		candidates, _ := iprange.DetectInternalIPRange()
		if len(candidates) == 0 {
			t.Skip("no private network ranges detected on this host")
		}
		selected := candidates[0].Network.String()

		_, _, _, e := makeTestEnv(t)

		tmpDir, err := os.MkdirTemp("", "testdatadb")
		require.NoError(t, err)

		t.Cleanup(func() {
			os.RemoveAll(tmpDir)
		})

		v := url.Values{}
		v.Add("port", "not-a-port") // forces a validation error
		v.Add("domain", "example.com")
		v.Add("auth_url", "https://auth.example.com")
		v.Add("config_file_preset", "custom")
		v.Add("config_path", filepath.Join(tmpDir, "auththingie2.yaml"))
		v.Add("db_path", filepath.Join(tmpDir, "at2.db"))
		v.Add("trusted_networks", selected)

		r, err := http.NewRequest(http.MethodPost, "https://auth.example.com/ftue/step0", strings.NewReader(v.Encode()))
		require.NoError(t, err)
		attachSetupAuthCookie(r, e)
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		e.buildMux(StepStartFromBeginning).ServeHTTP(w, r)

		body := w.Body.String()
		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, body, fmt.Sprintf(`value="%s" checked`, selected))
		assert.NotContains(t, body, "You must configure some sort of trusted proxy setup")
	})

	t.Run("rejects an IP address or full URL as the server domain", func(t *testing.T) {
		_, _, _, e := makeTestEnv(t)

		tmpDir, err := os.MkdirTemp("", "testdatadb")
		require.NoError(t, err)

		t.Cleanup(func() {
			os.RemoveAll(tmpDir)
		})

		tests := []struct {
			Domain        string
			ExpectedError string
		}{
			{Domain: "192.168.1.10", ExpectedError: "an IP address can not be used as the server domain"},
			{Domain: "127.0.0.1", ExpectedError: "an IP address can not be used as the server domain"},
			{Domain: "fd00::1", ExpectedError: "an IP address can not be used as the server domain"},
			{Domain: "https://exampe.com", ExpectedError: "Invalid domain: this must be a bare domain. No scheme, no path, no port, no nothing"},
			{Domain: "localhost:9000", ExpectedError: "Invalid domain: this must be a bare domain. No scheme, no path, no port, no nothing"},
		}

		for _, curr := range tests {
			t.Run(curr.Domain, func(t *testing.T) {
				v := url.Values{}
				v.Add("port", "9000")
				v.Add("domain", curr.Domain)
				v.Add("auth_url", "https://auth.example.com")
				v.Add("config_file_preset", "custom")
				v.Add("config_path", filepath.Join(tmpDir, "auththingie2.yaml"))
				v.Add("db_path", filepath.Join(tmpDir, "at2.db"))
				v.Add("custom_trusted_network", "10.0.0.0/16")

				r, err := http.NewRequest(http.MethodPost, "https://auth.example.com/ftue/step0", strings.NewReader(v.Encode()))
				require.NoError(t, err)
				attachSetupAuthCookie(r, e)
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				w := httptest.NewRecorder()

				e.buildMux(StepStartFromBeginning).ServeHTTP(w, r)

				assert.Contains(t, w.Body.String(), curr.ExpectedError)
			})
		}
	})

	t.Run("a case with everything", func(t *testing.T) {
		_, _, cfg, e := makeTestEnv(t)

		tmpDir, err := os.MkdirTemp("", "testdatadb")
		require.NoError(t, err)

		t.Cleanup(func() {
			os.RemoveAll(tmpDir)
		})

		configFilePath := filepath.Join(tmpDir, "auththingie2.yaml")
		dbPath := filepath.Join(tmpDir, "at2.db")

		v := url.Values{}
		v.Add("port", "9000")
		v.Add("domain", "example.com")
		v.Add("auth_url", "https://auth.example.com")
		v.Add("config_file_preset", "custom")
		v.Add("config_path", configFilePath)
		v.Add("db_path", dbPath)
		v.Add("custom_trusted_network", "10.0.0.0/16")

		r, err := http.NewRequest(http.MethodPost, "https://auth.example.com/ftue/step0", strings.NewReader(v.Encode()))
		require.NoError(t, err)
		attachSetupAuthCookie(r, e)
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		e.buildMux(StepStartFromBeginning).ServeHTTP(w, r)

		assert.Equal(t, http.StatusFound, w.Result().StatusCode)
		redirectURL, err := w.Result().Location()
		require.NoError(t, err)
		attachSetupAuthCookie(r, e)
		assert.Equal(t, "/ftue/step1", redirectURL.Path)

		assert.FileExists(t, configFilePath)
		assert.FileExists(t, dbPath)

		assert.Equal(t, dbPath, cfg.GetString(config.ConfigKeyDBFile))
		assert.Equal(t, "sqlite", cfg.GetString(config.ConfigKeyDBKind))
		assert.Equal(t, "example.com", cfg.GetString(config.ConfigKeyServerDomain))
		assert.Equal(t, "https://auth.example.com", cfg.GetString(config.ConfigKeyServerAuthURL))
		assert.Equal(t, uint64(9000), cfg.GetUint64(config.ConfigKeyServerPort))
		assert.Equal(t, []string{"10.0.0.0/16"}, cfg.GetStringSlice(config.ConfigKeyTrustedProxyNetwork))

		assert.NotNil(t, e.database)
		assert.NotNil(t, e.analyzer)
	})
}
