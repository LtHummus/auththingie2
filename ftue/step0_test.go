package ftue

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

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
		assert.Contains(t, w.Body.String(), `<input type="radio" id="slash-config-radio" name="config_file_preset" value="slashconfig"  checked  onclick="showCustomFields()" />`)
		assert.Contains(t, w.Body.String(), `<input type="radio" id="cwd-radio" name="config_file_preset" value="pwd"  onclick="showCustomFields()"  />`)
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
		assert.Contains(t, w.Body.String(), `<input type="radio" id="slash-config-radio" name="config_file_preset" value="slashconfig"  onclick="showCustomFields()" />`)
		assert.Contains(t, w.Body.String(), `<input type="radio" id="cwd-radio" name="config_file_preset" value="pwd"  checked  onclick="showCustomFields()"  />`)
		assert.Contains(t, w.Body.String(), `<input type="text" name="domain" id="domain-field" required aria-label="Server Domain" value="example.com" autocomplete="off" autocorrect="off" spellcheck="off" />`)
		assert.Contains(t, w.Body.String(), `<input type="text" name="auth_url" id="auth-url-field" required aria-label="Auth URL Field" value="auth.example.com" autocomplete="off" autocorrect="off" spellcheck="off" />`)

	})
}
