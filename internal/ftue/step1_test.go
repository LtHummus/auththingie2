package ftue

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/lthummus/auththingie2/internal/render"
)

func TestFtueEnv_HandleFTUEStep1(t *testing.T) {
	render.Init()

	t.Run("just render", func(t *testing.T) {
		_, _, e := makeTestEnv(t)

		r := httptest.NewRequest(http.MethodGet, "/ftue/step1", nil)
		w := httptest.NewRecorder()

		e.buildMux(StepStartFromBeginning).ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "Now that you have a config file and a database, we need to set up some users. If you have a previously working")
		assert.Contains(t, w.Body.String(), "AuthThingie 1 installation, we can import your rules and your users from the config file you used. If you don't")
		assert.Contains(t, w.Body.String(), "have a previous installation (or you want to start from scratch), you can do that as well")
		assert.Contains(t, w.Body.String(), `<p id="ftue-choose-destiny">`)
		assert.Contains(t, w.Body.String(), `<a href="/ftue/scratch">Start from scratch</a>`)
		assert.Contains(t, w.Body.String(), `<a href="/ftue/import">Import a config file from AuthThingie 1</a>`)
	})
}
