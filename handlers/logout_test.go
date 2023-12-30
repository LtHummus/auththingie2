package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/lthummus/auththingie2/render"
)

func TestEnv_HandleLogout(t *testing.T) {
	setupSalts(t)
	render.Init()

	t.Run("clobber session", func(t *testing.T) {
		_, db, e := makeTestEnv(t)
		mux := e.BuildRouter()

		r := makeTestRequest(t, http.MethodGet, "/logout", nil, withUser(sampleNonAdminUser, db))
		w := httptest.NewRecorder()

		mux.ServeHTTP(w, r)

		resp := w.Result()

		assert.Equal(t, http.StatusFound, resp.StatusCode)
		redirectURL, err := resp.Location()
		assert.NoError(t, err)
		assert.Equal(t, "/", redirectURL.Path)

		// check for two cookies -- CSRF and session
		assert.Len(t, resp.Cookies(), 2)

		// TODO: can we validate the session data here?

	})
}
