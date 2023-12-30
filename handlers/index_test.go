package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/lthummus/auththingie2/render"
)

func TestEnv_HandleIndex(t *testing.T) {
	setupSalts(t)
	render.Init()

	t.Run("not logged in", func(t *testing.T) {
		_, _, e := makeTestEnv(t)
		mux := e.BuildRouter()

		r := makeTestRequest(t, http.MethodGet, "/", nil)
		w := httptest.NewRecorder()

		mux.ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), `You are currently logged out. You can <a href="/login">log in here</a>.`)
	})

	t.Run("logged in", func(t *testing.T) {
		_, db, e := makeTestEnv(t)
		mux := e.BuildRouter()

		r := makeTestRequest(t, http.MethodGet, "/", nil, withUser(sampleAdminUser, db))
		w := httptest.NewRecorder()

		mux.ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), `You are logged in as <strong>adminuser</strong>. You can <a href="/logout">log out if you wish</a>.`)
	})
}
