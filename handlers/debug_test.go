package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/lthummus/auththingie2/render"
)

func TestEnv_HandleDebug(t *testing.T) {
	setupSalts(t)
	render.Init()

	t.Setenv("ENVIRONMENT", "prod")

	t.Run("not logged in should fail", func(t *testing.T) {
		_, _, _, e := makeTestEnv(t)

		r := makeTestRequest(t, http.MethodGet, "/debug", nil)
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusNotFound, w.Result().StatusCode)
	})

	t.Run("not admin should fail", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)

		r := makeTestRequest(t, http.MethodGet, "/debug", nil, withUser(sampleNonAdminUser, db))
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusNotFound, w.Result().StatusCode)
	})

	t.Run("should render without explicit enable if admin", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)

		r := makeTestRequest(t, http.MethodGet, "/debug", nil, withUser(sampleAdminUser, db))
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
	})

	t.Run("if flag is on, always render debug page", func(t *testing.T) {
		_, _, _, e := makeTestEnv(t)

		t.Setenv("ENABLE_DEBUG_PAGE", "true")

		r := makeTestRequest(t, http.MethodGet, "/debug", nil)
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)

	})
}
