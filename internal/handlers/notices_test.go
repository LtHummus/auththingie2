package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lthummus/auththingie2/internal/notices"
	"github.com/lthummus/auththingie2/internal/render"
)

func TestEnv_ShowNotices(t *testing.T) {
	render.Init()

	t.Run("non admin should error", func(t *testing.T) {
		_, _, _, e := makeTestEnv(t)
		r := makeTestRequest(t, http.MethodGet, "/admin/notices", nil)
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusForbidden, w.Result().StatusCode)
	})

	t.Run("error out if logged in and not admin", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)
		r := makeTestRequest(t, http.MethodGet, "/admin/notices", nil, withUser(sampleNonAdminUser, db))
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusForbidden, w.Result().StatusCode)
	})

	t.Run("show messages if admin and there are messages to show", func(t *testing.T) {
		t.Cleanup(func() {
			notices.Reset()
		})

		notices.AddMessage("test", "This is a test message")

		_, db, _, e := makeTestEnv(t)
		r := makeTestRequest(t, http.MethodGet, "/admin/notices", nil, withUser(sampleAdminUser, db))
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "This is a test message")
		assert.Contains(t, w.Body.String(), `<a href="/">`)
	})

	t.Run("show messages with correct redirect uri", func(t *testing.T) {
		t.Cleanup(func() {
			notices.Reset()
		})

		notices.AddMessage("test", "This is a test message")

		_, db, _, e := makeTestEnv(t)
		r := makeTestRequest(t, http.MethodGet, "/admin/notices?redirect_uri=https://example.com", nil, withUser(sampleAdminUser, db))
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "This is a test message")
		assert.Contains(t, w.Body.String(), `<a href="https://example.com">`)
	})

	t.Run("redirect if there are no messages", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)
		r := makeTestRequest(t, http.MethodGet, "/admin/notices?redirect_uri=https://example.com", nil, withUser(sampleAdminUser, db))
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusFound, w.Result().StatusCode)
		loc, err := w.Result().Location()
		require.NoError(t, err)
		assert.Equal(t, "https://example.com", loc.String())
	})

	t.Run("redirect if there are messages, but user is suppressing them", func(t *testing.T) {
		t.Cleanup(func() {
			notices.Reset()
			viper.Set("unsafe_hide_admin_messages", false)
		})

		viper.Set("unsafe_hide_admin_messages", true)

		notices.AddMessage("hi", "hi")

		_, db, _, e := makeTestEnv(t)
		r := makeTestRequest(t, http.MethodGet, "/admin/notices?redirect_uri=https://example.com", nil, withUser(sampleAdminUser, db))
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusFound, w.Result().StatusCode)
		loc, err := w.Result().Location()
		require.NoError(t, err)
		assert.Equal(t, "https://example.com", loc.String())
	})
}
