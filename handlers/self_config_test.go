package handlers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/lthummus/auththingie2/config"
	"github.com/lthummus/auththingie2/render"
	"github.com/lthummus/auththingie2/user"
)

func TestEnv_HandleSelfConfigGet(t *testing.T) {
	setupSalts(t)
	render.Init()

	t.Run("fail if not logged in", func(t *testing.T) {
		_, _, _, e := makeTestEnv(t)

		r := makeTestRequest(t, http.MethodGet, "/edit_self", nil)
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusForbidden, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "you must be logged in to access this page")
	})

	t.Run("render if logged in", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)

		r := makeTestRequest(t, http.MethodGet, "/edit_self", nil, withUser(sampleNonAdminUser, db))
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), `<h2>Editing Yourself (<strong>regularuser</strong>)</h2>`)
		assert.Contains(t, w.Body.String(), `You do not currently have TOTP enabled. If you wish to enable it, you can go <a href="/enable_totp">here</a>`)
		assert.Contains(t, w.Body.String(), `<a href="/webauthn/manage">Manage Your Passkeys</a>`)
	})

	t.Run("don't render passkeys if disabled", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)

		viper.Set(config.KeyPasskeysDisabled, true)
		t.Cleanup(func() {
			viper.Set(config.KeyPasskeysDisabled, false)
		})

		r := makeTestRequest(t, http.MethodGet, "/edit_self", nil, withUser(sampleNonAdminUser, db))
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), `<h2>Editing Yourself (<strong>regularuser</strong>)</h2>`)
		assert.Contains(t, w.Body.String(), `You do not currently have TOTP enabled. If you wish to enable it, you can go <a href="/enable_totp">here</a>`)
		assert.NotContains(t, w.Body.String(), `<a href="/webauthn/manage">Manage Your Passkeys</a>`)
	})

	t.Run("show correct TOTP status if user is enrolled", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)

		r := makeTestRequest(t, http.MethodGet, "/edit_self", nil, withUser(sampleNonAdminWithTOTP, db))
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), `You have TOTP enabled. You can disable it by clicking <a class="link-like" hx-target="#totp_setup_container" hx-swap="innerHTML" hx-post="/disable_totp" hx-confirm="Are you sure you want to disable TOTP?">here</a>`)
	})
}

func TestEnv_HandleSelfConfigPasswordGet(t *testing.T) {
	setupSalts(t)
	render.Init()

	t.Run("basic case", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)

		r := makeTestRequest(t, http.MethodGet, "/edit_self/password", nil, withUser(sampleNonAdminUser, db))
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
	})
}

func TestEnv_HandleSelfConfigPasswordPost(t *testing.T) {
	setupSalts(t)
	render.Init()

	t.Run("fail if not logged in", func(t *testing.T) {
		_, _, _, e := makeTestEnv(t)

		v := url.Values{}
		v.Add("old_pw", "password1")
		v.Add("pw1", "password2")
		v.Add("pw2", "password2")

		r := makeTestRequest(t, http.MethodPost, "/edit_self/password", strings.NewReader(v.Encode()))
		r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusUnauthorized, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "you must be logged in to access this page")
	})

	t.Run("incorrect initial password", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)

		v := url.Values{}
		v.Add("old_pw", "password1")
		v.Add("pw1", "password2")
		v.Add("pw2", "password2")

		r := makeTestRequest(t, http.MethodPost, "/edit_self/password", strings.NewReader(v.Encode()), withUser(sampleNonAdminUser, db))
		r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "Incorrect old password")
	})

	t.Run("mismatched new passwords", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)

		v := url.Values{}
		v.Add("old_pw", "test1")
		v.Add("pw1", "password1")
		v.Add("pw2", "password2")

		r := makeTestRequest(t, http.MethodPost, "/edit_self/password", strings.NewReader(v.Encode()), withUser(sampleNonAdminUser, db))
		r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "New passwords do not match")
	})

	t.Run("blank new passwords", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)

		v := url.Values{}
		v.Add("old_pw", "test1")
		v.Add("pw1", "")
		v.Add("pw2", "")

		r := makeTestRequest(t, http.MethodPost, "/edit_self/password", strings.NewReader(v.Encode()), withUser(sampleNonAdminUser, db))
		r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "New password may not be blank")
	})

	t.Run("error on db update", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)

		v := url.Values{}
		v.Add("old_pw", "test1")
		v.Add("pw1", "password1")
		v.Add("pw2", "password1")

		db.On("SaveUser", mock.Anything, mock.AnythingOfType("*user.User")).Return(errors.New("nope"))

		r := makeTestRequest(t, http.MethodPost, "/edit_self/password", strings.NewReader(v.Encode()), withUser(sampleNonAdminUser, db))
		r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "Could not save updated password to database")
	})

	t.Run("everything worked", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)

		v := url.Values{}
		v.Add("old_pw", "test1")
		v.Add("pw1", "password1")
		v.Add("pw2", "password1")

		db.On("SaveUser", mock.Anything, mock.AnythingOfType("*user.User")).Return(nil)

		r := makeTestRequest(t, http.MethodPost, "/edit_self/password", strings.NewReader(v.Encode()), withUser(sampleNonAdminUser, db))
		r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusFound, w.Result().StatusCode)
		redirectedURL, err := w.Result().Location()
		assert.NoError(t, err)
		assert.Equal(t, "/", redirectedURL.Path)

		updatedUser := db.Mock.Calls[1].Arguments[1].(*user.User)

		assert.NoError(t, updatedUser.CheckPassword("password1"))

		changedTime := time.Unix(updatedUser.PasswordTimestamp, 0)
		assert.WithinDuration(t, time.Now(), changedTime, 2*time.Second)
	})

}
