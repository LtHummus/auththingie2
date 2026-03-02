package ftue

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/lthummus/auththingie2/internal/argon"
	"github.com/lthummus/auththingie2/internal/render"
	"github.com/lthummus/auththingie2/internal/user"
)

func TestFtueEnv_HandleFTUEScratchRenderPage(t *testing.T) {
	render.Init()

	t.Run("just rendeer", func(t *testing.T) {
		_, _, e := makeTestEnv(t)

		r := httptest.NewRequest(http.MethodGet, "/ftue/scratch", nil)
		w := httptest.NewRecorder()

		e.buildMux(StepStartFromBeginning).ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), `<input type="text" name="username" id="username-field" required aria-label="Username" placeholder="Username" />`)
		assert.Contains(t, w.Body.String(), `<input type="password" name="password" id="password-field" required placeholder="Password" aria-label="Password"/>`)
		assert.Contains(t, w.Body.String(), `<input type="password" name="password2" id="password2-field" required placeholder="Password (again)" aria-label="Password (again)"/>`)
		assert.Contains(t, w.Body.String(), `button type="submit" class="contrast">Create Admin User</button>`)
	})
}

func TestFtueEnv_HandleFTUEScratchRenderPOST(t *testing.T) {
	render.Init()

	t.Run("CSRF detection", func(t *testing.T) {
		_, _, e := makeTestEnv(t)

		v := url.Values{}
		v.Add("username", "test")
		v.Add("password", "test1")
		v.Add("password2", "test1")

		r := httptest.NewRequest(http.MethodPost, "/ftue/scratch", strings.NewReader(v.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Sec-Fetch-Site", "cross-site")
		w := httptest.NewRecorder()

		e.buildMux(StepStartFromBeginning).ServeHTTP(w, r)

		assert.Equal(t, http.StatusForbidden, w.Result().StatusCode)
	})

	t.Run("missing username", func(t *testing.T) {
		_, _, e := makeTestEnv(t)

		v := url.Values{}
		v.Add("username", "")

		r := httptest.NewRequest(http.MethodPost, "/ftue/scratch", strings.NewReader(v.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		e.buildMux(StepStartFromBeginning).ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "ERROR: username must be specified")
	})

	t.Run("missing password", func(t *testing.T) {
		_, _, e := makeTestEnv(t)

		v := url.Values{}
		v.Add("username", "test")
		v.Add("password", "")
		v.Add("password2", "")

		r := httptest.NewRequest(http.MethodPost, "/ftue/scratch", strings.NewReader(v.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		e.buildMux(StepStartFromBeginning).ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "ERROR: password mismatch or is blank!")
	})

	t.Run("password mismatch", func(t *testing.T) {
		_, _, e := makeTestEnv(t)

		v := url.Values{}
		v.Add("username", "test")
		v.Add("password", "aaaaa")
		v.Add("password2", "bbbbb")

		r := httptest.NewRequest(http.MethodPost, "/ftue/scratch", strings.NewReader(v.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		e.buildMux(StepStartFromBeginning).ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "ERROR: password mismatch or is blank!")
	})

	t.Run("invalid characters test", func(t *testing.T) {
		_, _, e := makeTestEnv(t)

		v := url.Values{}
		v.Add("username", "test")
		v.Add("password", "⁧45⁩")
		v.Add("password2", "⁧45⁩")

		r := httptest.NewRequest(http.MethodPost, "/ftue/scratch", strings.NewReader(v.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		e.buildMux(StepStartFromBeginning).ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "password contains invalid characters, pick a new one")
	})

	t.Run("user creation fails", func(t *testing.T) {
		db, _, e := makeTestEnv(t)

		db.On("CreateUser", mock.Anything, mock.AnythingOfType("*user.User")).Return(errors.New("nope"))

		v := url.Values{}
		v.Add("username", "test")
		v.Add("password", "test1")
		v.Add("password2", "test1")

		r := httptest.NewRequest(http.MethodPost, "/ftue/scratch", strings.NewReader(v.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		e.buildMux(StepStartFromBeginning).ServeHTTP(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "could not create admin user")
	})

	t.Run("everything works", func(t *testing.T) {
		db, _, e := makeTestEnv(t)

		db.On("CreateUser", mock.Anything, mock.AnythingOfType("*user.User")).Return(nil)

		v := url.Values{}
		v.Add("username", "test")
		v.Add("password", "test1")
		v.Add("password2", "test1")

		r := httptest.NewRequest(http.MethodPost, "/ftue/scratch", strings.NewReader(v.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		e.buildMux(StepStartFromBeginning).ServeHTTP(w, r)

		assert.Equal(t, http.StatusFound, w.Result().StatusCode)
		redirectURL, err := w.Result().Location()
		require.NoError(t, err)
		assert.Equal(t, "/ftue/restart", redirectURL.Path)

		createdUser := db.Mock.Calls[0].Arguments[1].(*user.User)

		assert.Equal(t, "test", createdUser.Username)
		assert.NoError(t, argon.ValidatePassword("test1", createdUser.PasswordHash))
		assert.True(t, createdUser.Admin)
	})
}
