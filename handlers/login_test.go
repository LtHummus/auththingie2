package handlers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/lthummus/auththingie2/argon"
	"github.com/lthummus/auththingie2/config"
	"github.com/lthummus/auththingie2/middlewares/session"
	"github.com/lthummus/auththingie2/render"
	"github.com/lthummus/auththingie2/salt"
	enrollment "github.com/lthummus/auththingie2/totp"
	"github.com/lthummus/auththingie2/user"
)

func TestEnv_HandleLoginPage(t *testing.T) {
	setupSalts(t)
	render.Init()

	sc := securecookie.New(salt.GenerateSigningKey(), salt.GenerateEncryptionKey())

	t.Run("render login page on GET", func(t *testing.T) {
		_, _, e := makeTestEnv(t)

		r := makeTestRequest(t, http.MethodGet, "/login", nil)
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), `<input type="text" name="username" id="username-field" required aria-label="Username" placeholder="Username" />`)
		assert.Contains(t, w.Body.String(), `<input type="password" name="password" id="password-field" required placeholder="Password" aria-label="Password"/>`)
		assert.Contains(t, w.Body.String(), `id="passkey-login-button"`)
	})

	t.Run("render login page with message", func(t *testing.T) {
		_, _, e := makeTestEnv(t)

		r := makeTestRequest(t, http.MethodGet, "/login?message=This+is+a+test+message", nil)
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), `<input type="text" name="username" id="username-field" required aria-label="Username" placeholder="Username" />`)
		assert.Contains(t, w.Body.String(), `<input type="password" name="password" id="password-field" required placeholder="Password" aria-label="Password"/>`)
		assert.Contains(t, w.Body.String(), `This is a test message`)
		assert.Contains(t, w.Body.String(), `id="passkey-login-button"`)
	})

	t.Run("login page should not have passkey option if passkeys are disabled", func(t *testing.T) {
		_, _, e := makeTestEnv(t)

		viper.Set(config.KeyPasskeysDisabled, true)
		t.Cleanup(func() {
			viper.Set(config.KeyPasskeysDisabled, false)
		})

		r := makeTestRequest(t, http.MethodGet, "/login", nil)
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), `<input type="text" name="username" id="username-field" required aria-label="Username" placeholder="Username" />`)
		assert.Contains(t, w.Body.String(), `<input type="password" name="password" id="password-field" required placeholder="Password" aria-label="Password"/>`)
		assert.NotContains(t, w.Body.String(), `id="passkey-login-button"`)
	})

	t.Run("puts redirect uri in form if needed", func(t *testing.T) {
		_, _, e := makeTestEnv(t)

		r := makeTestRequest(t, http.MethodGet, "/login?redirect_uri=https%3A%2F%2Fexample.com", nil)
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), `<input type="hidden" name="redirect_uri" value="https://example.com" />`)
	})

	// begin POST tests

	t.Run("gracefull handle database error", func(t *testing.T) {
		_, db, e := makeTestEnv(t)

		v := url.Values{}
		v.Add("username", "test")
		v.Add("password", "test1")

		db.On("GetUserByUsername", mock.Anything, "test").Return(nil, errors.New("database error"))

		r := makeTestRequest(t, http.MethodPost, "/login", strings.NewReader(v.Encode()), passesCSRF())
		r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "database error")
	})

	t.Run("user not found", func(t *testing.T) {
		_, db, e := makeTestEnv(t)

		v := url.Values{}
		v.Add("username", "test")
		v.Add("password", "test1")
		v.Add("redirect_uri", "https://test.example.com")

		db.On("GetUserByUsername", mock.Anything, "test").Return(nil, nil)

		r := makeTestRequest(t, http.MethodPost, "/login", strings.NewReader(v.Encode()), passesCSRF())
		r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "Invalid Username or Password")
		assert.Contains(t, w.Body.String(), `<input type="hidden" name="redirect_uri" value="https://test.example.com" />`)
	})

	t.Run("incorrect password", func(t *testing.T) {
		_, db, e := makeTestEnv(t)

		v := url.Values{}
		v.Add("username", "regularuser")
		v.Add("password", "thisisanincorrectpassword")
		v.Add("redirect_uri", "https://test.example.com")

		db.On("GetUserByUsername", mock.Anything, "regularuser").Return(sampleNonAdminUser, nil)

		r := makeTestRequest(t, http.MethodPost, "/login", strings.NewReader(v.Encode()), passesCSRF())
		r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "Invalid Username or Password")
		assert.Contains(t, w.Body.String(), `<input type="hidden" name="redirect_uri" value="https://test.example.com" />`)
	})

	t.Run("can't login with disabled account", func(t *testing.T) {
		_, db, e := makeTestEnv(t)

		v := url.Values{}
		v.Add("username", "regularuser")
		v.Add("password", "test1")
		v.Add("redirect_uri", "https://test.example.com/foo")

		db.On("GetUserByUsername", mock.Anything, "regularuser").Return(sampleDisabledUser, nil)

		r := makeTestRequest(t, http.MethodPost, "/login", strings.NewReader(v.Encode()), passesCSRF())
		r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "Account is disabled")
		assert.Empty(t, w.Result().Cookies())
	})

	t.Run("login passes with disable if TOTP is enabled", func(t *testing.T) {
		_, db, e := makeTestEnv(t)

		v := url.Values{}
		v.Add("username", "regularuser")
		v.Add("password", "test1")
		v.Add("redirect_uri", "https://test.example.com/foo")

		db.On("GetUserByUsername", mock.Anything, "regularuser").Return(sampleDisabledUserWithTOTP, nil)

		r := makeTestRequest(t, http.MethodPost, "/login", strings.NewReader(v.Encode()), passesCSRF())
		r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		ticketMatches := loginTicketRegex.FindStringSubmatch(w.Body.String())
		assert.Len(t, ticketMatches, 2)

		decoded, err := enrollment.DecodeLoginTicket(ticketMatches[1])
		assert.NoError(t, err)

		assert.Equal(t, sampleDisabledUserWithTOTP.Id, decoded.UserID)
		assert.WithinDuration(t, time.Now().Add(5*time.Minute), decoded.Expiration, time.Second)
	})

	t.Run("valid username/password with no TOTP and redirect uri", func(t *testing.T) {
		_, db, e := makeTestEnv(t)

		v := url.Values{}
		v.Add("username", "regularuser")
		v.Add("password", "test1")
		v.Add("redirect_uri", "https://test.example.com/foo")

		db.On("GetUserByUsername", mock.Anything, "regularuser").Return(sampleNonAdminUser, nil)

		r := makeTestRequest(t, http.MethodPost, "/login", strings.NewReader(v.Encode()), passesCSRF())
		r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusFound, w.Result().StatusCode)
		finalURL, err := w.Result().Location()
		assert.NoError(t, err)
		assert.Equal(t, "https", finalURL.Scheme)
		assert.Equal(t, "test.example.com", finalURL.Host)
		assert.Equal(t, "/foo", finalURL.Path)

		assert.Len(t, w.Result().Cookies(), 1)
		var sess session.Session
		err = sc.Decode(session.SessionCookieName, w.Result().Cookies()[0].Value, &sess)
		assert.NoError(t, err)

		assert.Equal(t, sampleNonAdminUser.Id, sess.UserID)
		assert.WithinDuration(t, time.Now(), sess.LoginTime, 1*time.Second)
	})

	t.Run("valid username/password with no TOTP or explicit redirect", func(t *testing.T) {
		_, db, e := makeTestEnv(t)

		v := url.Values{}
		v.Add("username", "regularuser")
		v.Add("password", "test1")
		v.Add("redirect_uri", "")

		db.On("GetUserByUsername", mock.Anything, "regularuser").Return(sampleNonAdminUser, nil)

		r := makeTestRequest(t, http.MethodPost, "/login", strings.NewReader(v.Encode()), passesCSRF())
		r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusFound, w.Result().StatusCode)
		finalURL, err := w.Result().Location()
		assert.NoError(t, err)
		assert.Equal(t, "", finalURL.Scheme)
		assert.Equal(t, "", finalURL.Host)
		assert.Equal(t, "/", finalURL.Path)
	})

	t.Run("correct username/password with TOTP", func(t *testing.T) {
		_, db, e := makeTestEnv(t)

		viper.Set("auth_url", "https://example.com")
		t.Cleanup(func() {
			viper.Set("auth_url", "")
		})

		v := url.Values{}
		v.Add("username", "sampletotp")
		v.Add("password", "test1")
		v.Add("redirect_uri", "https://test.example.com/foo")

		db.On("GetUserByUsername", mock.Anything, "sampletotp").Return(sampleNonAdminWithTOTP, nil)

		r := makeTestRequest(t, http.MethodPost, "/login", strings.NewReader(v.Encode()), passesCSRF())
		r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)

		ticketMatches := loginTicketRegex.FindStringSubmatch(w.Body.String())
		assert.Len(t, ticketMatches, 2)

		ticket, err := enrollment.DecodeLoginTicket(ticketMatches[1])
		assert.NoError(t, err)

		assert.Equal(t, sampleNonAdminWithTOTP.Id, ticket.UserID)
		assert.WithinDuration(t, time.Now().Add(5*time.Minute), ticket.Expiration, time.Second)
		assert.Equal(t, "https://test.example.com/foo", ticket.RedirectURI)
	})

	t.Run("migrate password on login", func(t *testing.T) {
		_, db, e := makeTestEnv(t)

		v := url.Values{}
		v.Add("username", "oldpwuser")
		v.Add("password", "test1")
		v.Add("redirect_uri", "")

		db.On("GetUserByUsername", mock.Anything, "oldpwuser").Return(sampleNonAdminWithOldArgonParams, nil)
		db.On("UpdatePassword", mock.Anything, mock.AnythingOfType("*user.User")).Return(nil)

		r := makeTestRequest(t, http.MethodPost, "/login", strings.NewReader(v.Encode()), passesCSRF())
		r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusFound, w.Result().StatusCode)
		finalURL, err := w.Result().Location()
		assert.NoError(t, err)
		assert.Equal(t, "", finalURL.Scheme)
		assert.Equal(t, "", finalURL.Host)
		assert.Equal(t, "/", finalURL.Path)

		// wait until the update password goroutine has finished
		assert.Eventually(t, func() bool {
			return len(db.Mock.Calls) >= 2
		}, 5*time.Second, 250*time.Millisecond)
		updatedUser := db.Mock.Calls[1].Arguments[1].(*user.User)

		assert.True(t, strings.HasPrefix(updatedUser.PasswordHash, "$argon2id$v=19$m=65536,t=3,p=2$"))
		assert.WithinDuration(t, time.Now(), time.Unix(updatedUser.PasswordTimestamp, 0), 2*time.Second)
		assert.NoError(t, argon.ValidatePassword("test1", updatedUser.PasswordHash))
	})
}
