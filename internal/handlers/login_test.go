package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/lthummus/auththingie2/internal/config"
	session2 "github.com/lthummus/auththingie2/internal/middlewares/session"
	"github.com/lthummus/auththingie2/internal/notices"
	"github.com/lthummus/auththingie2/internal/pwvalidate"
	"github.com/lthummus/auththingie2/internal/render"
	"github.com/lthummus/auththingie2/internal/salt"
	enrollment "github.com/lthummus/auththingie2/internal/totp"
)

func TestEnv_HandleLoginPage(t *testing.T) {
	setupSalts(t)
	render.Init()

	sc := securecookie.New(salt.GenerateSigningKey(), salt.GenerateEncryptionKey())

	t.Run("render login page on GET", func(t *testing.T) {
		_, _, _, _, ruriv, _, e := makeTestEnv(t)
		e.LoginLimiter = nil

		ruriv.On("Sanitize", "").Return("/", true)

		r := makeTestRequest(t, http.MethodGet, "/login", nil)
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), `<input type="text" name="username" id="username-field" required aria-label="Username" placeholder="Username" />`)
		assert.Contains(t, w.Body.String(), `<input type="password" name="password" id="password-field" required placeholder="Password" aria-label="Password"/>`)
		assert.Contains(t, w.Body.String(), `id="passkey-login-button"`)
	})

	t.Run("render login page with message", func(t *testing.T) {
		_, _, _, _, ruriv, _, e := makeTestEnv(t)
		e.LoginLimiter = nil

		ruriv.On("Sanitize", "").Return("/", true)

		r := makeTestRequest(t, http.MethodGet, fmt.Sprintf("/login?message=%s", loginMessageNotLoggedIn), nil)
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), `<input type="text" name="username" id="username-field" required aria-label="Username" placeholder="Username" />`)
		assert.Contains(t, w.Body.String(), `<input type="password" name="password" id="password-field" required placeholder="Password" aria-label="Password"/>`)
		assert.Contains(t, w.Body.String(), `You are not logged in. Please log in`)
		assert.Contains(t, w.Body.String(), `id="passkey-login-button"`)
	})

	t.Run("do not render arbitrary messages in to the page", func(t *testing.T) {
		_, _, _, _, ruriv, _, e := makeTestEnv(t)
		e.LoginLimiter = nil

		ruriv.On("Sanitize", "").Return("/", true)

		r := makeTestRequest(t, http.MethodGet, "/login?message=This+should+not+be+there+111111", nil)
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), `<input type="text" name="username" id="username-field" required aria-label="Username" placeholder="Username" />`)
		assert.Contains(t, w.Body.String(), `<input type="password" name="password" id="password-field" required placeholder="Password" aria-label="Password"/>`)
		assert.NotContains(t, w.Body.String(), `111111`)
		assert.Contains(t, w.Body.String(), `id="passkey-login-button"`)
	})

	t.Run("login page should not have passkey option if passkeys are disabled", func(t *testing.T) {
		_, _, _, _, ruriv, v, e := makeTestEnv(t)
		e.LoginLimiter = nil

		ruriv.On("Sanitize", "").Return("/", true)

		v.Set(config.KeyPasskeysDisabled, true)

		r := makeTestRequest(t, http.MethodGet, "/login", nil)
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), `<input type="text" name="username" id="username-field" required aria-label="Username" placeholder="Username" />`)
		assert.Contains(t, w.Body.String(), `<input type="password" name="password" id="password-field" required placeholder="Password" aria-label="Password"/>`)
		assert.NotContains(t, w.Body.String(), `id="passkey-login-button"`)
	})

	t.Run("puts redirect uri in form if needed", func(t *testing.T) {
		_, _, _, _, ruriv, _, e := makeTestEnv(t)
		e.LoginLimiter = nil
		ruriv.On("Sanitize", "https://example.com").Return("https://example.com", true)

		r := makeTestRequest(t, http.MethodGet, "/login?redirect_uri=https%3A%2F%2Fexample.com", nil)
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), `<input type="hidden" name="redirect_uri" value="https://example.com" />`)
		assert.Contains(t, w.Body.String(), `<button id="passkey-login-button" data-redirect-uri="https://example.com">`)
	})

	// begin POST tests

	t.Run("CSRF detection", func(t *testing.T) {
		_, _, _, _, _, _, e := makeTestEnv(t)

		v := url.Values{}
		v.Add("username", "test")
		v.Add("password", "test1")

		r := makeTestRequest(t, http.MethodPost, "/login", strings.NewReader(v.Encode()))
		r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Sec-Fetch-Site", "cross-origin")
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusForbidden, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "cross-origin request detected from Sec-Fetch-Site header")
	})

	t.Run("gracefully handle database error", func(t *testing.T) {
		_, _, _, pwv, ruriv, _, e := makeTestEnv(t)

		v := url.Values{}
		v.Add("username", "test")
		v.Add("password", "test1")

		ruriv.On("Sanitize", "").Return("/", true)
		pwv.On("Validate", mock.Anything, "test", "test1", "192.0.2.1").Return(nil, errors.New("whoops"))

		r := makeTestRequest(t, http.MethodPost, "/login", strings.NewReader(v.Encode()))
		r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Contains(t, w.Body.String(), "Server side error happened. Try again")
	})

	t.Run("invalid credentials, not locked", func(t *testing.T) {
		_, _, _, pwv, ruriv, _, e := makeTestEnv(t)

		v := url.Values{}
		v.Add("username", "test")
		v.Add("password", "test1")
		v.Add("redirect_uri", "https://test.example.com")

		ruriv.On("Sanitize", "https://test.example.com").Return("https://test.example.com", false)
		pwv.On("Validate", mock.Anything, "test", "test1", "192.0.2.1").Return(nil, &pwvalidate.InvalidUsernamePasswordError{
			AccountRemainingBeforeLocked: 4,
			IPRemainingBeforeLocked:      4,
		})

		r := makeTestRequest(t, http.MethodPost, "/login", strings.NewReader(v.Encode()))
		r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "Invalid username or password. You have 4 more attempts before the account is temporarily locked")
		assert.Contains(t, w.Body.String(), `<input type="hidden" name="redirect_uri" value="https://test.example.com" />`)
	})

	t.Run("incorrect password that results in a locked account (by username and IP)", func(t *testing.T) {
		_, _, _, pwv, ruriv, _, e := makeTestEnv(t)

		v := url.Values{}
		v.Add("username", "regularuser")
		v.Add("password", "thisisanincorrectpassword")
		v.Add("redirect_uri", "https://test.example.com")

		ruriv.On("Sanitize", "https://test.example.com").Return("https://test.example.com", false)
		pwv.On("Validate", mock.Anything, "regularuser", "thisisanincorrectpassword", "192.0.2.1").Return(nil, &pwvalidate.AccountLockedError{})

		r := makeTestRequest(t, http.MethodPost, "/login", strings.NewReader(v.Encode()))
		r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "Invalid username or password. This account has been locked due to multiple failures")
		assert.Contains(t, w.Body.String(), `<input type="hidden" name="redirect_uri" value="https://test.example.com" />`)
	})

	t.Run("can't login with disabled account", func(t *testing.T) {
		_, _, _, pwv, ruriv, _, e := makeTestEnv(t)

		v := url.Values{}
		v.Add("username", "regularuser")
		v.Add("password", "test1")
		v.Add("redirect_uri", "https://test.example.com/foo")

		ruriv.On("Sanitize", "https://test.example.com/foo").Return("https://test.example.com/foo", false)
		pwv.On("Validate", mock.Anything, "regularuser", "test1", "192.0.2.1").Return(sampleDisabledUser, &pwvalidate.AccountDisabledError{})

		r := makeTestRequest(t, http.MethodPost, "/login", strings.NewReader(v.Encode()))
		r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "Account is disabled")
		assert.Empty(t, w.Result().Cookies())
	})

	t.Run("login passes with disable if TOTP is enabled", func(t *testing.T) {
		_, _, _, pwv, ruriv, _, e := makeTestEnv(t)

		v := url.Values{}
		v.Add("username", "regularuser")
		v.Add("password", "test1")
		v.Add("redirect_uri", "https://test.example.com/foo")

		ruriv.On("Sanitize", "https://test.example.com/foo").Return("https://test.example.com/foo", false)
		pwv.On("Validate", mock.Anything, "regularuser", "test1", "192.0.2.1").Return(sampleDisabledUserWithTOTP, &pwvalidate.AccountDisabledError{})

		r := makeTestRequest(t, http.MethodPost, "/login", strings.NewReader(v.Encode()))
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
		_, _, _, pwv, ruriv, _, e := makeTestEnv(t)

		v := url.Values{}
		v.Add("username", "regularuser")
		v.Add("password", "test1")
		v.Add("redirect_uri", "https://test.example.com/foo")

		ruriv.On("Sanitize", "https://test.example.com/foo").Return("https://test.example.com/foo", false)
		pwv.On("Validate", mock.Anything, "regularuser", "test1", "192.0.2.1").Return(sampleNonAdminUser, nil)

		r := makeTestRequest(t, http.MethodPost, "/login", strings.NewReader(v.Encode()))
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
		var sess session2.Session
		err = sc.Decode(session2.SessionCookieName, w.Result().Cookies()[0].Value, &sess)
		assert.NoError(t, err)

		assert.Equal(t, sampleNonAdminUser.Id, sess.UserID)
		assert.WithinDuration(t, time.Now(), sess.LoginTime, 1*time.Second)
	})

	t.Run("valid username/password with no TOTP or explicit redirect", func(t *testing.T) {
		_, _, _, pwv, ruriv, _, e := makeTestEnv(t)

		v := url.Values{}
		v.Add("username", "regularuser")
		v.Add("password", "test1")
		v.Add("redirect_uri", "")

		ruriv.On("Sanitize", "").Return("/", true)
		pwv.On("Validate", mock.Anything, "regularuser", "test1", "192.0.2.1").Return(sampleNonAdminUser, nil)

		r := makeTestRequest(t, http.MethodPost, "/login", strings.NewReader(v.Encode()))
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

	t.Run("valid username/password, has messages, not admin", func(t *testing.T) {
		t.Cleanup(func() {
			notices.Reset()
		})
		_, _, _, pwv, ruriv, _, e := makeTestEnv(t)

		notices.AddMessage("test", "test message")

		v := url.Values{}
		v.Add("username", "regularuser")
		v.Add("password", "test1")
		v.Add("redirect_uri", "https://test.example.com/foo")

		ruriv.On("Sanitize", "https://test.example.com/foo").Return("https://test.example.com/foo", false)
		pwv.On("Validate", mock.Anything, "regularuser", "test1", "192.0.2.1").Return(sampleNonAdminUser, nil)

		r := makeTestRequest(t, http.MethodPost, "/login", strings.NewReader(v.Encode()))
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
		var sess session2.Session
		err = sc.Decode(session2.SessionCookieName, w.Result().Cookies()[0].Value, &sess)
		assert.NoError(t, err)

		assert.Equal(t, sampleNonAdminUser.Id, sess.UserID)
		assert.WithinDuration(t, time.Now(), sess.LoginTime, 1*time.Second)
	})

	t.Run("valid username/password, has messages, is admin", func(t *testing.T) {
		t.Cleanup(func() {
			notices.Reset()
		})
		_, _, _, pwv, ruriv, _, e := makeTestEnv(t)

		notices.AddMessage("test", "test message")

		v := url.Values{}
		v.Add("username", "adminuser")
		v.Add("password", "test1")
		v.Add("redirect_uri", "https://test.example.com/foo")

		ruriv.On("Sanitize", "https://test.example.com/foo").Return("https://test.example.com/foo", false)
		pwv.On("Validate", mock.Anything, "adminuser", "test1", "192.0.2.1").Return(sampleAdminUser, nil)

		r := makeTestRequest(t, http.MethodPost, "/login", strings.NewReader(v.Encode()))
		r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusFound, w.Result().StatusCode)
		finalURL, err := w.Result().Location()
		assert.NoError(t, err)
		assert.Equal(t, "/admin/notices", finalURL.Path)
		assert.Equal(t, "redirect_uri=https%3A%2F%2Ftest.example.com%2Ffoo", finalURL.RawQuery)

		assert.Len(t, w.Result().Cookies(), 1)
		var sess session2.Session
		err = sc.Decode(session2.SessionCookieName, w.Result().Cookies()[0].Value, &sess)
		assert.NoError(t, err)

		assert.Equal(t, sampleAdminUser.Id, sess.UserID)
		assert.WithinDuration(t, time.Now(), sess.LoginTime, 1*time.Second)
	})

	t.Run("correct username/password with TOTP", func(t *testing.T) {
		_, _, _, pwv, ruriv, cfg, e := makeTestEnv(t)

		cfg.Set("auth_url", "https://example.com")

		v := url.Values{}
		v.Add("username", "sampletotp")
		v.Add("password", "test1")
		v.Add("redirect_uri", "https://test.example.com/foo")

		ruriv.On("Sanitize", "https://test.example.com/foo").Return("https://test.example.com/foo", false)
		pwv.On("Validate", mock.Anything, "sampletotp", "test1", "192.0.2.1").Return(sampleNonAdminWithTOTP, nil)

		r := makeTestRequest(t, http.MethodPost, "/login", strings.NewReader(v.Encode()))
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

}
