package ftue

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lthummus/auththingie2/internal/ftue/session"
	"github.com/lthummus/auththingie2/internal/render"
)

func findSetupCookie(t *testing.T, w *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()

	for _, curr := range w.Result().Cookies() {
		if curr.Name == session.FTUESessionCookieName {
			return curr
		}
	}

	return nil
}

func postSetupCode(t *testing.T, e *ftueEnv, code string) *httptest.ResponseRecorder {
	t.Helper()

	v := url.Values{}
	v.Add("setup_code", code)

	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(v.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	e.buildMux(StepStartFromBeginning).ServeHTTP(w, r)

	return w
}

func TestFtueEnv_HandleSetupCodeGET(t *testing.T) {
	render.Init()

	t.Run("renders the setup code prompt without any data", func(t *testing.T) {
		_, _, _, e := makeTestEnv(t)

		r := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()

		e.buildMux(StepStartFromBeginning).ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), `<form action="/" method="post">`)
		assert.Contains(t, w.Body.String(), `name="setup_code"`)
	})
}

func TestFtueEnv_HandleSetupCodePOST(t *testing.T) {
	render.Init()

	t.Run("correct code writes a session and sends the user to /begin", func(t *testing.T) {
		_, _, _, e := makeTestEnv(t)

		w := postSetupCode(t, e, testSetupCode)

		assert.Equal(t, http.StatusFound, w.Result().StatusCode)
		assert.Equal(t, "/begin", w.Result().Header.Get("Location"))

		c := findSetupCookie(t, w)
		require.NotNil(t, c)
		assert.True(t, c.HttpOnly)
		assert.Equal(t, http.SameSiteStrictMode, c.SameSite)
		assert.NotEmpty(t, c.Value)
	})

	t.Run("the issued cookie actually opens the protected flow", func(t *testing.T) {
		_, _, _, e := makeTestEnv(t)

		c := findSetupCookie(t, postSetupCode(t, e, testSetupCode))
		require.NotNil(t, c)

		r := httptest.NewRequest(http.MethodGet, "/begin", nil)
		r.AddCookie(c)
		w := httptest.NewRecorder()

		e.buildMux(StepStartFromBeginning).ServeHTTP(w, r)

		assert.Equal(t, http.StatusFound, w.Result().StatusCode)
		assert.Equal(t, "/ftue/step0", w.Result().Header.Get("Location"))
	})

	t.Run("code is accepted case insensitively and with surrounding whitespace", func(t *testing.T) {
		for _, curr := range []string{
			strings.ToLower(testSetupCode),
			"  " + testSetupCode + "\t",
			"  " + strings.ToLower(testSetupCode) + " ",
		} {
			_, _, _, e := makeTestEnv(t)

			w := postSetupCode(t, e, curr)

			assert.Equal(t, http.StatusFound, w.Result().StatusCode, "input %q should have been accepted", curr)
			assert.NotNil(t, findSetupCookie(t, w), "input %q should have been issued a cookie", curr)
		}
	})

	t.Run("wrong code re-renders with an error and issues no cookie", func(t *testing.T) {
		for _, curr := range []string{
			"",
			"NOPE",
			testSetupCode + "X",
			testSetupCode[:len(testSetupCode)-1],
		} {
			_, _, _, e := makeTestEnv(t)

			w := postSetupCode(t, e, curr)

			assert.Equal(t, http.StatusOK, w.Result().StatusCode, "input %q should not have redirected", curr)
			assert.Contains(t, w.Body.String(), "Invalid setup code", "input %q should have been rejected", curr)
			assert.Nil(t, findSetupCookie(t, w), "input %q should not have been issued a cookie", curr)
		}
	})

	t.Run("CSRF detection", func(t *testing.T) {
		_, _, _, e := makeTestEnv(t)

		v := url.Values{}
		v.Add("setup_code", testSetupCode)

		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(v.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Sec-Fetch-Site", "cross-site")
		w := httptest.NewRecorder()

		e.buildMux(StepStartFromBeginning).ServeHTTP(w, r)

		assert.Equal(t, http.StatusForbidden, w.Result().StatusCode)
		assert.Nil(t, findSetupCookie(t, w))
	})
}

func TestFtueEnv_SetupCodeProtection(t *testing.T) {
	render.Init()

	// check every page other than the main "enter setup code" one
	protected := []string{
		"/begin",
		"/ftue/step0",
		"/ftue/step1",
		"/ftue/scratch",
		"/ftue/import",
		"/ftue/restart",
	}

	t.Run("no cookie is unauthorized", func(t *testing.T) {
		for _, curr := range protected {
			_, _, _, e := makeTestEnv(t)

			r := httptest.NewRequest(http.MethodGet, curr, nil)
			w := httptest.NewRecorder()

			e.buildMux(StepStartFromBeginning).ServeHTTP(w, r)

			assert.Equal(t, http.StatusUnauthorized, w.Result().StatusCode, "%s should require a setup cookie", curr)
		}
	})

	t.Run("undecodable cookie is forbidden", func(t *testing.T) {
		for _, curr := range protected {
			_, _, _, e := makeTestEnv(t)

			r := httptest.NewRequest(http.MethodGet, curr, nil)
			r.AddCookie(&http.Cookie{Name: session.FTUESessionCookieName, Value: "i-am-not-a-real-cookie"})
			w := httptest.NewRecorder()

			e.buildMux(StepStartFromBeginning).ServeHTTP(w, r)

			assert.Equal(t, http.StatusForbidden, w.Result().StatusCode, "%s should reject a garbage cookie", curr)
		}
	})

	t.Run("validly signed cookie carrying the wrong code is forbidden", func(t *testing.T) {
		for _, curr := range protected {
			_, _, _, e := makeTestEnv(t)

			// valid signed cookie, wrong code
			encoded, err := e.protector.EncodeValidCookie(testSetupCode + "-NOT-IT")
			require.NoError(t, err)

			r := httptest.NewRequest(http.MethodGet, curr, nil)
			r.AddCookie(&http.Cookie{Name: session.FTUESessionCookieName, Value: encoded})
			w := httptest.NewRecorder()

			e.buildMux(StepStartFromBeginning).ServeHTTP(w, r)

			assert.Equal(t, http.StatusForbidden, w.Result().StatusCode, "%s should reject a cookie with the wrong code", curr)
		}
	})

	t.Run("cookie from a different server instance is forbidden", func(t *testing.T) {
		for _, curr := range protected {
			_, _, _, e := makeTestEnv(t)

			// correct code, wrong keys
			other := session.NewMiddleware(testSetupCode)
			encoded, err := other.EncodeValidCookie(testSetupCode)
			require.NoError(t, err)

			r := httptest.NewRequest(http.MethodGet, curr, nil)
			r.AddCookie(&http.Cookie{Name: session.FTUESessionCookieName, Value: encoded})
			w := httptest.NewRecorder()

			e.buildMux(StepStartFromBeginning).ServeHTTP(w, r)

			assert.Equal(t, http.StatusForbidden, w.Result().StatusCode, "%s should reject a foreign cookie", curr)
		}
	})

	t.Run("the code prompt and static assets stay reachable", func(t *testing.T) {
		for _, curr := range []string{"/", "/static/css/auththingie2.css"} {
			_, _, _, e := makeTestEnv(t)

			r := httptest.NewRequest(http.MethodGet, curr, nil)
			w := httptest.NewRecorder()

			e.buildMux(StepStartFromBeginning).ServeHTTP(w, r)

			assert.Equal(t, http.StatusOK, w.Result().StatusCode, "%s should be reachable without a cookie", curr)
		}
	})
}
