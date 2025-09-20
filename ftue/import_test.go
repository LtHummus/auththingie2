package ftue

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/lthummus/auththingie2/render"
	"github.com/lthummus/auththingie2/rules"
	"github.com/lthummus/auththingie2/user"
)

var (
	importKeyExtractRegex = regexp.MustCompile(`<input type="hidden" name="import_key" value="([0-9a-f]*)" />`)
)

const (
	goodImportText = `auththingie {
  siteName: "Test Site"
  timeout: 24h
  timeZone: America/Los_Angeles
  domain: example.com

  rules: [
   {
      "name": "Keys",
      "hostPattern": "keys.example.com",
      "pathPattern": "*",
      "permittedRoles": [],
      "public": true
    },
    {
      "name": "Play Test",
      "hostPattern": "guess.example.com",
      "pathPattern": "*",
      "permittedRoles": ["a"],
      "public": false
    }
  ]

  users: [
    {
      "htpasswdLine": "test:$2y$10$/0OcSuJa/CxSEVwOUdhtZeHlfCUFTV6pswaSl6BPlnedEIxlAypVi",
      "admin": true,
      "duoEnabled": true,
      "totpSecret":  "JBSWY3DPEHPK3PXP",
      "roles": []
    },
    {
      "htpasswdLine": "someuser:$2y$10$NPcVe61oWn/VB8ktVgfUbuyhoHZqKnVt5FI.QgC0vV4MHaOutybwu",
      "admin": false,
      "roles": ["a"]
    }
  ]

  authSiteUrl: "https://auth.example.com"


}
`
)

func TestFtueEnv_HandleRenderImportPage(t *testing.T) {
	render.Init()

	t.Run("just render", func(t *testing.T) {
		_, _, e := makeTestEnv(t)

		r := httptest.NewRequest(http.MethodGet, "/ftue/import", nil)
		w := httptest.NewRecorder()

		e.buildMux(StepStartFromBeginning).ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "This will import as much as we can from the AuthThingie 1 config file. You can either upload the config file yourself or you can")
		assert.Contains(t, w.Body.String(), "paste the context in the text area below.")
		assert.Contains(t, w.Body.String(), `<form action="/ftue/import" method="post">`)
		assert.Contains(t, w.Body.String(), `<button type="submit" class="contrast">Import</button>`)
	})
}

func TestFtueEnv_HandlerImportPageUpload(t *testing.T) {
	render.Init()
	initCache()

	t.Run("empty config file test", func(t *testing.T) {
		_, _, e := makeTestEnv(t)

		r := httptest.NewRequest(http.MethodPost, "/ftue/import", nil)
		w := httptest.NewRecorder()

		e.buildMux(StepStartFromBeginning).ServeHTTP(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "no contents")
	})

	t.Run("error in config parse", func(t *testing.T) {
		contents := `---AAA___A__)(!(*@#$)(A*S()*(`

		_, _, e := makeTestEnv(t)

		v := url.Values{}
		v.Add("config_file_text", contents)

		r := httptest.NewRequest(http.MethodPost, "/ftue/import", strings.NewReader(v.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		e.buildMux(StepStartFromBeginning).ServeHTTP(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "could not parse config file")
	})

	t.Run("valid config file parse", func(t *testing.T) {
		_, _, e := makeTestEnv(t)

		v := url.Values{}
		v.Add("config_file_text", goodImportText)

		r := httptest.NewRequest(http.MethodPost, "/ftue/import", strings.NewReader(v.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		e.buildMux(StepStartFromBeginning).ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), `<h2>Confirm Users and Rules</h2>`)
		assert.Contains(t, w.Body.String(), `<td>test</td>`)
		assert.Contains(t, w.Body.String(), `<td>someuser</td>`)
		assert.Contains(t, w.Body.String(), `<td>keys.example.com</td>`)
		assert.Contains(t, w.Body.String(), `<td>Play Test</td>`)
		assert.Contains(t, w.Body.String(), `<td>guess.example.com</td>`)
		assert.Contains(t, w.Body.String(), `<form action="/ftue/import/confirm" method="post">`)
		require.Regexp(t, importKeyExtractRegex, w.Body.String())

		importKey := importKeyExtractRegex.FindStringSubmatch(w.Body.String())[1]

		importResult := importCache.Get(importKey)
		assert.NotNil(t, importResult)
	})
}

func TestFtueEnv_HandleImportConfirm(t *testing.T) {
	render.Init()
	initCache()

	t.Run("import key missing", func(t *testing.T) {
		_, _, e := makeTestEnv(t)

		v := url.Values{}
		v.Add("import_key", "")

		r := httptest.NewRequest(http.MethodPost, "/ftue/import/confirm", strings.NewReader(v.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		e.buildMux(StepStartFromBeginning).ServeHTTP(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "empty import key")
	})

	t.Run("invalid import key", func(t *testing.T) {
		_, _, e := makeTestEnv(t)

		v := url.Values{}
		v.Add("import_key", "thisimportkeydoesnotexist")

		r := httptest.NewRequest(http.MethodPost, "/ftue/import/confirm", strings.NewReader(v.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		e.buildMux(StepStartFromBeginning).ServeHTTP(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "no import data found")
	})

	t.Run("fail to create user", func(t *testing.T) {
		db, _, e := makeTestEnv(t)

		v := url.Values{}
		v.Add("config_file_text", goodImportText)

		r := httptest.NewRequest(http.MethodPost, "/ftue/import", strings.NewReader(v.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		e.buildMux(StepStartFromBeginning).ServeHTTP(w, r)

		importKey := importKeyExtractRegex.FindStringSubmatch(w.Body.String())[1]

		v2 := url.Values{}
		v2.Add("import_key", importKey)

		r2 := httptest.NewRequest(http.MethodPost, "/ftue/import/confirm", strings.NewReader(v2.Encode()))
		r2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w2 := httptest.NewRecorder()

		db.On("CreateUser", mock.Anything, mock.AnythingOfType("*user.User")).Return(errors.New("oh no"))

		e.buildMux(StepStartFromBeginning).ServeHTTP(w2, r2)

		assert.Equal(t, http.StatusInternalServerError, w2.Result().StatusCode)
		assert.Contains(t, w2.Body.String(), "could not create user")

	})

	t.Run("fail to write config file", func(t *testing.T) {
		db, a, e := makeTestEnv(t)

		v := url.Values{}
		v.Add("config_file_text", goodImportText)

		r := httptest.NewRequest(http.MethodPost, "/ftue/import", strings.NewReader(v.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		e.buildMux(StepStartFromBeginning).ServeHTTP(w, r)

		importKey := importKeyExtractRegex.FindStringSubmatch(w.Body.String())[1]

		v2 := url.Values{}
		v2.Add("import_key", importKey)

		r2 := httptest.NewRequest(http.MethodPost, "/ftue/import/confirm", strings.NewReader(v2.Encode()))
		r2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w2 := httptest.NewRecorder()

		db.On("CreateUser", mock.Anything, mock.AnythingOfType("*user.User")).Return(nil)
		db.On("CreateUser", mock.Anything, mock.AnythingOfType("*user.User")).Return(nil)

		a.On("AddRule", mock.AnythingOfType("rules.Rule"))
		a.On("AddRule", mock.AnythingOfType("rules.Rule"))
		a.On("WriteConfig").Return(errors.New("whoops"))

		e.buildMux(StepStartFromBeginning).ServeHTTP(w2, r2)

		assert.Equal(t, http.StatusInternalServerError, w2.Result().StatusCode)
		assert.Contains(t, w2.Body.String(), "could not write config file")

	})

	t.Run("happy case (full flow)", func(t *testing.T) {
		db, a, e := makeTestEnv(t)

		v := url.Values{}
		v.Add("config_file_text", goodImportText)

		r := httptest.NewRequest(http.MethodPost, "/ftue/import", strings.NewReader(v.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		e.buildMux(StepStartFromBeginning).ServeHTTP(w, r)

		importKey := importKeyExtractRegex.FindStringSubmatch(w.Body.String())[1]

		v2 := url.Values{}
		v2.Add("import_key", importKey)

		r2 := httptest.NewRequest(http.MethodPost, "/ftue/import/confirm", strings.NewReader(v2.Encode()))
		r2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w2 := httptest.NewRecorder()

		db.On("CreateUser", mock.Anything, mock.AnythingOfType("*user.User")).Return(nil)
		db.On("CreateUser", mock.Anything, mock.AnythingOfType("*user.User")).Return(nil)

		a.On("AddRule", mock.AnythingOfType("rules.Rule"))
		a.On("AddRule", mock.AnythingOfType("rules.Rule"))
		a.On("WriteConfig").Return(nil)

		e.buildMux(StepStartFromBeginning).ServeHTTP(w2, r2)

		assert.Equal(t, http.StatusFound, w2.Result().StatusCode)
		redirectURL, err := w2.Result().Location()
		require.NoError(t, err)
		assert.Equal(t, "/ftue/restart", redirectURL.Path)

		u1 := db.Mock.Calls[0].Arguments[1].(*user.User)
		assert.Equal(t, "test", u1.Username)
		assert.Equal(t, "$2y$10$/0OcSuJa/CxSEVwOUdhtZeHlfCUFTV6pswaSl6BPlnedEIxlAypVi", u1.PasswordHash)
		assert.True(t, u1.Admin)
		assert.Equal(t, "JBSWY3DPEHPK3PXP", *u1.TOTPSeed)

		u2 := db.Mock.Calls[1].Arguments[1].(*user.User)
		assert.Equal(t, "someuser", u2.Username)
		assert.Equal(t, "$2y$10$NPcVe61oWn/VB8ktVgfUbuyhoHZqKnVt5FI.QgC0vV4MHaOutybwu", u2.PasswordHash)
		assert.False(t, u2.Admin)
		assert.Nil(t, u2.TOTPSeed)
		assert.Equal(t, []string{"a"}, u2.Roles)

		rule1 := a.Mock.Calls[0].Arguments[0].(rules.Rule)
		assert.Equal(t, "Keys", rule1.Name)
		require.NotNil(t, rule1.HostPattern)
		assert.Equal(t, "keys.example.com", *rule1.HostPattern)
		assert.True(t, rule1.Public)

		rule2 := a.Mock.Calls[1].Arguments[0].(rules.Rule)
		assert.Equal(t, "Play Test", rule2.Name)
		require.NotNil(t, rule2.HostPattern)
		assert.Equal(t, "guess.example.com", *rule2.HostPattern)
		require.NotNil(t, rule2.PathPattern)
		assert.Equal(t, "*", *rule2.PathPattern)
		assert.False(t, rule2.Public)
		assert.Equal(t, []string{"a"}, rule2.PermittedRoles)

	})
}
