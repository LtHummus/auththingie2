package handlers

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"

	"github.com/lthummus/auththingie2/internal/trueip"

	"github.com/lthummus/auththingie2/internal/config"
	session2 "github.com/lthummus/auththingie2/internal/middlewares/session"
	"github.com/lthummus/auththingie2/internal/pwvalidate"
	"github.com/lthummus/auththingie2/internal/render"
	"github.com/lthummus/auththingie2/internal/rules"
	"github.com/lthummus/auththingie2/internal/user"

	"github.com/google/uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	_ "github.com/lthummus/auththingie2/internal/ainit"
)

const sourceIPHeader = "X-Forwarded-For"

type testRequestOption = func(sess *session2.Session)

func withLoginTime(time time.Time) testRequestOption {
	return func(sess *session2.Session) {
		sess.LoginTime = time
	}
}

func buildUserCookie(t *testing.T, e *Env, user *user.User) *session2.Session {
	if user != nil && user.Id == "" {
		user.Id = strings.Trim(uuid.New().String(), "-")
	}

	sess, err := session2.NewDefaultSession(e.Configuration)
	require.NoError(t, err)

	if user != nil {
		sess.UserID = user.Id
	}

	return &sess
}

func setAttachHeaders(t *testing.T, v *viper.Viper) {
	v.Set(config.ConfigKeyAttachUserIDAuthResponseHeader, "Id-Header")
	v.Set(config.ConfigKeyAttachUsernameAuthResponseHeader, "Username-Header")
}

func validateHeaders(t *testing.T, id string, username string, r *http.Response) {
	assert.Equal(t, id, r.Header.Get("Id-Header"))
	assert.Equal(t, username, r.Header.Get("Username-Header"))
}

func buildTestRequest(t *testing.T, e *Env, user *user.User, options ...testRequestOption) *http.Request {
	h := http.Header{}
	h.Add(httpMethodHeader, "GET")
	h.Add(protocolHeader, "https")
	h.Add(hostHeader, "download.example.com")
	h.Add(requestURIHeader, "/")
	h.Add(sourceIPHeader, "10.0.0.1")
	r, _ := http.NewRequest(http.MethodGet, "/check", nil)
	r.Header = h

	sess := buildUserCookie(t, e, user)

	for _, curr := range options {
		curr(sess)
	}

	r.AddCookie(&http.Cookie{
		Name:  session2.SessionCookieName,
		Value: sess.SessionID,
	})

	r.RemoteAddr = "127.0.0.1:29583"

	// so much copying :(
	return session2.ArbitraryAttachSession(*sess, r, user, nil)
}

func TestEnv_HandleAccountDisabled(t *testing.T) {
	render.Init()

	t.Run("basic case", func(t *testing.T) {
		w := httptest.NewRecorder()
		_, _, _, _, _, _, e := makeTestEnv(t)
		r := buildTestRequest(t, e, &user.User{Username: "sample-user", Disabled: true})

		e.HandleAccountDisabled(w, r)

		resp := w.Result()

		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		assert.Contains(t, w.Body.String(), "Your account has been disabled. You are currently logged in as <strong>sample-user</strong>")
	})
}

func TestPullInfoFromRequest(t *testing.T) {
	h := http.Header{}
	h.Add(httpMethodHeader, "GET")
	h.Add(protocolHeader, "https")
	h.Add(hostHeader, "download.example.com")
	h.Add(requestURIHeader, "/somepage.html?foo=bar")
	h.Add(sourceIPHeader, "10.0.0.1")
	r, _ := http.NewRequest(http.MethodGet, "/check", nil)
	r.Header = h

	ri := pullInfoFromRequest(r)

	assert.Equal(t, "GET", ri.Method)
	assert.Equal(t, "https", ri.Protocol)
	assert.Equal(t, "download.example.com", ri.Host)
	assert.Equal(t, "/somepage.html", ri.RequestURI)
	assert.Equal(t, "foo=bar", ri.QueryString)
	assert.Equal(t, net.ParseIP("10.0.0.1"), ri.SourceIP)
}

func TestEnv_HandleNotAllowed(t *testing.T) {
	render.Init()

	t.Run("not logged in", func(t *testing.T) {
		w := httptest.NewRecorder()
		_, _, _, _, _, _, e := makeTestEnv(t)
		r := buildTestRequest(t, e, nil)

		e.HandleNotAllowed(w, r)

		resp := w.Result()

		assert.Equal(t, http.StatusForbidden, resp.StatusCode)

		assert.Contains(t, w.Body.String(), "<strong>&lt;not logged in&gt;</strong>")
	})

	t.Run("with logged in user", func(t *testing.T) {
		w := httptest.NewRecorder()
		_, _, _, _, _, _, e := makeTestEnv(t)
		r := buildTestRequest(t, e, &user.User{Username: "test-user"})

		e.HandleNotAllowed(w, r)

		resp := w.Result()

		assert.Equal(t, http.StatusForbidden, resp.StatusCode)

		assert.Contains(t, w.Body.String(), "test-user")
	})

}

func TestEnv_HandleCheckRequest(t *testing.T) {
	v := viper.New()
	v.Set(config.ConfigKeyTrustedProxyNetwork, []string{"127.0.0.1"})
	trueip.Initialize(t.Context(), v)
	t.Cleanup(func() {
		trueip.TearDown(t.Context())
	})

	t.Run("reject requests from non-trusted proxy", func(t *testing.T) {
		_, _, _, _, _, _, e := makeTestEnv(t)
		r := buildTestRequest(t, e, nil)
		r.RemoteAddr = "99.99.99.99:9999"

		w := httptest.NewRecorder()
		e.HandleCheckRequest(w, r)

		assert.Equal(t, http.StatusForbidden, w.Result().StatusCode)
	})

	t.Run("reject requests that can't be redirected to", func(t *testing.T) {
		_, _, _, _, ruriv, _, e := makeTestEnv(t)
		r := buildTestRequest(t, e, nil)

		ruriv.On("IsAllowed", "https://download.example.com/").Return(false)

		w := httptest.NewRecorder()
		e.HandleCheckRequest(w, r)

		assert.Equal(t, http.StatusForbidden, w.Result().StatusCode)
		assert.Equal(t, "invalid url attempted to be checked; this is probably a configuration error\n", w.Body.String())
	})

	t.Run("handle matches no rules; no user", func(t *testing.T) {
		a, _, _, _, ruriv, _, e := makeTestEnv(t)
		r := buildTestRequest(t, e, nil)

		ruriv.On("IsAllowed", "https://download.example.com/").Return(true)
		a.On("MatchesRule", mock.Anything).Return(nil)

		w := httptest.NewRecorder()
		e.HandleCheckRequest(w, r)

		resp := w.Result()
		assert.Equal(t, http.StatusFound, resp.StatusCode)
		redirectURL, err := resp.Location()
		require.NoError(t, err)
		assert.Equal(t, loginMessageNotLoggedIn, redirectURL.Query().Get(loginMessageParam))
		assert.Equal(t, "/login", redirectURL.Path)
		assert.Equal(t, "https://download.example.com/", redirectURL.Query().Get(redirectURLParam))

		// check to make sure the rule was passed properly
		ri := a.Calls[0].Arguments[0].(*rules.RequestInfo)

		assert.True(t, ri.Valid())
		assert.Equal(t, http.MethodGet, ri.Method)
		assert.Equal(t, "https", ri.Protocol)
		assert.Equal(t, "download.example.com", ri.Host)
		assert.Equal(t, "/", ri.RequestURI)
		assert.Equal(t, "10.0.0.1", ri.SourceIP.String())
	})

	t.Run("no rule, but user is admin", func(t *testing.T) {
		a, _, _, _, ruriv, _, e := makeTestEnv(t)
		r := buildTestRequest(t, e, &user.User{Id: "5", Username: "test", Admin: true})

		ruriv.On("IsAllowed", "https://download.example.com/").Return(true)
		a.On("MatchesRule", mock.Anything).Return(nil)

		w := httptest.NewRecorder()
		e.HandleCheckRequest(w, r)

		resp := w.Result()

		assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	})

	t.Run("no rule, user is admin, header should be attached", func(t *testing.T) {
		a, _, _, _, ruriv, v, e := makeTestEnv(t)
		r := buildTestRequest(t, e, &user.User{Id: "5", Username: "test", Admin: true})

		setAttachHeaders(t, v)

		ruriv.On("IsAllowed", "https://download.example.com/").Return(true)
		a.On("MatchesRule", mock.Anything).Return(nil)

		w := httptest.NewRecorder()
		e.HandleCheckRequest(w, r)

		resp := w.Result()

		assert.Equal(t, http.StatusNoContent, resp.StatusCode)
		validateHeaders(t, "5", "test", resp)
	})

	t.Run("yes rule, user is admin", func(t *testing.T) {
		a, _, _, _, ruriv, _, e := makeTestEnv(t)
		r := buildTestRequest(t, e, &user.User{Username: "test", Admin: true})

		ruriv.On("IsAllowed", "https://download.example.com/").Return(true)
		a.On("MatchesRule", mock.Anything).Return(&rules.Rule{})

		w := httptest.NewRecorder()
		e.HandleCheckRequest(w, r)

		resp := w.Result()

		assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	})

	t.Run("yes rule, user is admin, headers attached", func(t *testing.T) {
		a, _, _, _, ruriv, v, e := makeTestEnv(t)
		r := buildTestRequest(t, e, &user.User{Id: "5", Username: "test", Admin: true})

		ruriv.On("IsAllowed", "https://download.example.com/").Return(true)
		a.On("MatchesRule", mock.Anything).Return(&rules.Rule{})

		setAttachHeaders(t, v)

		w := httptest.NewRecorder()
		e.HandleCheckRequest(w, r)

		resp := w.Result()

		assert.Equal(t, http.StatusNoContent, resp.StatusCode)
		validateHeaders(t, "5", "test", resp)
	})

	t.Run("yes rule, non-admin, group is allowed", func(t *testing.T) {
		a, _, _, _, ruriv, _, e := makeTestEnv(t)
		r := buildTestRequest(t, e, &user.User{Username: "test", Admin: false, Roles: []string{"foo"}})

		ruriv.On("IsAllowed", "https://download.example.com/").Return(true)
		a.On("MatchesRule", mock.Anything).Return(&rules.Rule{PermittedRoles: []string{"foo", "bar"}})

		w := httptest.NewRecorder()
		e.HandleCheckRequest(w, r)

		resp := w.Result()

		assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	})

	t.Run("yes rule, non-admin, group allowed, headers attached", func(t *testing.T) {
		a, _, _, _, ruriv, v, e := makeTestEnv(t)
		r := buildTestRequest(t, e, &user.User{Id: "1234", Username: "test", Admin: false, Roles: []string{"foo"}})

		ruriv.On("IsAllowed", "https://download.example.com/").Return(true)
		a.On("MatchesRule", mock.Anything).Return(&rules.Rule{PermittedRoles: []string{"foo", "bar"}})

		setAttachHeaders(t, v)

		w := httptest.NewRecorder()
		e.HandleCheckRequest(w, r)

		resp := w.Result()

		assert.Equal(t, http.StatusNoContent, resp.StatusCode)
		validateHeaders(t, "1234", "test", resp)
	})

	t.Run("yes rule, non-admin, user is not allowed", func(t *testing.T) {
		a, _, _, _, ruriv, _, e := makeTestEnv(t)
		r := buildTestRequest(t, e, &user.User{Username: "test", Admin: false, Roles: []string{"foo"}})

		ruriv.On("IsAllowed", "https://download.example.com/").Return(true)
		a.On("MatchesRule", mock.Anything).Return(&rules.Rule{PermittedRoles: []string{"bar"}})

		w := httptest.NewRecorder()
		e.HandleCheckRequest(w, r)

		resp := w.Result()

		assert.Equal(t, http.StatusFound, resp.StatusCode)

		redirectLocation, err := resp.Location()
		assert.NoError(t, err)
		assert.Equal(t, "/forbidden", redirectLocation.Path)
	})

	t.Run("yes rule, non-admin, basic auth, role not allowed", func(t *testing.T) {
		a, _, _, pwv, ruriv, _, e := makeTestEnv(t)
		r := buildTestRequest(t, e, nil)
		r.SetBasicAuth("username", "test1")

		ruriv.On("IsAllowed", "https://download.example.com/").Return(true)
		pwv.On("Validate", mock.Anything, "username", "test1", "10.0.0.1").Return(&user.User{Username: "test",
			PasswordHash: "$argon2id$v=19$m=65536,t=3,p=2$dwWG0v/k39J/7eB5D2gCZw$jnLnqbck1oa2e5scSSQAy4THJUR734LEq6XTunB7678",
			Admin:        false,
			Roles:        []string{"foo"},
		}, nil)
		a.On("MatchesRule", mock.Anything).Return(&rules.Rule{PermittedRoles: []string{"bar"}})

		w := httptest.NewRecorder()
		e.HandleCheckRequest(w, r)

		resp := w.Result()

		assert.Equal(t, http.StatusFound, resp.StatusCode)
		redirectURL, err := resp.Location()
		require.NoError(t, err)

		assert.Equal(t, "/forbidden", redirectURL.Path)
	})

	t.Run("basic auth invalid credentials", func(t *testing.T) {
		a, _, _, pwv, ruriv, _, e := makeTestEnv(t)
		r := buildTestRequest(t, e, nil)
		r.SetBasicAuth("username", "test2")

		ruriv.On("IsAllowed", "https://download.example.com/").Return(true)
		pwv.On("Validate", mock.Anything, "username", "test2", "10.0.0.1").Return(nil, &pwvalidate.InvalidUsernamePasswordError{})
		a.On("MatchesRule", mock.Anything).Return(&rules.Rule{PermittedRoles: []string{"bar"}})

		w := httptest.NewRecorder()
		e.HandleCheckRequest(w, r)

		resp := w.Result()

		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		assert.Contains(t, w.Body.String(), "invalid credentials")
	})

	t.Run("yes rule, non-admin, has TOTP w/ basic auth", func(t *testing.T) {
		a, _, _, pwv, ruriv, _, e := makeTestEnv(t)
		r := buildTestRequest(t, e, nil)
		r.SetBasicAuth("username", "test1")
		r.RemoteAddr = "127.0.0.1:9999"

		ruriv.On("IsAllowed", "https://download.example.com/").Return(true)
		pwv.On("Validate", mock.Anything, "username", "test1", "10.0.0.1").Return(&user.User{Username: "test",
			PasswordHash: "$argon2id$v=19$m=65536,t=3,p=2$dwWG0v/k39J/7eB5D2gCZw$jnLnqbck1oa2e5scSSQAy4THJUR734LEq6XTunB7678",
			Admin:        false,
			Roles:        []string{"foo"},
			TOTPSeed:     &sampleTOTPSeed,
		}, nil)
		a.On("MatchesRule", mock.Anything).Return(&rules.Rule{PermittedRoles: []string{"foo"}})

		w := httptest.NewRecorder()
		e.HandleCheckRequest(w, r)

		resp := w.Result()

		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		assert.Contains(t, w.Body.String(), "Can not use basic auth with TOTP enabled")
	})

	t.Run("yes rule, non-admin, has TOTP w/ passkeys", func(t *testing.T) {
		a, _, _, pwv, ruriv, _, e := makeTestEnv(t)
		r := buildTestRequest(t, e, nil)
		r.SetBasicAuth("username", "test1")
		r.RemoteAddr = "127.0.0.1:9999"

		ruriv.On("IsAllowed", "https://download.example.com/").Return(true)
		pwv.On("Validate", mock.Anything, "username", "test1", "10.0.0.1").Return(&user.User{
			Username:     "test",
			PasswordHash: "$argon2id$v=19$m=65536,t=3,p=2$dwWG0v/k39J/7eB5D2gCZw$jnLnqbck1oa2e5scSSQAy4THJUR734LEq6XTunB7678",
			Admin:        false,
			Roles:        []string{"foo"},
			StoredCredentials: []user.Passkey{
				{}, // force one passkey
			},
		}, nil)
		a.On("MatchesRule", mock.Anything).Return(&rules.Rule{PermittedRoles: []string{"foo"}})

		w := httptest.NewRecorder()
		e.HandleCheckRequest(w, r)

		resp := w.Result()

		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		assert.Contains(t, w.Body.String(), "Can not use basic auth with passkeys enabled")
	})

	t.Run("yes rule, non-admin, user is disabled", func(t *testing.T) {
		a, _, _, _, ruriv, _, e := makeTestEnv(t)
		r := buildTestRequest(t, e, &user.User{Username: "test", Admin: false, Roles: []string{"foo"}, Disabled: true})

		ruriv.On("IsAllowed", "https://download.example.com/").Return(true)
		a.On("MatchesRule", mock.Anything).Return(&rules.Rule{PermittedRoles: []string{"foo"}})
		w := httptest.NewRecorder()
		e.HandleCheckRequest(w, r)

		resp := w.Result()

		assert.Equal(t, http.StatusFound, resp.StatusCode)

		redirectLocation, err := resp.Location()
		assert.NoError(t, err)
		assert.Equal(t, "/disabled", redirectLocation.Path)

	})

	t.Run("yes rule, rule is public, no user", func(t *testing.T) {
		a, _, _, _, ruriv, _, e := makeTestEnv(t)
		r := buildTestRequest(t, e, nil)

		ruriv.On("IsAllowed", "https://download.example.com/").Return(true)
		a.On("MatchesRule", mock.Anything).Return(&rules.Rule{Public: true})

		w := httptest.NewRecorder()
		e.HandleCheckRequest(w, r)

		resp := w.Result()

		assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	})

	t.Run("yes rule, rule is public, no user, attach headers", func(t *testing.T) {
		a, _, _, _, ruriv, v, e := makeTestEnv(t)
		r := buildTestRequest(t, e, nil)

		ruriv.On("IsAllowed", "https://download.example.com/").Return(true)
		a.On("MatchesRule", mock.Anything).Return(&rules.Rule{Public: true})

		setAttachHeaders(t, v)

		w := httptest.NewRecorder()
		e.HandleCheckRequest(w, r)

		resp := w.Result()

		assert.Equal(t, http.StatusNoContent, resp.StatusCode)
		validateHeaders(t, publicUserIDHeaderValue, publicUsernameHeaderValue, resp)
	})

	t.Run("yes rule, rule is public, disabled user", func(t *testing.T) {
		a, _, _, _, ruriv, v, e := makeTestEnv(t)
		r := buildTestRequest(t, e, sampleDisabledUser)

		ruriv.On("IsAllowed", "https://download.example.com/").Return(true)
		a.On("MatchesRule", mock.Anything).Return(&rules.Rule{Public: true})

		setAttachHeaders(t, v)

		w := httptest.NewRecorder()
		e.HandleCheckRequest(w, r)

		resp := w.Result()

		assert.Equal(t, http.StatusNoContent, resp.StatusCode)
		validateHeaders(t, publicUserIDHeaderValue, publicUsernameHeaderValue, resp)

	})

	t.Run("yes rule, rule is public, disabled user, attach headers", func(t *testing.T) {
		a, _, _, _, ruriv, _, e := makeTestEnv(t)
		r := buildTestRequest(t, e, sampleDisabledUser)

		ruriv.On("IsAllowed", "https://download.example.com/").Return(true)
		a.On("MatchesRule", mock.Anything).Return(&rules.Rule{Public: true})

		w := httptest.NewRecorder()
		e.HandleCheckRequest(w, r)

		resp := w.Result()

		assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	})

	t.Run("invalid headers specified", func(t *testing.T) {
		_, _, _, _, _, _, e := makeTestEnv(t)
		r := httptest.NewRequest(http.MethodGet, "/check", nil)
		r.RemoteAddr = "127.0.0.1:9987"

		w := httptest.NewRecorder()
		e.HandleCheckRequest(w, r)

		resp := w.Result()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("invalid cookie", func(t *testing.T) {
		a, _, _, _, ruriv, _, e := makeTestEnv(t)
		r := buildTestRequest(t, e, nil)
		r.AddCookie(&http.Cookie{
			Name:  session2.SessionCookieName,
			Value: "lol",
		})

		ruriv.On("IsAllowed", "https://download.example.com/").Return(true)
		a.On("MatchesRule", mock.Anything).Return(nil)

		w := httptest.NewRecorder()
		e.HandleCheckRequest(w, r)

		resp := w.Result()

		assert.Equal(t, http.StatusFound, resp.StatusCode)
		redirectURL, err := resp.Location()
		require.NoError(t, err)
		assert.Equal(t, loginMessageNotLoggedIn, redirectURL.Query().Get(loginMessageParam))
	})

	t.Run("works with duration (still in time)", func(t *testing.T) {
		a, _, _, _, ruriv, _, e := makeTestEnv(t)
		r := buildTestRequest(t, e, &user.User{Id: "5", Username: "test", Admin: false, Roles: []string{"a", "b"}}, withLoginTime(time.Now().Add(-1*time.Minute)))

		ruriv.On("IsAllowed", "https://download.example.com/").Return(true)
		a.On("MatchesRule", mock.Anything).Return(&rules.Rule{
			PermittedRoles: []string{"a"},
			Timeout:        new(5 * time.Minute),
		})

		w := httptest.NewRecorder()
		e.HandleCheckRequest(w, r)

		resp := w.Result()

		assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	})

	t.Run("works with duration (needs to reauth)", func(t *testing.T) {
		a, _, _, _, ruriv, _, e := makeTestEnv(t)
		r := buildTestRequest(t, e, &user.User{Id: "5", Username: "test", Admin: false, Roles: []string{"a", "b"}}, withLoginTime(time.Now().Add(-1*time.Hour)))

		a.On("MatchesRule", mock.Anything).Return(&rules.Rule{
			PermittedRoles: []string{"a"},
			Timeout:        new(5 * time.Minute),
		})
		ruriv.On("IsAllowed", "https://download.example.com/").Return(true)

		w := httptest.NewRecorder()
		e.HandleCheckRequest(w, r)

		resp := w.Result()

		assert.Equal(t, http.StatusFound, resp.StatusCode)
		redirectURL, err := resp.Location()
		require.NoError(t, err)
		assert.Equal(t, loginMessageRuleRequiresSecondLogin, redirectURL.Query().Get(loginMessageParam))
		assert.Equal(t, "/login", redirectURL.Path)
		assert.Equal(t, "https://download.example.com/", redirectURL.Query().Get(redirectURLParam))
	})
}
