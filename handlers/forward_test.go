package handlers

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	session2 "github.com/lthummus/auththingie2/middlewares/session"
	"github.com/lthummus/auththingie2/render"
	rules2 "github.com/lthummus/auththingie2/rules"
	"github.com/lthummus/auththingie2/user"

	"github.com/google/uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	_ "github.com/lthummus/auththingie2/ainit"
	"github.com/lthummus/auththingie2/mocks"
)

const sourceIPHeader = "X-Forwarded-For"

type testRequestOption = func(sess *session2.Session)

func withLoginTime(time time.Time) testRequestOption {
	return func(sess *session2.Session) {
		sess.LoginTime = time
	}
}

func buildTestEnv(t *testing.T) (*mocks.Analyzer, *Env) {
	a := mocks.NewAnalyzer(t)
	db := mocks.NewDB(t)
	return a, &Env{
		Analyzer: a,
		Database: db,
	}
}

func buildUserCookie(t *testing.T, e *Env, user *user.User) *session2.Session {
	if user != nil && user.Id == "" {
		user.Id = strings.Trim(uuid.New().String(), "-")
	}

	sess, err := session2.NewDefaultSession()
	require.NoError(t, err)

	if user != nil {
		sess.UserID = user.Id
	}

	return &sess
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

	// so much copying :(
	return session2.ArbitraryAttachSession(*sess, r, user, nil)
}

func TestEnv_HandleNotAllowed(t *testing.T) {
	render.Init()

	t.Run("not logged in", func(t *testing.T) {
		w := httptest.NewRecorder()
		_, e := buildTestEnv(t)
		r := buildTestRequest(t, e, nil)

		e.HandleNotAllowed(w, r)

		resp := w.Result()

		assert.Equal(t, http.StatusForbidden, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		resp.Body.Close()

		assert.Contains(t, string(body), "<strong>&lt;not logged in&gt;</strong>")
	})

	t.Run("with logged in user", func(t *testing.T) {
		w := httptest.NewRecorder()
		_, e := buildTestEnv(t)
		r := buildTestRequest(t, e, &user.User{Username: "test-user"})

		e.HandleNotAllowed(w, r)

		resp := w.Result()

		assert.Equal(t, http.StatusForbidden, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		resp.Body.Close()

		assert.Contains(t, string(body), "test-user")
	})

}

func TestEnv_HandleCheckRequest(t *testing.T) {
	t.Run("handle matches no rules; no user", func(t *testing.T) {
		a, e := buildTestEnv(t)
		r := buildTestRequest(t, e, nil)

		a.On("MatchesRule", mock.Anything).Return(nil)

		w := httptest.NewRecorder()
		e.HandleCheckRequest(w, r)

		resp := w.Result()
		assert.Equal(t, http.StatusFound, resp.StatusCode)

		// check to make sure the rule was passed properly
		ri := a.Calls[0].Arguments[0].(*rules2.RequestInfo)

		assert.True(t, ri.Valid())
		assert.Equal(t, http.MethodGet, ri.Method)
		assert.Equal(t, "https", ri.Protocol)
		assert.Equal(t, "download.example.com", ri.Host)
		assert.Equal(t, "/", ri.RequestURI)
		assert.Equal(t, "10.0.0.1", ri.SourceIP.String())
	})

	t.Run("no rule, but user is admin", func(t *testing.T) {
		a, e := buildTestEnv(t)
		r := buildTestRequest(t, e, &user.User{Id: "5", Username: "test", Admin: true})

		a.On("MatchesRule", mock.Anything).Return(nil)

		w := httptest.NewRecorder()
		e.HandleCheckRequest(w, r)

		resp := w.Result()

		assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	})

	t.Run("yes rule, user is admin", func(t *testing.T) {
		a, e := buildTestEnv(t)
		r := buildTestRequest(t, e, &user.User{Username: "test", Admin: true})

		a.On("MatchesRule", mock.Anything).Return(&rules2.Rule{})

		w := httptest.NewRecorder()
		e.HandleCheckRequest(w, r)

		resp := w.Result()

		assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	})

	t.Run("yes rule, non-admin, group is allowed", func(t *testing.T) {
		a, e := buildTestEnv(t)
		r := buildTestRequest(t, e, &user.User{Username: "test", Admin: false, Roles: []string{"foo"}})

		a.On("MatchesRule", mock.Anything).Return(&rules2.Rule{PermittedRoles: []string{"foo", "bar"}})

		w := httptest.NewRecorder()
		e.HandleCheckRequest(w, r)

		resp := w.Result()

		assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	})

	t.Run("yes rule, non-admin, user is not allowed", func(t *testing.T) {
		a, e := buildTestEnv(t)
		r := buildTestRequest(t, e, &user.User{Username: "test", Admin: false, Roles: []string{"foo"}})

		a.On("MatchesRule", mock.Anything).Return(&rules2.Rule{PermittedRoles: []string{"bar"}})

		w := httptest.NewRecorder()
		e.HandleCheckRequest(w, r)

		resp := w.Result()

		assert.Equal(t, http.StatusFound, resp.StatusCode)

		redirectLocation, err := resp.Location()
		assert.NoError(t, err)
		assert.Equal(t, "/forbidden", redirectLocation.Path)
	})

	t.Run("yes rule, rule is public, no user", func(t *testing.T) {
		a, e := buildTestEnv(t)
		r := buildTestRequest(t, e, nil)

		a.On("MatchesRule", mock.Anything).Return(&rules2.Rule{Public: true})

		w := httptest.NewRecorder()
		e.HandleCheckRequest(w, r)

		resp := w.Result()

		assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	})

	t.Run("invalid headers specified", func(t *testing.T) {
		_, e := buildTestEnv(t)
		r := httptest.NewRequest(http.MethodGet, "/check", nil)

		w := httptest.NewRecorder()
		e.HandleCheckRequest(w, r)

		resp := w.Result()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("invalid cookie", func(t *testing.T) {
		a, e := buildTestEnv(t)
		r := buildTestRequest(t, e, nil)
		r.AddCookie(&http.Cookie{
			Name:  session2.SessionCookieName,
			Value: "lol",
		})

		a.On("MatchesRule", mock.Anything).Return(nil)

		w := httptest.NewRecorder()
		e.HandleCheckRequest(w, r)

		resp := w.Result()

		assert.Equal(t, http.StatusFound, resp.StatusCode)
	})

	t.Run("works with duration (still in time)", func(t *testing.T) {
		a, e := buildTestEnv(t)
		r := buildTestRequest(t, e, &user.User{Id: "5", Username: "test", Admin: false, Roles: []string{"a", "b"}}, withLoginTime(time.Now().Add(-1*time.Minute)))

		timeout := 5 * time.Minute

		a.On("MatchesRule", mock.Anything).Return(&rules2.Rule{
			PermittedRoles: []string{"a"},
			Timeout:        &timeout,
		})

		w := httptest.NewRecorder()
		e.HandleCheckRequest(w, r)

		resp := w.Result()

		assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	})

	t.Run("works with duration (needs to reauth)", func(t *testing.T) {
		a, e := buildTestEnv(t)
		r := buildTestRequest(t, e, &user.User{Id: "5", Username: "test", Admin: false, Roles: []string{"a", "b"}}, withLoginTime(time.Now().Add(-1*time.Hour)))

		timeout := 5 * time.Minute

		a.On("MatchesRule", mock.Anything).Return(&rules2.Rule{
			PermittedRoles: []string{"a"},
			Timeout:        &timeout,
		})

		w := httptest.NewRecorder()
		e.HandleCheckRequest(w, r)

		resp := w.Result()

		assert.Equal(t, http.StatusFound, resp.StatusCode)
	})
}
