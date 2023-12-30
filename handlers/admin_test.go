package handlers

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/lthummus/auththingie2/render"
	rules2 "github.com/lthummus/auththingie2/rules"
	"github.com/lthummus/auththingie2/user"
)

func TestEnv_HandleAdminPage(t *testing.T) {
	setupSalts(t)
	render.Init()

	t.Run("fail if not admin", func(t *testing.T) {
		_, db, e := makeTestEnv(t)
		mux := e.BuildRouter()

		r := makeTestRequest(t, http.MethodGet, "/admin", nil, withUser(sampleNonAdminUser, db))
		w := httptest.NewRecorder()

		mux.ServeHTTP(w, r)

		assert.Equal(t, http.StatusForbidden, w.Result().StatusCode)
		assert.Equal(t, strings.TrimSpace(w.Body.String()), "you cannot access this page")
	})

	t.Run("render if admin", func(t *testing.T) {
		a, db, e := makeTestEnv(t)
		mux := e.BuildRouter()

		db.On("GetAllUsers", mock.Anything).Return([]*user.AdminListUser{
			{
				Id:       "a",
				Username: "a",
			},
			{
				Id:       "b",
				Username: "b",
			},
		}, nil)

		host := "test.example.com"
		a.On("Rules").Return([]rules2.Rule{
			{
				Name:            "test-rule",
				SourceAddress:   nil,
				ProtocolPattern: nil,
				HostPattern:     &host,
				PathPattern:     nil,
				Timeout:         nil,
				Public:          false,
				PermittedRoles:  []string{"a"},
			},
		})

		r := makeTestRequest(t, http.MethodGet, "/admin", nil, withUser(sampleAdminUser, db))
		w := httptest.NewRecorder()

		mux.ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), `<a href="/admin/users/a">Edit User</a></td>`)
	})

	t.Run("db failure", func(t *testing.T) {
		_, db, e := makeTestEnv(t)
		mux := e.BuildRouter()

		db.On("GetAllUsers", mock.Anything).Return(nil, errors.New("whoops"))

		r := makeTestRequest(t, http.MethodGet, "/admin", nil, withUser(sampleAdminUser, db))
		w := httptest.NewRecorder()

		mux.ServeHTTP(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Result().StatusCode)
	})
}

func TestEnv_HandleTestRule(t *testing.T) {
	setupSalts(t)
	render.Init()

	t.Run("basic test", func(t *testing.T) {
		a, db, e := makeTestEnv(t)
		mux := e.BuildRouter()

		a.On("MatchesRule", &rules2.RequestInfo{
			Method:     http.MethodGet,
			Protocol:   "https",
			Host:       "test.example.com",
			RequestURI: "/foo",
			SourceIP:   net.ParseIP("11.11.11.11"),
		}).Return(&rules2.Rule{Name: "test-rule"})

		v := url.Values{}
		v.Add("url", "https://test.example.com/foo")

		r := makeTestRequest(t, http.MethodGet, fmt.Sprintf("/admin/ruletest?%s", v.Encode()), nil, withUser(sampleAdminUser, db))

		w := httptest.NewRecorder()

		mux.ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "Matched rule <strong>test-rule</strong>")
	})

	t.Run("fail if no url provided", func(t *testing.T) {
		_, db, e := makeTestEnv(t)
		mux := e.BuildRouter()

		r := makeTestRequest(t, http.MethodGet, "/admin/ruletest", nil, withUser(sampleAdminUser, db))

		w := httptest.NewRecorder()

		mux.ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "Error in testing rule: URL to test was blank")
	})

	t.Run("fail if URL invalid", func(t *testing.T) {
		_, db, e := makeTestEnv(t)
		mux := e.BuildRouter()

		v := url.Values{}
		v.Add("url", ":blahblah")

		r := makeTestRequest(t, http.MethodGet, fmt.Sprintf("/admin/ruletest?%s", v.Encode()), nil, withUser(sampleAdminUser, db))

		w := httptest.NewRecorder()

		mux.ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "Error in testing rule: Invalid URL to test:")
	})

	t.Run("fail if source IP invalid", func(t *testing.T) {
		_, db, e := makeTestEnv(t)
		mux := e.BuildRouter()

		v := url.Values{}
		v.Add("url", "https://test.example.com")
		v.Add("source", "badip")

		r := makeTestRequest(t, http.MethodGet, fmt.Sprintf("/admin/ruletest?%s", v.Encode()), nil, withUser(sampleAdminUser, db))

		w := httptest.NewRecorder()

		mux.ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "Error in testing rule: Invalid source IP")
	})

	t.Run("fail if logged in non-admin", func(t *testing.T) {
		_, db, e := makeTestEnv(t)
		mux := e.BuildRouter()

		v := url.Values{}
		v.Add("url", "https://test.example.com")

		r := makeTestRequest(t, http.MethodGet, fmt.Sprintf("/admin/ruletest?%s", v.Encode()), nil, withUser(sampleNonAdminUser, db))
		w := httptest.NewRecorder()

		mux.ServeHTTP(w, r)

		assert.Equal(t, http.StatusForbidden, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "you cannot access this page")
	})

	t.Run("fail if logged in non-admin", func(t *testing.T) {
		_, _, e := makeTestEnv(t)
		mux := e.BuildRouter()

		v := url.Values{}
		v.Add("url", "https://test.example.com")

		r := makeTestRequest(t, http.MethodGet, fmt.Sprintf("/admin/ruletest?%s", v.Encode()), nil)
		w := httptest.NewRecorder()

		mux.ServeHTTP(w, r)

		assert.Equal(t, http.StatusForbidden, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "you cannot access this page")
	})
}
