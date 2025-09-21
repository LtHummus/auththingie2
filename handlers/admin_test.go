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

	"github.com/lthummus/auththingie2/argon"
	"github.com/lthummus/auththingie2/render"
	"github.com/lthummus/auththingie2/rules"
	"github.com/lthummus/auththingie2/user"
)

func TestEnv_HandleAdminPage(t *testing.T) {
	setupSalts(t)
	render.Init()

	t.Run("fail if not admin", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)

		r := makeTestRequest(t, http.MethodGet, "/admin", nil, withUser(sampleNonAdminUser, db))
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusForbidden, w.Result().StatusCode)
		assert.Equal(t, strings.TrimSpace(w.Body.String()), "you cannot access this page")
	})

	t.Run("render if admin", func(t *testing.T) {
		a, db, _, e := makeTestEnv(t)

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
		a.On("Rules").Return([]rules.Rule{
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

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), `<a href="/admin/users/a">Edit User</a></td>`)
	})

	t.Run("db failure", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)

		db.On("GetAllUsers", mock.Anything).Return(nil, errors.New("whoops"))

		r := makeTestRequest(t, http.MethodGet, "/admin", nil, withUser(sampleAdminUser, db))
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Result().StatusCode)
	})
}

func TestEnv_HandleTestRule(t *testing.T) {
	setupSalts(t)
	render.Init()

	t.Run("basic test", func(t *testing.T) {
		a, db, _, e := makeTestEnv(t)

		a.On("MatchesRule", &rules.RequestInfo{
			Method:     http.MethodGet,
			Protocol:   "https",
			Host:       "test.example.com",
			RequestURI: "/foo",
			SourceIP:   net.ParseIP("11.11.11.11"),
		}).Return(&rules.Rule{Name: "test-rule"})

		v := url.Values{}
		v.Add("url", "https://test.example.com/foo")

		r := makeTestRequest(t, http.MethodGet, fmt.Sprintf("/admin/ruletest?%s", v.Encode()), nil, withUser(sampleAdminUser, db))

		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "Matched rule <strong>test-rule</strong>")
	})

	t.Run("fail if no url provided", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)

		r := makeTestRequest(t, http.MethodGet, "/admin/ruletest", nil, withUser(sampleAdminUser, db))

		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "Error in testing rule: URL to test was blank")
	})

	t.Run("fail if URL invalid", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)

		v := url.Values{}
		v.Add("url", ":blahblah")

		r := makeTestRequest(t, http.MethodGet, fmt.Sprintf("/admin/ruletest?%s", v.Encode()), nil, withUser(sampleAdminUser, db))

		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "Error in testing rule: Invalid URL to test:")
	})

	t.Run("fail if source IP invalid", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)

		v := url.Values{}
		v.Add("url", "https://test.example.com")
		v.Add("source", "badip")

		r := makeTestRequest(t, http.MethodGet, fmt.Sprintf("/admin/ruletest?%s", v.Encode()), nil, withUser(sampleAdminUser, db))

		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "Error in testing rule: Invalid source IP")
	})

	t.Run("fail if logged in non-admin", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)

		v := url.Values{}
		v.Add("url", "https://test.example.com")

		r := makeTestRequest(t, http.MethodGet, fmt.Sprintf("/admin/ruletest?%s", v.Encode()), nil, withUser(sampleNonAdminUser, db))
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusForbidden, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "you cannot access this page")
	})

	t.Run("fail if logged in non-admin", func(t *testing.T) {
		_, _, _, e := makeTestEnv(t)

		v := url.Values{}
		v.Add("url", "https://test.example.com")

		r := makeTestRequest(t, http.MethodGet, fmt.Sprintf("/admin/ruletest?%s", v.Encode()), nil)
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusForbidden, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "you cannot access this page")
	})
}

func TestEnv_HandleUserPatchTagsModification(t *testing.T) {
	setupSalts(t)
	render.Init()

	t.Run("not logged in should fail", func(t *testing.T) {
		_, _, _, e := makeTestEnv(t)

		v := url.Values{}
		v.Add("new-tag", "test-tag")

		r := makeTestRequest(t, http.MethodPatch, "/admin/users/test/tags", strings.NewReader(v.Encode()))
		r.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusUnprocessableEntity, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "You must be logged in as admin to do this")
	})

	t.Run("non admin user should fail", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)

		v := url.Values{}
		v.Add("new-tag", "test-tag")

		r := makeTestRequest(t, http.MethodPatch, "/admin/users/test/tags", strings.NewReader(v.Encode()), withUser(sampleNonAdminUser, db))
		r.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusUnprocessableEntity, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "You must be logged in as admin to do this")
	})

	t.Run("check CSRF protection", func(t *testing.T) {
		_, _, _, e := makeTestEnv(t)
		v := url.Values{}
		v.Add("new-tag", "test-tag")

		r := makeTestRequest(t, http.MethodPatch, "/admin/users/test/tags", strings.NewReader(v.Encode()))
		r.Header.Add("Sec-Fetch-Site", "cross-site")

		w := httptest.NewRecorder()
		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusForbidden, w.Result().StatusCode)
		assert.Equal(t, "cross-origin request detected from Sec-Fetch-Site header\n", w.Body.String())
	})

	t.Run("database error", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)

		db.On("GetUserByGuid", mock.Anything, "test").Return(nil, errors.New("oh no"))

		v := url.Values{}
		v.Add("new-tag", "test-tag")

		r := makeTestRequest(t, http.MethodPatch, "/admin/users/test/tags", strings.NewReader(v.Encode()), withUser(sampleAdminUser, db))
		r.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusUnprocessableEntity, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "Could not get user from database:")
	})

	t.Run("user not found", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)

		db.On("GetUserByGuid", mock.Anything, "test").Return(nil, nil)

		v := url.Values{}
		v.Add("new-tag", "test-tag")

		r := makeTestRequest(t, http.MethodPatch, "/admin/users/test/tags", strings.NewReader(v.Encode()), withUser(sampleAdminUser, db))
		r.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusUnprocessableEntity, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "User not found in database")
	})

	t.Run("no tag specified", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)

		db.On("GetUserByGuid", mock.Anything, "test").Return(&user.User{
			Id:       "test",
			Username: "testname",
			Roles:    []string{"a"},
		}, nil)

		v := url.Values{}

		r := makeTestRequest(t, http.MethodPatch, "/admin/users/test/tags", strings.NewReader(v.Encode()), withUser(sampleAdminUser, db))
		r.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusUnprocessableEntity, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "Tag can not be blank")
	})

	t.Run("tag already exists specified", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)

		db.On("GetUserByGuid", mock.Anything, "test").Return(&user.User{
			Id:       "test",
			Username: "testname",
			Roles:    []string{"a"},
		}, nil)

		v := url.Values{}
		v.Add("new-tag", "a")

		r := makeTestRequest(t, http.MethodPatch, "/admin/users/test/tags", strings.NewReader(v.Encode()), withUser(sampleAdminUser, db))
		r.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusUnprocessableEntity, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "Tag `a` already exists on user")
	})

	t.Run("database error on save", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)

		db.On("GetUserByGuid", mock.Anything, "test").Return(&user.User{
			Id:       "test",
			Username: "testname",
			Roles:    []string{"b"},
		}, nil)
		db.On("SaveUser", mock.Anything, mock.Anything).Return(errors.New("oh no"))

		v := url.Values{}
		v.Add("new-tag", "a")

		r := makeTestRequest(t, http.MethodPatch, "/admin/users/test/tags", strings.NewReader(v.Encode()), withUser(sampleAdminUser, db))
		r.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusUnprocessableEntity, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "Could not update user in database: ")
	})

	t.Run("everything worked", func(t *testing.T) {
		a, db, _, e := makeTestEnv(t)

		db.On("GetUserByGuid", mock.Anything, "test").Return(&user.User{
			Id:       "test",
			Username: "testname",
			Roles:    []string{"b"},
		}, nil)
		db.On("SaveUser", mock.Anything, &user.User{
			Id:       "test",
			Username: "testname",
			Roles:    []string{"b", "a"},
		}).Return(nil)

		a.On("KnownRoles").Return([]string{"a", "b"})

		v := url.Values{}
		v.Add("new-tag", "a")

		r := makeTestRequest(t, http.MethodPatch, "/admin/users/test/tags", strings.NewReader(v.Encode()), withUser(sampleAdminUser, db))
		r.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), `hx-confirm="Delete role b from this user?"`)
	})
}

func TestEnv_HandleUserTagDelete(t *testing.T) {
	setupSalts(t)
	render.Init()

	t.Run("detect CSRF detection", func(t *testing.T) {
		_, _, _, e := makeTestEnv(t)

		r := makeTestRequest(t, http.MethodDelete, "/admin/users/testuser/tags/dtag", nil, isHTMXRequest())
		r.Header.Set("Sec-Fetch-Site", "badvalue")
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusForbidden, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "cross-origin request detected from Sec-Fetch-Site header")
	})

	t.Run("fail if not logged in", func(t *testing.T) {
		_, _, _, e := makeTestEnv(t)

		r := makeTestRequest(t, http.MethodDelete, "/admin/users/testuser/tags/dtag", nil, isHTMXRequest())
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusUnprocessableEntity, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "You must be logged in as admin to do this")
	})

	t.Run("fail if not admin", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)

		r := makeTestRequest(t, http.MethodDelete, "/admin/users/testuser/tags/dtag", nil, withUser(sampleNonAdminUser, db), isHTMXRequest())
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusUnprocessableEntity, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "You must be logged in as admin to do this")
	})

	t.Run("handle database error gracefully", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)

		db.On("GetUserByGuid", mock.Anything, "testuser").Return(nil, errors.New("oh no!"))

		r := makeTestRequest(t, http.MethodDelete, "/admin/users/testuser/tags/dtag", nil, withUser(sampleAdminUser, db), isHTMXRequest())
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusUnprocessableEntity, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "Could not get user from database")
	})

	t.Run("handle target user not found gracefully", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)

		db.On("GetUserByGuid", mock.Anything, "testuser").Return(nil, nil)

		r := makeTestRequest(t, http.MethodDelete, "/admin/users/testuser/tags/dtag", nil, withUser(sampleAdminUser, db), isHTMXRequest())
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusUnprocessableEntity, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), `<div id="tag-error" class="error-box ">User not found in database</div>`)
	})

	t.Run("handle db error on save", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)

		db.On("GetUserByGuid", mock.Anything, "testuser").Return(&user.User{
			Id:       "testuser",
			Username: "a test user",
			Roles:    []string{"aaa", "bbb", "dtag"},
		}, nil)
		db.On("SaveUser", mock.Anything, &user.User{
			Id:       "testuser",
			Username: "a test user",
			Roles:    []string{"aaa", "bbb"},
		}).Return(errors.New("whoops"))

		r := makeTestRequest(t, http.MethodDelete, "/admin/users/testuser/tags/dtag", nil, withUser(sampleAdminUser, db), isHTMXRequest())
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusUnprocessableEntity, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), `Could not update user in database`)
	})

	t.Run("everything worked ok", func(t *testing.T) {
		a, db, _, e := makeTestEnv(t)

		db.On("GetUserByGuid", mock.Anything, "testuser").Return(&user.User{
			Id:       "testuser",
			Username: "a test user",
			Roles:    []string{"aaa", "bbb", "dtag"},
		}, nil)
		db.On("SaveUser", mock.Anything, &user.User{
			Id:       "testuser",
			Username: "a test user",
			Roles:    []string{"aaa", "bbb"},
		}).Return(nil)
		a.On("KnownRoles", mock.Anything).Return([]string{"a", "b"})

		r := makeTestRequest(t, http.MethodDelete, "/admin/users/testuser/tags/dtag", nil, withUser(sampleAdminUser, db), isHTMXRequest())
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), `<span class="modify-badge-button add-badge-button" hx-on:click="clearTagError()" hx-patch="/admin/users/testuser/tags" hx-vals='{"new-tag":"a"}' hx-target="#tag-edit-table">`)
	})
}

func TestBuildMissingRoles(t *testing.T) {
	t.Run("sample input", func(t *testing.T) {
		a, _, _, e := makeTestEnv(t)

		a.On("KnownRoles").Return([]string{"aaa", "bbb", "ccc", "ddd"})

		missingRoles := e.buildMissingRoles(&user.User{
			Roles: []string{"aaa", "bbb"},
		})

		assert.ElementsMatch(t, []string{"ccc", "ddd"}, missingRoles)
	})
}

func TestEnv_RenderUserEditPage(t *testing.T) {
	setupSalts(t)
	render.Init()

	t.Run("fail if not logged in", func(t *testing.T) {
		_, _, _, e := makeTestEnv(t)

		r := makeTestRequest(t, http.MethodGet, "/admin/users/myuser", nil)
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusForbidden, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "you must be an admin to do this")
	})

	t.Run("fail if non-admin", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)

		r := makeTestRequest(t, http.MethodGet, "/admin/users/myuser", nil, withUser(sampleNonAdminUser, db))
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusForbidden, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "you must be an admin to do this")
	})

	t.Run("handle database error", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)

		db.On("GetUserByGuid", mock.Anything, "myuser").Return(nil, errors.New("noooo"))

		r := makeTestRequest(t, http.MethodGet, "/admin/users/myuser", nil, withUser(sampleAdminUser, db))
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "could not get user info")
	})

	t.Run("handle user does not exist", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)

		db.On("GetUserByGuid", mock.Anything, "myuser").Return(nil, nil)

		r := makeTestRequest(t, http.MethodGet, "/admin/users/myuser", nil, withUser(sampleAdminUser, db))
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusNotFound, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "user does not exist")
	})

	t.Run("everything works ok", func(t *testing.T) {
		a, db, _, e := makeTestEnv(t)

		a.On("KnownRoles").Return([]string{"a", "b", "c"})
		db.On("GetUserByGuid", mock.Anything, "myuser").Return(&user.User{
			Id:       "myuser",
			Username: "ausername",
			Roles:    []string{"a", "b"},
			Admin:    false,
		}, nil)

		r := makeTestRequest(t, http.MethodGet, "/admin/users/myuser", nil, withUser(sampleAdminUser, db))
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "<li>Editing <strong>ausername</strong></li>")
	})
}

func TestEnv_HandleEditUserSubmission(t *testing.T) {
	setupSalts(t)
	render.Init()

	t.Run("detect CSRF protection", func(t *testing.T) {
		t.Run("fail if not logged in", func(t *testing.T) {
			_, _, _, e := makeTestEnv(t)

			r := makeTestRequest(t, http.MethodPost, "/admin/users/myuser", nil)
			r.Header.Set("Sec-Fetch-Site", "foo")

			w := httptest.NewRecorder()

			e.BuildRouter().ServeHTTP(w, r)

			assert.Equal(t, http.StatusForbidden, w.Result().StatusCode)
			assert.Contains(t, w.Body.String(), "cross-origin request detected from Sec-Fetch-Site header")
		})
	})

	t.Run("fail if not logged in", func(t *testing.T) {
		_, _, _, e := makeTestEnv(t)

		r := makeTestRequest(t, http.MethodPost, "/admin/users/myuser", nil)
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusForbidden, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "you must be an admin for this")
	})

	t.Run("fail if not admin", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)

		r := makeTestRequest(t, http.MethodPost, "/admin/users/myuser", nil, withUser(sampleNonAdminUser, db))
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusForbidden, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "you must be an admin for this")
	})

	t.Run("database error on user retrieval", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)

		db.On("GetUserByGuid", mock.Anything, "myuser").Return(nil, errors.New("womp womp"))

		r := makeTestRequest(t, http.MethodPost, "/admin/users/myuser", nil, withUser(sampleAdminUser, db))
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "could not get user")
	})

	t.Run("handle user not found", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)

		v := url.Values{}
		v.Add("new-pwd", "anewpassword")

		db.On("GetUserByGuid", mock.Anything, "myuser").Return(nil, nil)

		r := makeTestRequest(t, http.MethodPost, "/admin/users/myuser", strings.NewReader(v.Encode()), withUser(sampleAdminUser, db))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusNotFound, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "could not find user")
	})

	t.Run("could not save user", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)

		v := url.Values{}
		v.Add("new-pwd", "anewpassword")

		db.On("GetUserByGuid", mock.Anything, "myuser").Return(&user.User{
			Id:       "myuser",
			Username: "myuser",
		}, nil)
		db.On("SaveUser", mock.Anything, mock.AnythingOfType("*user.User")).Return(errors.New("whoopsies"))

		r := makeTestRequest(t, http.MethodPost, "/admin/users/myuser", strings.NewReader(v.Encode()), withUser(sampleAdminUser, db))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "could not persist changes to database")
	})

	t.Run("All OK", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)

		v := url.Values{}
		v.Add("new-pwd", "anewpassword")

		db.On("GetUserByGuid", mock.Anything, "myuser").Return(&user.User{
			Id:       "myuser",
			Username: "myuser",
		}, nil)
		db.On("SaveUser", mock.Anything, mock.AnythingOfType("*user.User")).Return(nil)

		r := makeTestRequest(t, http.MethodPost, "/admin/users/myuser", strings.NewReader(v.Encode()), withUser(sampleAdminUser, db))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusFound, w.Result().StatusCode)
		redirectLocation, err := w.Result().Location()
		assert.NoError(t, err)
		assert.Equal(t, "/admin", redirectLocation.Path)

		updatedUser := db.Mock.Calls[2].Arguments[1].(*user.User)
		assert.NoError(t, argon.ValidatePassword("anewpassword", updatedUser.PasswordHash))
	})
}

func TestEnv_HandleCreateUserPage(t *testing.T) {
	setupSalts(t)
	render.Init()

	t.Run("fail if not logged in", func(t *testing.T) {
		_, _, _, e := makeTestEnv(t)

		r := makeTestRequest(t, http.MethodGet, "/admin/users/create", nil)
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusUnauthorized, w.Result().StatusCode)
	})

	t.Run("fail if not admin", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)

		r := makeTestRequest(t, http.MethodGet, "/admin/users/create", nil, withUser(sampleNonAdminUser, db))
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusUnauthorized, w.Result().StatusCode)
	})

	t.Run("all ok", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)

		r := makeTestRequest(t, http.MethodGet, "/admin/users/create", nil, withUser(sampleAdminUser, db))
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), `<form action="/admin/users/create" method="post">`)
	})
}

func TestEnv_HandleCreateUserPost(t *testing.T) {
	setupSalts(t)
	render.Init()

	t.Run("check CSRF detection", func(t *testing.T) {
		_, _, _, e := makeTestEnv(t)

		r := makeTestRequest(t, http.MethodPost, "/admin/users/create", nil)
		r.Header.Set("Origin", "https://bad.example.com")
		r.Header.Set("Host", "example.com")
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusForbidden, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "cross-origin request detected, and/or browser is out of date: Sec-Fetch-Site is missing, and Origin does not match Host")
	})

	t.Run("fail if not logged in", func(t *testing.T) {
		_, _, _, e := makeTestEnv(t)

		r := makeTestRequest(t, http.MethodPost, "/admin/users/create", nil)
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusUnauthorized, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "you must be an admin to access this page")
	})

	t.Run("fail if not admin", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)

		r := makeTestRequest(t, http.MethodPost, "/admin/users/create", nil, withUser(sampleNonAdminUser, db))
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusUnauthorized, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "you must be an admin to access this page")
	})

	t.Run("fail if no username", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)

		v := url.Values{}
		v.Add("pw1", "apass")
		v.Add("pw2", "apass")

		r := makeTestRequest(t, http.MethodPost, "/admin/users/create", strings.NewReader(v.Encode()), withUser(sampleAdminUser, db))
		r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "Username may not be blank")
	})

	t.Run("fail if pw is blank", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)

		v := url.Values{}
		v.Add("username", "newuser")
		v.Add("pw1", "")
		v.Add("pw2", "apass")

		r := makeTestRequest(t, http.MethodPost, "/admin/users/create", strings.NewReader(v.Encode()), withUser(sampleAdminUser, db))
		r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "Password may not be blank")
	})

	t.Run("fail if passwords do not match", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)

		v := url.Values{}
		v.Add("username", "newuser")
		v.Add("pw1", "apass1")
		v.Add("pw2", "apass")

		r := makeTestRequest(t, http.MethodPost, "/admin/users/create", strings.NewReader(v.Encode()), withUser(sampleAdminUser, db))
		r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "Passwords do not match")
	})

	t.Run("check for existing user fails", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)

		db.On("GetUserByUsername", mock.Anything, "newuser").Return(nil, errors.New("wheee"))

		v := url.Values{}
		v.Add("username", "newuser")
		v.Add("pw1", "apass")
		v.Add("pw2", "apass")

		r := makeTestRequest(t, http.MethodPost, "/admin/users/create", strings.NewReader(v.Encode()), withUser(sampleAdminUser, db))
		r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "Could not query for username")
	})

	t.Run("user already exists", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)

		db.On("GetUserByUsername", mock.Anything, "newuser").Return(&user.User{}, nil)

		v := url.Values{}
		v.Add("username", "newuser")
		v.Add("pw1", "apass")
		v.Add("pw2", "apass")

		r := makeTestRequest(t, http.MethodPost, "/admin/users/create", strings.NewReader(v.Encode()), withUser(sampleAdminUser, db))
		r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "Username already exists")
	})

	t.Run("fail to save user", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)

		db.On("GetUserByUsername", mock.Anything, "newuser").Return(nil, nil)
		db.On("CreateUser", mock.Anything, mock.AnythingOfType("*user.User")).Return(errors.New("whoops"))

		v := url.Values{}
		v.Add("username", "newuser")
		v.Add("pw1", "apass")
		v.Add("pw2", "apass")

		r := makeTestRequest(t, http.MethodPost, "/admin/users/create", strings.NewReader(v.Encode()), withUser(sampleAdminUser, db))
		r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "Could not create user in database")
	})

	t.Run("everything worked", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)

		db.On("GetUserByUsername", mock.Anything, "newuser").Return(nil, nil)
		db.On("CreateUser", mock.Anything, mock.AnythingOfType("*user.User")).Return(nil)

		v := url.Values{}
		v.Add("username", "newuser")
		v.Add("pw1", "apass")
		v.Add("pw2", "apass")

		r := makeTestRequest(t, http.MethodPost, "/admin/users/create", strings.NewReader(v.Encode()), withUser(sampleAdminUser, db))
		r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusFound, w.Result().StatusCode)
		redirectURL, err := w.Result().Location()
		assert.NoError(t, err)
		assert.Equal(t, "/admin", redirectURL.Path)

		createdUser := db.Mock.Calls[2].Arguments[1].(*user.User)
		assert.Equal(t, "newuser", createdUser.Username)
		assert.NoError(t, argon.ValidatePassword("apass", createdUser.PasswordHash))
	})
}

func TestEnv_HandleAdminUnenrollTOTP(t *testing.T) {
	setupSalts(t)
	render.Init()
	seed := "sampletotpseed"

	t.Run("detect CSRF protection", func(t *testing.T) {
		_, _, _, e := makeTestEnv(t)

		r := makeTestRequest(t, http.MethodPost, "/admin/users/someid/totp_unenroll", nil)
		r.Header.Set("Sec-Fetch-Site", "cross-site")
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusForbidden, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "cross-origin request detected from Sec-Fetch-Site header")
	})

	t.Run("fail if not logged in", func(t *testing.T) {
		_, _, _, e := makeTestEnv(t)

		r := makeTestRequest(t, http.MethodPost, "/admin/users/someid/totp_unenroll", nil)
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusUnauthorized, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "you must be an admin to access this page")
	})

	t.Run("fail if not admin", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)

		r := makeTestRequest(t, http.MethodPost, "/admin/users/someid/totp_unenroll", nil, withUser(sampleNonAdminUser, db))
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusUnauthorized, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "you must be an admin to access this page")
	})

	t.Run("fail if attempting to unenroll self", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)

		r := makeTestRequest(t, http.MethodPost, fmt.Sprintf("/admin/users/%s/totp_unenroll", sampleAdminUser.Id), nil, withUser(sampleAdminUser, db))
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusUnprocessableEntity, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "to unenroll yourself, you must use the normal method")
	})

	t.Run("fail to get user to modify", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)

		db.On("GetUserByGuid", mock.Anything, "myuser").Return(nil, errors.New("whe"))

		r := makeTestRequest(t, http.MethodPost, "/admin/users/myuser/totp_unenroll", nil, withUser(sampleAdminUser, db))
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "database error")
	})

	t.Run("user not found", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)

		db.On("GetUserByGuid", mock.Anything, "myuser").Return(nil, nil)

		r := makeTestRequest(t, http.MethodPost, "/admin/users/myuser/totp_unenroll", nil, withUser(sampleAdminUser, db))
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusNotFound, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "user not found")
	})

	t.Run("failed to save user", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)

		db.On("GetUserByGuid", mock.Anything, "myuser").Return(&user.User{
			Id:       "myuser",
			Username: "somerandomuseranme",
			TOTPSeed: &seed,
		}, nil)
		db.On("SaveUser", mock.Anything, mock.AnythingOfType("*user.User")).Return(errors.New("could not save"))

		r := makeTestRequest(t, http.MethodPost, "/admin/users/myuser/totp_unenroll", nil, withUser(sampleAdminUser, db))
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "database error")
	})

	t.Run("all ok", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)

		db.On("GetUserByGuid", mock.Anything, "myuser").Return(&user.User{
			Id:       "myuser",
			Username: "somerandomuseranme",
			TOTPSeed: &seed,
		}, nil)
		db.On("SaveUser", mock.Anything, mock.AnythingOfType("*user.User")).Return(nil)

		r := makeTestRequest(t, http.MethodPost, "/admin/users/myuser/totp_unenroll", nil, withUser(sampleAdminUser, db))
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusFound, w.Result().StatusCode)
		redirectURL, err := w.Result().Location()
		assert.NoError(t, err)
		assert.Equal(t, "/admin/users/myuser", redirectURL.Path)

		modifiedUser := db.Mock.Calls[2].Arguments[1].(*user.User)
		assert.Nil(t, modifiedUser.TOTPSeed)
	})
}

func TestEnv_HandleUserDelete(t *testing.T) {
	setupSalts(t)
	render.Init()

	t.Run("detect CSRF protection", func(t *testing.T) {
		_, _, _, e := makeTestEnv(t)

		r := makeTestRequest(t, http.MethodPost, "/admin/users/myuser/delete", nil)
		r.Header.Set("Sec-Fetch-Site", "cross-site")
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusForbidden, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "cross-origin request detected from Sec-Fetch-Site header")
	})

	t.Run("fail if not logged in", func(t *testing.T) {
		_, _, _, e := makeTestEnv(t)

		r := makeTestRequest(t, http.MethodPost, "/admin/users/myuser/delete", nil)
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusUnauthorized, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "you must be an admin to access this page")
	})

	t.Run("fail if not admin", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)

		r := makeTestRequest(t, http.MethodPost, "/admin/users/myuser/delete", nil, withUser(sampleNonAdminUser, db))
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusUnauthorized, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "you must be an admin to access this page")
	})

	t.Run("attempt to delete self", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)

		r := makeTestRequest(t, http.MethodPost, fmt.Sprintf("/admin/users/%s/delete", sampleAdminUser.Id), nil, withUser(sampleAdminUser, db))
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusUnprocessableEntity, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "you cannot delete yourself")
	})

	t.Run("deletion failure", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)

		db.On("DeleteUser", mock.Anything, "myuser").Return(errors.New("no delete for you"))

		r := makeTestRequest(t, http.MethodPost, "/admin/users/myuser/delete", nil, withUser(sampleAdminUser, db))
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "database error")
	})

	t.Run("everything ok", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)

		db.On("DeleteUser", mock.Anything, "myuser").Return(nil)

		r := makeTestRequest(t, http.MethodPost, "/admin/users/myuser/delete", nil, withUser(sampleAdminUser, db))
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusFound, w.Result().StatusCode)
		redirectURL, err := w.Result().Location()
		assert.NoError(t, err)
		assert.Equal(t, "/admin", redirectURL.Path)
	})
}

func TestEnv_HandleUserDisableEnable(t *testing.T) {
	setupSalts(t)
	render.Init()

	t.Run("CSRF protection detect", func(t *testing.T) {
		_, _, _, e := makeTestEnv(t)

		r := makeTestRequest(t, http.MethodPatch, "/admin/users/myuser/disable", nil)
		r.Header.Set("Sec-Fetch-Site", "askdjasdfkjsdfkjdsf")
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusForbidden, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "cross-origin request detected from Sec-Fetch-Site header")
	})

	t.Run("fail if not logged in", func(t *testing.T) {
		_, _, _, e := makeTestEnv(t)

		r := makeTestRequest(t, http.MethodPatch, "/admin/users/myuser/disable", nil)
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusUnauthorized, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "you must be an admin to access this page")
	})

	t.Run("fail if not admin", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)

		r := makeTestRequest(t, http.MethodPatch, "/admin/users/myuser/disable", nil, withUser(sampleNonAdminUser, db))
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusUnauthorized, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "you must be an admin to access this page")
	})

	t.Run("attempt to modify self", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)

		r := makeTestRequest(t, http.MethodPatch, fmt.Sprintf("/admin/users/%s/disable", sampleAdminUser.Id), nil, withUser(sampleAdminUser, db))
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusUnprocessableEntity, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "you cannot delete yourself")
	})

	t.Run("modification failure", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)

		db.On("SetUserEnabled", mock.Anything, "myuser", false).Return(errors.New("no modify for you"))

		r := makeTestRequest(t, http.MethodPatch, "/admin/users/myuser/disable", nil, withUser(sampleAdminUser, db))
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusUnprocessableEntity, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "database error")
	})

	t.Run("everything ok for disable", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)

		db.On("SetUserEnabled", mock.Anything, "myuser", false).Return(nil)

		r := makeTestRequest(t, http.MethodPatch, "/admin/users/myuser/disable", nil, withUser(sampleAdminUser, db))
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), `<input hx-patch="/admin/users/myuser/disable" hx-target="#account-disable-switch" hx-swap="innerHTML" type="checkbox" id="account-enabled" name="enabled" role="switch"  />`)
	})

	t.Run("everything ok for enable", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)

		v := url.Values{}
		v.Add("enabled", "on")

		db.On("SetUserEnabled", mock.Anything, "myuser", true).Return(nil)

		r := makeTestRequest(t, http.MethodPatch, "/admin/users/myuser/disable", strings.NewReader(v.Encode()), withUser(sampleAdminUser, db))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), `<input hx-patch="/admin/users/myuser/disable" hx-target="#account-disable-switch" hx-swap="innerHTML" type="checkbox" id="account-enabled" name="enabled" role="switch"  checked  />`)

	})
}
