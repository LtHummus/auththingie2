package handlers

import (
	"net/http"
	"net/http/httptest"
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

		db.On("GetUserByGuid", mock.Anything, sampleNonAdminUser.Id).Return(sampleNonAdminUser, nil)

		r := makeTestRequest(t, http.MethodGet, "/admin", nil, withUser(sampleNonAdminUser))
		w := httptest.NewRecorder()

		mux.ServeHTTP(w, r)

		assert.Equal(t, http.StatusForbidden, w.Result().StatusCode)
		assert.Equal(t, strings.TrimSpace(w.Body.String()), "you cannot access this page")
	})

	t.Run("render if admin", func(t *testing.T) {
		a, db, e := makeTestEnv(t)
		mux := e.BuildRouter()

		db.On("GetUserByGuid", mock.Anything, sampleAdminUser.Id).Return(sampleAdminUser, nil)
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

		r := makeTestRequest(t, http.MethodGet, "/admin", nil, withUser(sampleAdminUser))
		w := httptest.NewRecorder()

		mux.ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), `<a href="/admin/users/a">Edit User</a></td>`)
	})
}
