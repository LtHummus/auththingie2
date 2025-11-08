package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/securecookie"
	"github.com/stretchr/testify/assert"

	session2 "github.com/lthummus/auththingie2/internal/middlewares/session"
	"github.com/lthummus/auththingie2/internal/render"
	"github.com/lthummus/auththingie2/internal/salt"
)

func TestEnv_HandleLogout(t *testing.T) {
	setupSalts(t)
	render.Init()

	t.Run("clobber session", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)

		r := makeTestRequest(t, http.MethodGet, "/logout", nil, withUser(sampleNonAdminUser, db))
		w := httptest.NewRecorder()

		e.BuildRouter().ServeHTTP(w, r)

		resp := w.Result()

		assert.Equal(t, http.StatusFound, resp.StatusCode)
		redirectURL, err := resp.Location()
		assert.NoError(t, err)
		assert.Equal(t, "/", redirectURL.Path)

		// check for two cookies -- session
		assert.Len(t, resp.Cookies(), 1)

		sc := securecookie.New(salt.GenerateSigningKey(), salt.GenerateEncryptionKey())
		var sessionCookieData string
		for _, curr := range resp.Cookies() {
			if curr.Name == session2.SessionCookieName {
				sessionCookieData = curr.Value
				break
			}
		}
		assert.NotEmpty(t, sessionCookieData)

		var sess session2.Session
		err = sc.Decode(session2.SessionCookieName, sessionCookieData, &sess)
		assert.NoError(t, err)

		assert.Empty(t, sess.UserID)
	})
}
