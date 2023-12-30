package handlers

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gorilla/csrf"
	"github.com/gorilla/securecookie"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/lthummus/auththingie2/middlewares/session"
	"github.com/lthummus/auththingie2/mocks"
	"github.com/lthummus/auththingie2/salt"
	"github.com/lthummus/auththingie2/user"
)

var (
	sampleAdminUser = &user.User{
		Id:                "sample-admin",
		Username:          "adminuser",
		PasswordHash:      "",
		Roles:             []string{},
		Admin:             true,
		TOTPSeed:          nil,
		RecoveryCodes:     nil,
		PasswordTimestamp: time.Now().Add(-10 * time.Hour).Unix(),
		StoredCredentials: nil,
	}

	sampleNonAdminUser = &user.User{
		Id:                "sample-regular",
		Username:          "regularuser",
		PasswordHash:      "",
		Roles:             []string{"a", "b"},
		Admin:             false,
		TOTPSeed:          nil,
		RecoveryCodes:     nil,
		PasswordTimestamp: time.Now().Add(-10 * time.Hour).Unix(),
		StoredCredentials: nil,
	}
)

type connectionOption func(cd *testConnectionData)

var (
	passesCSRF = func() connectionOption {
		return func(cd *testConnectionData) {
			cd.req = csrf.UnsafeSkipCheck(cd.req)
		}
	}
	withUser = func(u *user.User, db *mocks.DB) connectionOption {
		return func(cd *testConnectionData) {
			cd.user = u
			cd.sess.UserID = u.Id
			cd.sess.LoginTime = time.Now()

			db.On("GetUserByGuid", mock.Anything, u.Id).Return(u, nil)
		}
	}
	isHTMXRequest = func() connectionOption {
		return func(cd *testConnectionData) {
			cd.req.Header.Set("HX-Request", "true")
		}
	}
)

func setupSalts(t *testing.T) {
	saltDir, err := os.MkdirTemp("", "attestsalt")
	require.NoError(t, err)

	t.Cleanup(func() {
		os.RemoveAll(saltDir)
	})

	t.Setenv("SALT_FILE", filepath.Join(saltDir, "attestsalt"))

	salt.CheckOrMakeSalt()
}

func makeTestEnv(t *testing.T) (*mocks.Analyzer, *mocks.DB, *Env) {
	a := mocks.NewAnalyzer(t)
	db := mocks.NewDB(t)
	return a, db, &Env{
		Database: db,
		Analyzer: a,
		WebAuthn: nil,
	}
}

type testConnectionData struct {
	req  *http.Request
	sess *session.Session
	sc   *securecookie.SecureCookie
	user *user.User
}

func makeTestRequest(t *testing.T, method string, path string, body io.Reader, opts ...connectionOption) *http.Request {
	tcd := &testConnectionData{}
	tcd.req = httptest.NewRequest(method, path, body)

	sess, err := session.NewDefaultSession()
	require.NoError(t, err)
	tcd.sess = &sess
	tcd.sc = securecookie.New(salt.GenerateSigningKey(), salt.GenerateEncryptionKey())

	for i := range opts {
		opts[i](tcd)
	}

	tcd.req = session.ArbitraryAttachSession(*tcd.sess, tcd.req, tcd.user, tcd.sc)
	encodedSession, err := tcd.sc.Encode(session.SessionCookieName, sess)
	require.NoError(t, err)
	tcd.req.AddCookie(&http.Cookie{
		Name:  session.SessionCookieName,
		Value: encodedSession,
	})

	return tcd.req
}
