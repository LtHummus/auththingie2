package handlers

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
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
	sampleTOTPSeed = "JBSWY3DPEHPK3PXP"

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

	sampleNonAdminWithTOTP = &user.User{
		Id:                "sample-totp",
		Username:          "sampletotp",
		PasswordHash:      "",
		Roles:             []string{"b", "c"},
		Admin:             false,
		TOTPSeed:          &sampleTOTPSeed,
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
			copiedUser := &user.User{
				Id:                u.Id,
				Username:          u.Username,
				PasswordHash:      u.PasswordHash,
				Roles:             make([]string, len(u.Roles)),
				Admin:             u.Admin,
				TOTPSeed:          u.TOTPSeed,
				RecoveryCodes:     make([]string, len(u.RecoveryCodes)),
				PasswordTimestamp: u.PasswordTimestamp,
				StoredCredentials: make([]user.Passkey, len(u.StoredCredentials)),
			}
			copy(copiedUser.Roles, u.Roles)
			copy(copiedUser.RecoveryCodes, u.RecoveryCodes)
			for i := range u.StoredCredentials {
				copiedUser.StoredCredentials[i] = user.Passkey{
					Credential: webauthn.Credential{
						ID:              u.StoredCredentials[i].ID,
						PublicKey:       make([]byte, len(u.StoredCredentials[i].PublicKey)),
						AttestationType: u.StoredCredentials[i].AttestationType,
						Transport:       make([]protocol.AuthenticatorTransport, len(u.StoredCredentials[i].Transport)),
						Flags:           u.StoredCredentials[i].Flags,
						Authenticator: webauthn.Authenticator{
							AAGUID:       make([]byte, len(u.StoredCredentials[i].Authenticator.AAGUID)),
							SignCount:    u.StoredCredentials[i].Authenticator.SignCount,
							CloneWarning: u.StoredCredentials[i].Authenticator.CloneWarning,
							Attachment:   u.StoredCredentials[i].Authenticator.Attachment,
						},
					},
				}
				copy(copiedUser.StoredCredentials[i].Credential.PublicKey, u.StoredCredentials[i].Credential.PublicKey)
				copy(copiedUser.StoredCredentials[i].Transport, u.StoredCredentials[i].Transport)
				copy(copiedUser.StoredCredentials[i].Authenticator.AAGUID, u.StoredCredentials[i].Authenticator.AAGUID)
			}

			cd.user = copiedUser
			cd.sess.UserID = u.Id
			cd.sess.LoginTime = time.Now()

			db.On("GetUserByGuid", mock.Anything, u.Id).Return(copiedUser, nil)
		}
	}
	isHTMXRequest = func() connectionOption {
		return func(cd *testConnectionData) {
			cd.req.Header.Set("HX-Request", "true")
		}
	}
	withCustomSession = func(s func(s *session.Session)) connectionOption {
		return func(cd *testConnectionData) {
			s(cd.sess)
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
