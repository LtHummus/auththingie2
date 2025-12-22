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
	"github.com/google/uuid"
	"github.com/gorilla/securecookie"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	session2 "github.com/lthummus/auththingie2/internal/middlewares/session"
	"github.com/lthummus/auththingie2/internal/mocks"
	"github.com/lthummus/auththingie2/internal/salt"
	"github.com/lthummus/auththingie2/internal/user"
)

var (
	sampleTOTPSeed = "JBSWY3DPEHPK3PXP"

	sampleAdminUser = &user.User{
		Id:                uuid.New().String(),
		Username:          "adminuser",
		PasswordHash:      "$argon2id$v=19$m=65536,t=3,p=2$f5DrCPQlwRJ5q1fA4K+i/g$c8XhJISMUI3wjIUULHvn0HIJinvOBBb4KnvOcvuJ4e0", // test1
		Roles:             []string{},
		Admin:             true,
		TOTPSeed:          nil,
		RecoveryCodes:     nil,
		PasswordTimestamp: time.Now().Add(-10 * time.Hour).Unix(),
		StoredCredentials: nil,
	}

	sampleNonAdminUser = &user.User{
		Id:                uuid.New().String(),
		Username:          "regularuser",
		PasswordHash:      "$argon2id$v=19$m=65536,t=3,p=2$f5DrCPQlwRJ5q1fA4K+i/g$c8XhJISMUI3wjIUULHvn0HIJinvOBBb4KnvOcvuJ4e0", // test1
		Roles:             []string{"a", "b"},
		Admin:             false,
		TOTPSeed:          nil,
		RecoveryCodes:     nil,
		PasswordTimestamp: time.Now().Add(-10 * time.Hour).Unix(),
		StoredCredentials: nil,
	}

	sampleDisabledUser = &user.User{
		Id:                uuid.New().String(),
		Username:          "regularuser",
		PasswordHash:      "$argon2id$v=19$m=65536,t=3,p=2$f5DrCPQlwRJ5q1fA4K+i/g$c8XhJISMUI3wjIUULHvn0HIJinvOBBb4KnvOcvuJ4e0", // test1
		Roles:             []string{"a", "b"},
		Admin:             false,
		TOTPSeed:          nil,
		RecoveryCodes:     nil,
		PasswordTimestamp: time.Now().Add(-10 * time.Hour).Unix(),
		StoredCredentials: nil,
		Disabled:          true,
	}

	sampleDisabledUserWithTOTP = &user.User{
		Id:                uuid.New().String(),
		Username:          "regularuser",
		PasswordHash:      "$argon2id$v=19$m=65536,t=3,p=2$f5DrCPQlwRJ5q1fA4K+i/g$c8XhJISMUI3wjIUULHvn0HIJinvOBBb4KnvOcvuJ4e0", // test1
		Roles:             []string{"a", "b"},
		Admin:             false,
		TOTPSeed:          &sampleTOTPSeed,
		RecoveryCodes:     nil,
		PasswordTimestamp: time.Now().Add(-10 * time.Hour).Unix(),
		StoredCredentials: nil,
		Disabled:          true,
	}

	sampleNonAdminWithOldArgonParams = &user.User{
		Id:                uuid.New().String(),
		Username:          "oldpwuser",
		PasswordHash:      "$argon2id$v=19$m=32768,t=4,p=2$8bI7QCiqbhywTY82FHeMVKI1QgcRwAWYNqoI/95EhNI$u6q8XTUlKRXYZUZrGGXDu2KZHgJnGA8fI9aJSDIJRfA", // test1
		Roles:             []string{"a", "b"},
		Admin:             false,
		TOTPSeed:          nil,
		RecoveryCodes:     nil,
		PasswordTimestamp: time.Now().Add(-10 * time.Hour).Unix(),
		StoredCredentials: nil,
	}

	sampleNonAdminWithTOTP = &user.User{
		Id:                uuid.New().String(),
		Username:          "sampletotp",
		PasswordHash:      "$argon2id$v=19$m=65536,t=3,p=2$f5DrCPQlwRJ5q1fA4K+i/g$c8XhJISMUI3wjIUULHvn0HIJinvOBBb4KnvOcvuJ4e0", // test1
		Roles:             []string{"b", "c"},
		Admin:             false,
		TOTPSeed:          &sampleTOTPSeed,
		RecoveryCodes:     nil,
		PasswordTimestamp: time.Now().Add(-10 * time.Hour).Unix(),
		StoredCredentials: nil,
	}

	keyFriendlyName               = "someRandomKey"
	keyLastUsed                   = time.Now().Add(-2 * time.Hour)
	sampleNonAdminWithCredentials = &user.User{
		Id:                uuid.New().String(),
		Username:          "ihavekeys",
		PasswordHash:      "",
		Roles:             []string{"a"},
		Admin:             false,
		TOTPSeed:          nil,
		RecoveryCodes:     nil,
		PasswordTimestamp: time.Now().Add(-10 * time.Hour).Unix(),
		StoredCredentials: []user.Passkey{
			{
				Credential: webauthn.Credential{
					ID:              []byte{86, 7, 148, 97, 110, 70, 193, 56, 81, 75, 190, 23, 211, 102, 137, 71},
					PublicKey:       []byte{165, 1, 2, 3, 38, 32, 1, 33, 88, 32, 93, 166, 99, 29, 163, 204, 120, 247, 32, 174, 246, 70, 194, 51, 177, 15, 70, 183, 251, 124, 118, 45, 183, 79, 146, 29, 221, 234, 160, 47, 187, 236, 34, 88, 32, 75, 144, 209, 18, 170, 172, 69, 49, 211, 3, 238, 70, 62, 4, 28, 3, 120, 220, 85, 154, 189, 150, 127, 38, 167, 35, 144, 246, 66, 10, 155, 240},
					AttestationType: "",
					Transport:       nil,
					Flags: webauthn.CredentialFlags{
						UserPresent:    true,
						UserVerified:   true,
						BackupEligible: true,
						BackupState:    true,
					},
					Authenticator: webauthn.Authenticator{
						AAGUID:       []byte{186, 218, 85, 102, 167, 170, 64, 31, 189, 150, 69, 97, 154, 85, 18, 13},
						SignCount:    0,
						CloneWarning: false,
						Attachment:   protocol.Platform,
					},
				},
				FriendlyName: &keyFriendlyName,
				LastUsed:     &keyLastUsed,
			},
		},
	}
	sampleNonAdminWithMultiplePasskeys = &user.User{
		Id:                uuid.New().String(),
		Username:          "ihavekeys",
		PasswordHash:      "",
		Roles:             []string{"a"},
		Admin:             false,
		TOTPSeed:          nil,
		RecoveryCodes:     nil,
		PasswordTimestamp: time.Now().Add(-10 * time.Hour).Unix(),
		StoredCredentials: []user.Passkey{
			{
				Credential: webauthn.Credential{
					ID:              []byte{86, 7, 148, 97, 110, 70, 193, 56, 81, 75, 190, 23, 211, 102, 137, 71},
					PublicKey:       []byte{165, 1, 2, 3, 38, 32, 1, 33, 88, 32, 93, 166, 99, 29, 163, 204, 120, 247, 32, 174, 246, 70, 194, 51, 177, 15, 70, 183, 251, 124, 118, 45, 183, 79, 146, 29, 221, 234, 160, 47, 187, 236, 34, 88, 32, 75, 144, 209, 18, 170, 172, 69, 49, 211, 3, 238, 70, 62, 4, 28, 3, 120, 220, 85, 154, 189, 150, 127, 38, 167, 35, 144, 246, 66, 10, 155, 240},
					AttestationType: "",
					Transport:       nil,
					Flags: webauthn.CredentialFlags{
						UserPresent:    true,
						UserVerified:   true,
						BackupEligible: true,
						BackupState:    true,
					},
					Authenticator: webauthn.Authenticator{
						AAGUID:       []byte{186, 218, 85, 102, 167, 170, 64, 31, 189, 150, 69, 97, 154, 85, 18, 13},
						SignCount:    0,
						CloneWarning: false,
						Attachment:   protocol.Platform,
					},
				},
				FriendlyName: &keyFriendlyName,
				LastUsed:     &keyLastUsed,
			},
			{
				Credential: webauthn.Credential{
					ID:              []byte{181, 87, 220, 35, 39, 191, 127, 140, 30, 194, 15, 63, 207, 245, 166, 59},
					PublicKey:       []byte{241, 207, 131, 106, 200, 171, 99, 251, 101, 45, 152, 125, 135, 54, 163, 6, 171, 54, 107, 71, 153, 193, 2, 99, 196, 5, 159, 201, 111, 59, 233, 10, 32, 90, 191, 115, 30, 128, 136, 157, 69, 242, 192, 157, 8, 71, 62, 138, 26, 195, 112, 163, 145, 84, 108, 255, 0, 193, 23, 91, 235, 168, 167, 246, 131, 53, 7, 67, 223, 152, 115, 176, 155, 146, 34, 46, 211, 249},
					AttestationType: "",
					Transport:       nil,
					Flags: webauthn.CredentialFlags{
						UserPresent:    true,
						UserVerified:   true,
						BackupEligible: true,
						BackupState:    true,
					},
					Authenticator: webauthn.Authenticator{
						AAGUID:       []byte{124, 211, 149, 213, 32, 159, 139, 22, 212, 19, 40, 124, 170, 35, 112, 209},
						SignCount:    0,
						CloneWarning: false,
						Attachment:   protocol.Platform,
					},
				},
				FriendlyName: &keyFriendlyName,
				LastUsed:     &keyLastUsed,
			},
		},
	}
)

type connectionOption func(cd *testConnectionData)

var (
	withUser = func(u *user.User, db *mocks.MockDB) connectionOption {
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
	withCustomSession = func(s func(s *session2.Session)) connectionOption {
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

func makeTestEnv(t *testing.T) (*mocks.MockAnalyzer, *mocks.MockDB, *mocks.MockLoginLimiter, *Env) {
	a := mocks.NewMockAnalyzer(t)
	db := mocks.NewMockDB(t)
	ll := mocks.NewMockLoginLimiter(t)
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          "example.com",
		RPDisplayName: "example.com",
		RPOrigins:     []string{"https://example.com"},
	})
	assert.NoError(t, err)
	return a, db, ll, &Env{
		Database:     db,
		Analyzer:     a,
		WebAuthn:     wa,
		LoginLimiter: ll,
	}
}

type testConnectionData struct {
	req  *http.Request
	sess *session2.Session
	sc   *securecookie.SecureCookie
	user *user.User
}

func makeTestRequest(t *testing.T, method string, path string, body io.Reader, opts ...connectionOption) *http.Request {
	tcd := &testConnectionData{}
	tcd.req = httptest.NewRequest(method, path, body)

	sess, err := session2.NewDefaultSession()
	require.NoError(t, err)
	tcd.sess = &sess
	tcd.sc = securecookie.New(salt.GenerateSigningKey(), salt.GenerateEncryptionKey())

	for i := range opts {
		opts[i](tcd)
	}

	tcd.req = session2.ArbitraryAttachSession(*tcd.sess, tcd.req, tcd.user, tcd.sc)
	encodedSession, err := tcd.sc.Encode(session2.SessionCookieName, sess)
	require.NoError(t, err)
	tcd.req.AddCookie(&http.Cookie{
		Name:  session2.SessionCookieName,
		Value: encodedSession,
	})

	return tcd.req
}
