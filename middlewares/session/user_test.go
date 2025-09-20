package session

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/securecookie"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/lthummus/auththingie2/mocks"
	"github.com/lthummus/auththingie2/user"
)

var (
	test1PasswordHash = "$argon2id$v=19$m=32768,t=4,p=2$doqbcsy6S669OpGN5twLfWm8mJjy6QywOJsPLnabTgs$zoyPNcenQg0H83J4EcX2QVLGJFAMkTXyg5Q8Rvt3qv0"
)

func generateMockUserSessionRequest(loggedIn bool, sc *securecookie.SecureCookie) (*user.User, *Session, *http.Request) {
	var u *user.User
	if loggedIn {
		u = &user.User{
			Id:       strings.Trim(uuid.New().String(), "-"),
			Username: "def",
		}
	}

	sess := &Session{
		SessionID:    strings.Trim(uuid.New().String(), "-"),
		UserID:       "",
		LoginTime:    time.Now().Add(-5 * time.Minute),
		Expires:      time.Now().Add(1 * time.Hour),
		CreationTime: time.Now().Add(-10 * time.Minute),
	}

	if u != nil {
		sess.UserID = u.Id
	}

	r := ArbitraryAttachSession(*sess, httptest.NewRequest(http.MethodGet, "/", nil), u, sc)

	return u, sess, r
}

func TestGetSessionFromRequest(t *testing.T) {
	t.Run("basic case", func(t *testing.T) {
		_, sess, r := generateMockUserSessionRequest(true, nil)

		retrievedSession := GetSessionFromRequest(r)
		assert.Equal(t, *sess, retrievedSession)
	})

	t.Run("panic when no session info is available", func(t *testing.T) {
		assert.Panics(t, func() {
			GetSessionFromRequest(httptest.NewRequest(http.MethodGet, "/", nil))
		})
	})
}

func TestGetUserFromRequest(t *testing.T) {
	t.Run("basic case", func(t *testing.T) {
		u, _, r := generateMockUserSessionRequest(true, nil)

		retrievedUser := GetUserFromRequest(r)

		assert.Equal(t, u, retrievedUser)
	})

	t.Run("not logged in", func(t *testing.T) {
		_, _, r := generateMockUserSessionRequest(false, nil)

		assert.Nil(t, GetUserFromRequest(r))
	})

	t.Run("panic if misconfigured", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)

		assert.Panics(t, func() {
			GetUserFromRequest(r)
		})
	})
}

func TestGetUserFromRequestAllowFallback(t *testing.T) {
	viper.Set("security.disable_migrate_on_login", true)

	t.Cleanup(func() {
		viper.Reset()
	})

	t.Run("with logged in user from session", func(t *testing.T) {
		u, _, r := generateMockUserSessionRequest(true, nil)
		db := mocks.NewMockDB(t)

		u2, source := GetUserFromRequestAllowFallback(r, db)
		assert.Equal(t, u, u2)
		assert.Equal(t, UserSourceSession, source)
	})

	t.Run("valid user from basic auth", func(t *testing.T) {
		_, _, r := generateMockUserSessionRequest(false, nil)
		db := mocks.NewMockDB(t)

		r.SetBasicAuth("test", "test1")

		db.On("GetUserByUsername", mock.Anything, "test").Return(&user.User{
			Username:          "test",
			PasswordHash:      test1PasswordHash,
			TOTPSeed:          nil,
			StoredCredentials: nil,
		}, nil)

		user, source := GetUserFromRequestAllowFallback(r, db)
		require.NotNil(t, user)

		assert.Equal(t, UserSourceBasicAuth, source)

		assert.Equal(t, "test", user.Username)
	})

	t.Run("basic auth user does not exist", func(t *testing.T) {
		_, _, r := generateMockUserSessionRequest(false, nil)
		db := mocks.NewMockDB(t)

		r.SetBasicAuth("baduser", "badpass")

		db.On("GetUserByUsername", mock.Anything, "baduser").Return(nil, nil)

		user, source := GetUserFromRequestAllowFallback(r, db)
		assert.Nil(t, user)
		assert.Equal(t, UserSourceInvalidUser, source)
	})

	t.Run("return invalid user if basic auth credentials are wrong", func(t *testing.T) {
		_, _, r := generateMockUserSessionRequest(false, nil)
		db := mocks.NewMockDB(t)

		r.SetBasicAuth("test", "test2")

		db.On("GetUserByUsername", mock.Anything, "test").Return(&user.User{
			Username:          "test",
			PasswordHash:      test1PasswordHash,
			TOTPSeed:          nil,
			StoredCredentials: nil,
		}, nil)

		user, source := GetUserFromRequestAllowFallback(r, db)
		assert.Nil(t, user)

		assert.Equal(t, UserSourceInvalidUser, source)
	})

	t.Run("return basic auth even if basic auth user has TOTP enabled", func(t *testing.T) {
		_, _, r := generateMockUserSessionRequest(false, nil)
		db := mocks.NewMockDB(t)

		r.SetBasicAuth("test", "test1")

		totpSeed := "ABCDEFG"
		db.On("GetUserByUsername", mock.Anything, "test").Return(&user.User{
			Username:          "test",
			PasswordHash:      test1PasswordHash,
			TOTPSeed:          &totpSeed,
			StoredCredentials: nil,
		}, nil)

		user, source := GetUserFromRequestAllowFallback(r, db)

		assert.True(t, user.TOTPEnabled())
		assert.Equal(t, "test", user.Username)
		assert.Equal(t, "ABCDEFG", *user.TOTPSeed)

		assert.Equal(t, UserSourceBasicAuth, source)
	})

	t.Run("return invalid user if user has passkeys enabled", func(t *testing.T) {
		_, _, r := generateMockUserSessionRequest(false, nil)
		db := mocks.NewMockDB(t)

		r.SetBasicAuth("test", "test1")

		db.On("GetUserByUsername", mock.Anything, "test").Return(&user.User{
			Username:     "test",
			PasswordHash: test1PasswordHash,
			TOTPSeed:     nil,
			StoredCredentials: []user.Passkey{
				{
					// don't actually need to define this, we just check that len is 0
				},
			},
		}, nil)

		user, source := GetUserFromRequestAllowFallback(r, db)

		assert.Equal(t, "test", user.Username)
		assert.Len(t, user.StoredCredentials, 1)
		assert.Equal(t, UserSourceBasicAuth, source)
	})
}

func TestWriteSession(t *testing.T) {
	sc := securecookie.New(securecookie.GenerateRandomKey(32), securecookie.GenerateRandomKey(32))

	t.Run("basic use case", func(t *testing.T) {
		_, s, r := generateMockUserSessionRequest(false, sc)
		w := httptest.NewRecorder()

		s.CustomData = map[string]any{
			"hello": "world",
		}

		err := WriteSession(w, r, *s)
		assert.NoError(t, err)

		resp := w.Result()

		assert.Len(t, resp.Cookies(), 1)

		cookie := resp.Cookies()[0]
		assert.Equal(t, SessionCookieName, cookie.Name)

		var decodedSess *Session
		err = sc.Decode(SessionCookieName, cookie.Value, &decodedSess)
		assert.NoError(t, err)

		assert.Equal(t, "world", decodedSess.CustomData["hello"])
	})

	t.Run("panics if middleware is misconfigured", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()
		s := Session{}

		assert.Panics(t, func() {
			_ = WriteSession(w, r, s)
		})
	})
}

func generateTestMiddleware(t *testing.T) (*securecookie.SecureCookie, *mocks.MockDB, *Middleware) {
	db := mocks.NewMockDB(t)
	sc := securecookie.New(securecookie.GenerateRandomKey(32), securecookie.GenerateRandomKey(32))

	return sc, db, &Middleware{
		sc: sc,
		db: db,
		handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("hi!"))
		}),
	}
}

func assertHandlerWasCalled(t *testing.T, r *http.Response) {
	body, err := io.ReadAll(r.Body)
	assert.NoError(t, err)
	r.Body.Close()

	assert.Equal(t, "hi!", string(body), "Handler was not called")
}

func assertSessionData(t *testing.T, sc *securecookie.SecureCookie, resp *http.Response, assertions func(t *testing.T, session *Session)) {
	assert.Len(t, resp.Cookies(), 1)

	cookie := resp.Cookies()[0]

	assert.Equal(t, SessionCookieName, cookie.Name)

	var sess *Session
	err := sc.Decode(SessionCookieName, cookie.Value, &sess)
	require.NoError(t, err)

	assertions(t, sess)
}

func TestMiddleware_ServeHTTP(t *testing.T) {
	t.Run("do nothing if path prefix is /static", func(t *testing.T) {
		_, _, m := generateTestMiddleware(t)

		r := httptest.NewRequest(http.MethodGet, "/static/js/auththingie.js", nil)
		w := httptest.NewRecorder()

		m.ServeHTTP(w, r)

		assertHandlerWasCalled(t, w.Result())
	})

	t.Run("generate a new session if one did not exist", func(t *testing.T) {
		sc, _, m := generateTestMiddleware(t)

		r := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()

		m.ServeHTTP(w, r)

		resp := w.Result()

		assertSessionData(t, sc, resp, func(t *testing.T, session *Session) {
			assert.Empty(t, session.UserID)
			assert.WithinDuration(t, time.Now(), session.CreationTime, 5*time.Second)
		})
		assertHandlerWasCalled(t, resp)
	})

	t.Run("fail on bad session decode", func(t *testing.T) {
		sc, _, m := generateTestMiddleware(t)

		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.AddCookie(&http.Cookie{
			Name:  SessionCookieName,
			Value: "abcdefg",
		})
		w := httptest.NewRecorder()

		m.ServeHTTP(w, r)

		resp := w.Result()
		assertSessionData(t, sc, resp, func(t *testing.T, session *Session) {
			assert.Empty(t, session.UserID)
			assert.WithinDuration(t, time.Now(), session.CreationTime, 5*time.Second)
		})
		assertHandlerWasCalled(t, resp)

	})

	t.Run("properly read user from session", func(t *testing.T) {
		sc, db, m := generateTestMiddleware(t)

		db.On("GetUserByGuid", mock.Anything, "test-user").Return(&user.User{
			Username:          "test-username",
			Id:                "test-user",
			PasswordTimestamp: time.Now().Add(-1 * time.Hour).Unix(),
		}, nil)

		encodedSession, err := sc.Encode(SessionCookieName, Session{
			SessionID:    strings.Trim(uuid.New().String(), "-"),
			UserID:       "test-user",
			LoginTime:    time.Now().Add(-5 * time.Minute),
			Expires:      time.Now().Add(10 * time.Minute),
			CreationTime: time.Now().Add(-10 * time.Minute),
			CustomData:   nil,
		})
		require.NoError(t, err)

		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.AddCookie(&http.Cookie{
			Name:  SessionCookieName,
			Value: encodedSession,
		})

		w := httptest.NewRecorder()

		m.ServeHTTP(w, r)

		resp := w.Result()

		assert.Empty(t, resp.Cookies()) // assert we were not logged out
		assertHandlerWasCalled(t, resp)
	})

	t.Run("log user out if password has changed recently", func(t *testing.T) {
		sc, db, m := generateTestMiddleware(t)

		db.On("GetUserByGuid", mock.Anything, "test-user").Return(&user.User{
			Username:          "test-username",
			Id:                "test-user",
			PasswordTimestamp: time.Now().Add(-1 * time.Minute).Unix(),
		}, nil)

		encodedSession, err := sc.Encode(SessionCookieName, Session{
			SessionID:    strings.Trim(uuid.New().String(), "-"),
			UserID:       "test-user",
			LoginTime:    time.Now().Add(-5 * time.Minute),
			Expires:      time.Now().Add(10 * time.Minute),
			CreationTime: time.Now().Add(-10 * time.Minute),
			CustomData:   nil,
		})
		require.NoError(t, err)
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.AddCookie(&http.Cookie{
			Name:  SessionCookieName,
			Value: encodedSession,
		})

		w := httptest.NewRecorder()

		m.ServeHTTP(w, r)

		assertSessionData(t, sc, w.Result(), func(t *testing.T, session *Session) {
			assert.Empty(t, session.UserID) // assert we were logged out
		})

	})

	t.Run("expire session after expiration date", func(t *testing.T) {
		sc, _, m := generateTestMiddleware(t)

		encodedSession, err := sc.Encode(SessionCookieName, Session{
			SessionID:    strings.Trim(uuid.New().String(), "-"),
			UserID:       "test-user",
			LoginTime:    time.Now().Add(-5 * time.Minute),
			Expires:      time.Now().Add(-10 * time.Minute),
			CreationTime: time.Now().Add(-10 * time.Minute),
			CustomData:   nil,
		})
		require.NoError(t, err)
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.AddCookie(&http.Cookie{
			Name:  SessionCookieName,
			Value: encodedSession,
		})

		w := httptest.NewRecorder()

		m.ServeHTTP(w, r)

		assertSessionData(t, sc, w.Result(), func(t *testing.T, session *Session) {
			assert.Empty(t, session.UserID) // assert we were logged out
		})

	})

	t.Run("recreate session if database error", func(t *testing.T) {
		sc, db, m := generateTestMiddleware(t)

		db.On("GetUserByGuid", mock.Anything, "test-user").Return(nil, errors.New("oh no"))

		encodedSession, err := sc.Encode(SessionCookieName, Session{
			SessionID:    strings.Trim(uuid.New().String(), "-"),
			UserID:       "test-user",
			LoginTime:    time.Now().Add(-5 * time.Minute),
			Expires:      time.Now().Add(10 * time.Minute),
			CreationTime: time.Now().Add(-10 * time.Minute),
			CustomData:   nil,
		})
		require.NoError(t, err)
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.AddCookie(&http.Cookie{
			Name:  SessionCookieName,
			Value: encodedSession,
		})

		w := httptest.NewRecorder()

		m.ServeHTTP(w, r)

		assertSessionData(t, sc, w.Result(), func(t *testing.T, session *Session) {
			assert.Empty(t, session.UserID) // assert we were logged out
		})
	})

	t.Run("issue new session if user does not exist", func(t *testing.T) {
		sc, db, m := generateTestMiddleware(t)

		db.On("GetUserByGuid", mock.Anything, "test-user").Return(nil, nil)

		encodedSession, err := sc.Encode(SessionCookieName, Session{
			SessionID:    strings.Trim(uuid.New().String(), "-"),
			UserID:       "test-user",
			LoginTime:    time.Now().Add(-5 * time.Minute),
			Expires:      time.Now().Add(10 * time.Minute),
			CreationTime: time.Now().Add(-10 * time.Minute),
			CustomData:   nil,
		})
		require.NoError(t, err)

		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.AddCookie(&http.Cookie{
			Name:  SessionCookieName,
			Value: encodedSession,
		})

		w := httptest.NewRecorder()

		m.ServeHTTP(w, r)

		resp := w.Result()

		assertSessionData(t, sc, w.Result(), func(t *testing.T, session *Session) {
			assert.Empty(t, session.UserID) // assert we were logged out
		})
		assertHandlerWasCalled(t, resp)
	})

	t.Run("don't reissue sessions if users are nil", func(t *testing.T) {
		sc, _, m := generateTestMiddleware(t)

		encodedSession, err := sc.Encode(SessionCookieName, Session{
			SessionID: strings.Trim(uuid.New().String(), "-"),
			UserID:    "",
			Expires:   time.Now().Add(1 * time.Hour),
			CustomData: map[string]any{
				"foo": "bar",
			},
		})
		require.NoError(t, err)

		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.AddCookie(&http.Cookie{
			Name:  SessionCookieName,
			Value: encodedSession,
		})

		w := httptest.NewRecorder()

		m.ServeHTTP(w, r)

		resp := w.Result()

		assert.Empty(t, resp.Cookies())
		assertHandlerWasCalled(t, resp)
	})
}
