package session

import (
	"context"
	"encoding/gob"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"

	"github.com/lthummus/auththingie2/argon"
	"github.com/lthummus/auththingie2/db"
	"github.com/lthummus/auththingie2/pwmigrate"
	"github.com/lthummus/auththingie2/salt"
	"github.com/lthummus/auththingie2/user"
	"github.com/lthummus/auththingie2/util"
)

type userContextKeyType string

const (
	SessionCookieName = "auththingie2_session"

	sessionContextKey userContextKeyType = "session_info"

	CookieLifetime = 48 * time.Hour
)

type UserSource int

const (
	UserSourceInvalidUser UserSource = iota
	UserSourceSession
	UserSourceBasicAuth
)

type Middleware struct {
	sc      *securecookie.SecureCookie
	db      db.DB
	handler http.Handler
}

type sessionData struct {
	id         string
	session    Session
	user       *user.User
	sc         *securecookie.SecureCookie
	writeCount int
}

func init() {
	gob.Register(Session{})
}

func NewMiddleware(next http.Handler, db db.DB) *Middleware {
	hk := salt.GenerateSigningKey()
	ek := salt.GenerateEncryptionKey()
	sc := securecookie.New(hk, ek)
	return &Middleware{
		sc:      sc,
		handler: next,
		db:      db,
	}
}

func GetSessionIDFromRequest(r *http.Request) string {
	info := r.Context().Value(sessionContextKey)
	if info == nil {
		panic("no session info in request, is middleware configured properly?")
	}

	return info.(*sessionData).id
}

func GetSessionFromRequest(r *http.Request) Session {
	info := r.Context().Value(sessionContextKey)
	if info == nil {
		panic("no session info in request, is middleware configured properly?")
	}

	return info.(*sessionData).session
}

func GetUserFromRequest(r *http.Request) *user.User {
	info := r.Context().Value(sessionContextKey)
	if info == nil {
		panic("no session info in request, is middleware configured properly?")
	}

	return info.(*sessionData).user
}

func GetUserFromRequestAllowFallback(r *http.Request, database db.DB) (*user.User, UserSource) {
	u := GetUserFromRequest(r)
	if u != nil {
		return u, UserSourceSession
	}

	username, pass, exists := r.BasicAuth()
	if !exists {
		return nil, UserSourceInvalidUser
	}

	dbu, err := database.GetUserByUsername(r.Context(), username)
	if err != nil {
		log.Warn().Err(err).Str("username", username).Msg("could not query for user")
		return nil, UserSourceInvalidUser
	}

	err = dbu.CheckPassword(pass)
	if err != nil {
		if errors.Is(err, user.ErrIncorrectPassword) {
			log.Warn().Str("username", username).Str("ip", util.FindTrueIP(r)).Msg("invalid login")
			return nil, UserSourceInvalidUser
		}
		log.Warn().Err(err).Str("username", username).Str("ip", util.FindTrueIP(r)).Msg("could not validate password")
		return nil, UserSourceInvalidUser
	}

	if argon.NeedsMigration(dbu.PasswordHash) {
		go func() {
			pwmigrate.MigrateUser(context.Background(), dbu, pass, database)
		}()
	}

	if dbu.TOTPEnabled() {
		log.Warn().Str("username", username).Str("ip", util.FindTrueIP(r)).Msg("can not use basic auth if user is TOTP enabled")
		return nil, UserSourceInvalidUser
	}

	if len(dbu.StoredCredentials) != 0 {
		log.Warn().Str("username", username).Str("ip", util.FindTrueIP(r)).Int("stored_credential_count", len(dbu.StoredCredentials)).Msg("can not use basic auth if user has passkeys")
		return nil, UserSourceInvalidUser
	}

	return dbu, UserSourceBasicAuth
}

func generateCookie(value string) *http.Cookie {
	return &http.Cookie{
		Name:     SessionCookieName,
		Value:    value,
		Secure:   true,
		HttpOnly: true,
		Domain:   viper.GetString("server.domain"),
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(DefaultLifetime.Seconds()),
	}
}

func WriteSession(w http.ResponseWriter, r *http.Request, s Session) error {
	// see if we have already set a cookie
	//allCookies := w.Header().Values("Set-Cookie")

	log.Debug().Caller(1).Msg("WriteSession")

	// TODO: check for old versions of the cookie first
	info := r.Context().Value(sessionContextKey)
	if info == nil {
		panic("no session info in request, is middleware configured properly?")
	}

	sd := info.(*sessionData)

	if sd.writeCount > 0 {
		log.Warn().Int("write_count", sd.writeCount).Caller(1).Msg("more than one WriteSessionCalled")
	}

	sd.writeCount++

	encoded, err := sd.sc.Encode(SessionCookieName, s)
	if err != nil {
		log.Error().Err(err).Msg("could not encode session data")
		return err
	}

	http.SetCookie(w, generateCookie(encoded))

	return nil
}

func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/static") {
		m.handler.ServeHTTP(w, r)
		return
	}

	// check to see if we have a session
	c, err := r.Cookie(SessionCookieName)
	if err != nil && !errors.Is(err, http.ErrNoCookie) {
		log.Error().Err(err).Msg("could not pull session cookie")
		http.Error(w, "could not pull session cookie", http.StatusInternalServerError)
		return
	}

	var sess *Session
	var u *user.User

	if c != nil {
		err = m.sc.Decode(SessionCookieName, c.Value, &sess)
		if err != nil {
			log.Warn().Err(err).Msg("could not validate session cookie")

		}

		if sess != nil && sess.UserID != "" && !sess.Expired() {
			// if the user is allegedly logged in, try and get them from the db
			u, err = m.db.GetUserByGuid(r.Context(), sess.UserID)
			if err != nil {
				log.Warn().Err(err).Msg("could not get user from db")

				// clear the session
				sess = nil
			}
		}
	}

	if u != nil {
		pwdTime := time.Unix(u.PasswordTimestamp, 0)
		if pwdTime.After(sess.CreationTime) {
			// user has changed password after this session was created, reset everything
			u = nil
			sess = nil
		}
	}

	if sess == nil {
		// no session found
		newSession, err := NewDefaultSession()
		if err != nil {
			log.Error().Err(err).Msg("could not create new session")
			http.Error(w, "could not create new session", http.StatusInternalServerError)
			return
		}
		sess = &newSession
		log.Debug().Msg("making new default session")
		encoded, err := m.sc.Encode(SessionCookieName, sess)
		if err != nil {
			log.Error().Err(err).Msg("could not encode session data")
		}

		http.SetCookie(w, generateCookie(encoded))
	}

	info := &sessionData{
		id:      sess.SessionID,
		session: *sess,
		user:    u,
		sc:      m.sc,
	}

	newCtx := context.WithValue(r.Context(), sessionContextKey, info)
	w.Header().Set("Vary", "Cookie")

	m.handler.ServeHTTP(w, r.WithContext(newCtx))

}

// ArbitraryAttachSession is used to arbitrarily attach a session's expected information to a given request...this should
// only really be used for testing because we don't have a god way to simulate the sessions middleware and some
// of our handlers might rely on it
func ArbitraryAttachSession(sess Session, r *http.Request, u *user.User) *http.Request {
	info := &sessionData{
		id:      sess.SessionID,
		session: sess,
		user:    u,
	}

	newCtx := context.WithValue(r.Context(), sessionContextKey, info)

	return r.WithContext(newCtx)
}
