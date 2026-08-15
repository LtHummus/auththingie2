package session

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/gob"
	"io"
	"net/http"

	"github.com/gorilla/securecookie"
	"github.com/rs/zerolog/log"
)

func init() {
	gob.Register(FTUESession{})
}

const (
	hkdfInfoEncryptionKey = "AUTHTHINGIE2-FTUE-KEY"
	hkdfInfoSigningKey    = "AUTHTHINGIE2-FTUE-SIGNING"

	FTUESessionCookieName = "auththingie2-setup"
)

type FTUESession struct {
	SetupCode string `json:"setup_code"`
}

type Middleware struct {
	sc        *securecookie.SecureCookie
	setupCode string
}

type MiddlewareHandler struct {
	sc        *securecookie.SecureCookie
	next      http.Handler
	setupCode string
}

func NewMiddleware(setupCode string) *Middleware {
	// here, we will generate purely random, ephemeral encryption keys to protect the session data
	// since the FTUE will be used only once (hopefully), we don't care about persistance, or keeping things around
	// or anything of that.
	secret := securecookie.GenerateRandomKey(32)
	salt := securecookie.GenerateRandomKey(32)

	sk, err := hkdf.Key(sha256.New, secret, salt, hkdfInfoSigningKey, 32)
	if err != nil {
		log.Fatal().Err(err).Msg("could not generate setup session signing key")
	}
	ek, err := hkdf.Key(sha256.New, secret, salt, hkdfInfoEncryptionKey, 32)
	if err != nil {
		log.Fatal().Err(err).Msg("could not generate setup session signing key")
	}
	return &Middleware{
		sc:        securecookie.New(sk, ek),
		setupCode: setupCode,
	}
}

func (m *Middleware) EncodeValidCookie(setupCode string) (string, error) {
	encoded, err := m.sc.Encode(FTUESessionCookieName, &FTUESession{SetupCode: setupCode})
	if err != nil {
		return "", err
	}

	return encoded, nil
}

func (m *Middleware) WriteSession(w http.ResponseWriter, setupCode string) error {
	encoded, err := m.EncodeValidCookie(setupCode)
	if err != nil {
		log.Error().Err(err).Msg("could not encode setup cookie")
		return err
	}

	// #nosec G124 -- setup may be run over insecure methods (for example accessed directly from an internal network)
	// and we want to support that
	http.SetCookie(w, &http.Cookie{
		Name:     FTUESessionCookieName,
		Value:    encoded,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})

	return nil
}

func (m *Middleware) Protect(handler http.Handler) *MiddlewareHandler {
	return &MiddlewareHandler{
		next:      handler,
		sc:        m.sc,
		setupCode: m.setupCode,
	}
}

func (m *Middleware) ProtectFunc(handler http.HandlerFunc) *MiddlewareHandler {
	return &MiddlewareHandler{
		next:      handler,
		sc:        m.sc,
		setupCode: m.setupCode,
	}
}

func (mh *MiddlewareHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(FTUESessionCookieName); err == nil {
		s := &FTUESession{}
		if err = mh.sc.Decode(FTUESessionCookieName, c.Value, &s); err != nil {
			http.Error(w, "invalid setup cookie. start over. i am sorry", http.StatusForbidden)
			return
		}

		if subtle.ConstantTimeCompare([]byte(mh.setupCode), []byte(s.SetupCode)) != 1 {
			http.Error(w, "incorrect setup code somehow. start over", http.StatusForbidden)
			return
		}

		mh.next.ServeHTTP(w, r)
	} else {
		http.Error(w, "no setup cookie found. start over", http.StatusUnauthorized)
	}
}

var codeEncoder = base32.NewEncoding("0123456789ABCDEFGHJKMNPQRSTVWXYZ").WithPadding(base32.NoPadding)

func GenerateSetupCode() (string, error) {
	buf := make([]byte, 16)
	_, err := io.ReadFull(rand.Reader, buf)
	if err != nil {
		return "", err
	}

	return codeEncoder.EncodeToString(buf), nil
}
