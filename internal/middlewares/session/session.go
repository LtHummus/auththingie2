package session

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/spf13/viper"

	"github.com/lthummus/auththingie2/internal/config"
	"github.com/lthummus/auththingie2/internal/user"

	"github.com/rs/zerolog/log"
)

const (
	IDLengthBytes = 32 // 256-bit

	DefaultCookieLifetime = 30 * 24 * time.Hour

	DefaultSessionLifetime = 7 * 24 * time.Hour
)

type Session struct {
	SessionID    string    `json:"session_id"`
	UserID       string    `json:"user_id,omitempty"`
	LoginTime    time.Time `json:"login_time"`
	Expires      time.Time `json:"expires"`
	CreationTime time.Time `json:"creation_time"` // note to self, is this useful?

	CustomData map[string]any `json:"custom_data"`
}

func NewDefaultSession(v *viper.Viper) (Session, error) {
	id, err := generateSessionID()
	if err != nil {
		log.Error().Err(err).Msg("could not generate session id")
		return Session{}, err
	}

	return Session{
		SessionID:    id,
		CreationTime: time.Now(),
		CustomData:   map[string]any{},
		Expires:      time.Now().Add(SessionLifetime(v)),
	}, nil
}

func CookieLifetime(v *viper.Viper) time.Duration {
	d := v.GetDuration(config.ConfigKeyDefaultCookieLifetime)
	if d != 0 {
		return d
	}

	return DefaultCookieLifetime
}

func SessionLifetime(v *viper.Viper) time.Duration {
	d := v.GetDuration(config.ConfigKeyDefaultSessionLifetime)
	if d != 0 {
		return d
	}

	return DefaultSessionLifetime
}

func (s *Session) ID() string {
	return s.SessionID
}

func (s *Session) Expired() bool {
	return s.Expires.Before(time.Now())
}

func (s *Session) PlaceUserInSession(u *user.User, v *viper.Viper) error {
	if u.Disabled {
		log.Panic().Str("username", u.Username).Msg("attempted to place disabled user in session")
	}

	newSessionID, err := generateSessionID()
	if err != nil {
		return fmt.Errorf("session: PlaceUserInSession: could not generate session ID: %w", err)
	}

	s.SessionID = newSessionID
	s.UserID = u.Id
	s.Expires = time.Now().Add(SessionLifetime(v))
	s.LoginTime = time.Now()
	log.Debug().Str("username", u.Username).Time("expires", s.Expires).Time("login_time", s.LoginTime).Msg("placing in session")

	return nil
}

func generateSessionID() (string, error) {
	b := make([]byte, IDLengthBytes)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b), nil
}
