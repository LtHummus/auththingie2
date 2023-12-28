package session

import (
	"crypto/rand"
	"encoding/base64"
	"time"

	"github.com/lthummus/auththingie2/user"

	"github.com/rs/zerolog/log"
)

const (
	IDLengthBytes = 32 // 256-bit

	DefaultLifetime = 24 * time.Hour

	DefaultSessionLifetime = 24 * 30 * time.Hour
)

type Session struct {
	SessionID    string    `json:"session_id"`
	UserID       string    `json:"user_id,omitempty"`
	LoginTime    time.Time `json:"login_time"`
	Expires      time.Time `json:"expires"` // note to self, is this useful?
	CreationTime time.Time `json:"creation_time"`

	CustomData map[string]any `json:"custom_data"`
}

func NewDefaultSession() (Session, error) {
	id, err := generateSessionID()
	if err != nil {
		log.Error().Err(err).Msg("could not generate session id")
		return Session{}, err
	}

	return Session{
		SessionID:    id,
		CreationTime: time.Now(),
		CustomData:   map[string]any{},
		Expires:      time.Now().Add(DefaultSessionLifetime),
	}, nil
}

func (s *Session) ID() string {
	return s.SessionID
}

func (s *Session) Expired() bool {
	return s.Expires.Before(time.Now())
}

func (s *Session) PlaceUserInSession(u *user.User) {
	log.Debug().Str("username", u.Username).Msg("placing in session")
	s.UserID = u.Id
	s.Expires = time.Now().Add(24 * time.Hour)
	s.LoginTime = time.Now()
}

func generateSessionID() (string, error) {
	b := make([]byte, IDLengthBytes)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b), nil
}
