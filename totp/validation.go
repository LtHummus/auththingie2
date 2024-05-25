package totp

import (
	"encoding/json"
	"fmt"
	"time"
)

var loginKind = []byte{'l'}

type LoginTicket struct {
	UserID      string    `json:"u"`
	RedirectURI string    `json:"r"`
	Expiration  time.Time `json:"e"`
}

func GenerateLoginTicket(userID, redirectURI string) LoginTicket {
	return LoginTicket{
		UserID:      userID,
		RedirectURI: redirectURI,
		Expiration:  time.Now().In(time.UTC).Add(5 * time.Minute),
	}
}

func (lt *LoginTicket) Encode() (string, error) {
	payloadBytes, _ := json.Marshal(lt)
	return encrypt(payloadBytes, loginKind)
}

func DecodeLoginTicket(ticket string) (LoginTicket, error) {
	var lt LoginTicket
	decoded, err := decrypt(ticket, loginKind)
	if err != nil {
		return lt, err
	}

	err = json.Unmarshal(decoded, &lt)
	if err != nil {
		return lt, fmt.Errorf("totp: DecodeLoginTicket: could not unmarshall json: %w", err)
	}

	return lt, nil
}
