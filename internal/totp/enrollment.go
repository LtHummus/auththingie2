package totp

import (
	"encoding/json"
	"fmt"
	"time"
)

var enrollmentKind = []byte{'e'}

type EnrollmentTicket struct {
	UserID     string    `json:"u"`
	Seed       string    `json:"s"`
	Expiration time.Time `json:"e"`
}

func GenerateEnrollmentTicket(userID string, seed string) EnrollmentTicket {
	return EnrollmentTicket{
		UserID:     userID,
		Seed:       seed,
		Expiration: time.Now().In(time.UTC).Add(5 * time.Minute),
	}
}

func (et *EnrollmentTicket) Encode() (string, error) {
	payloadBytes, _ := json.Marshal(et)

	return encrypt(payloadBytes, enrollmentKind)
}

func DecodeEnrollmentTicket(ticket string) (EnrollmentTicket, error) {
	var et EnrollmentTicket

	decoded, err := decrypt(ticket, enrollmentKind)
	if err != nil {
		return et, err
	}

	err = json.Unmarshal(decoded, &et)
	if err != nil {
		return et, fmt.Errorf("totp: DecodeEnrollmentTicket: could not unmarshal json: %w", err)
	}

	return et, nil
}
