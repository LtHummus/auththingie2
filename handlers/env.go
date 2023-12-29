package handlers

import (
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/lthummus/auththingie2/db"
	"github.com/lthummus/auththingie2/rules"
)

type Env struct {
	Database db.DB
	Analyzer rules.Analyzer
	WebAuthn *webauthn.WebAuthn
}
