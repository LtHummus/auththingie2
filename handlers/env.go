package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/rs/zerolog/log"

	"github.com/lthummus/auththingie2/db"
	"github.com/lthummus/auththingie2/rules"
)

type Env struct {
	Database db.DB
	Analyzer rules.Analyzer
	WebAuthn *webauthn.WebAuthn
}

func writeJSONError(w http.ResponseWriter, msg string, errorCode string, statusCode int) {
	resp := struct {
		Message   string `json:"message"`
		ErrorCode string `json:"error_code"`
		Failed    bool   `json:"failed"`
	}{
		Message:   msg,
		ErrorCode: errorCode,
		Failed:    true,
	}

	// this can never fail to marshal
	bytes, _ := json.Marshal(resp)

	w.WriteHeader(statusCode)
	_, err := w.Write(bytes)
	if err != nil {
		log.Error().Err(err).Caller(1).Msg("could not write JSON error to response")
	}
}
