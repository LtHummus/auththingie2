package handlers

import (
	"net/http"

	"github.com/rs/zerolog/log"

	session2 "github.com/lthummus/auththingie2/middlewares/session"
)

func (e *Env) HandleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	sess, err := session2.NewDefaultSession()
	if err != nil {
		log.Warn().Err(err).Msg("could not create default session")
		http.Error(w, "could not create default session", http.StatusInternalServerError)
		return
	}

	err = session2.WriteSession(w, r, sess)
	if err != nil {
		log.Warn().Err(err).Msg("could not sign user out")
		http.Error(w, "could not sign user out", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusFound)
}
