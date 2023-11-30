package handlers

import (
	"fmt"
	"net/http"
	"time"

	"github.com/hyperjumptech/jiffy"
	"github.com/rs/zerolog/log"

	"github.com/lthummus/auththingie2/middlewares/session"
	"github.com/lthummus/auththingie2/render"
	"github.com/lthummus/auththingie2/user"
)

type indexParams struct {
	User         *user.User
	LoginTime    string
	DurationTime string
}

const (
	loginDurationMinimum = 5 * time.Second
)

func (e *Env) HandleIndex(w http.ResponseWriter, r *http.Request) {
	needsSetup, err := e.Database.NeedsSetup(r.Context())
	if err != nil {
		log.Error().Err(err).Msg("could not check setup status")
		http.Error(w, "could not check setup status", http.StatusInternalServerError)
		return
	}

	if needsSetup {
		log.Info().Msg("AuthThingie2 has not been setup. Forwarding to setup...")
		http.Redirect(w, r, "/ftue", http.StatusFound)
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	u := session.GetUserFromRequest(r)
	s := session.GetSessionFromRequest(r)

	loginDuration := time.Since(s.LoginTime)
	timeString := ""
	durationString := ""
	if u != nil {
		timeString = s.LoginTime.Format(time.RFC822)
		if loginDuration < loginDurationMinimum {
			durationString = "just now"
		} else {
			durationString = fmt.Sprintf("%s ago", jiffy.DescribeDuration(loginDuration, jiffy.NewWant()))
		}
	}

	render.Render(w, "index.gohtml", &indexParams{
		User:         u,
		LoginTime:    timeString,
		DurationTime: durationString,
	})
}

func (e *Env) HandleBulkIndex(w http.ResponseWriter, r *http.Request) {
	u := session.GetUserFromRequest(r)
	if u == nil {
		e.renderLoggedOutIndex(w, r)
	} else {
		e.renderLoggedInIndex(w, r, u)
	}
}

func (e *Env) renderLoggedOutIndex(w http.ResponseWriter, r *http.Request) {
	render.Render(w, "index.loggedout.gohtml", nil)
}

func (e *Env) renderLoggedInIndex(w http.ResponseWriter, r *http.Request, u *user.User) {
	render.Render(w, "index.loggedin.gohtml", map[string]string{
		"Username": u.Username,
	})
}
