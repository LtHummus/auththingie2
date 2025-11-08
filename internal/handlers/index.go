package handlers

import (
	"fmt"
	"net/http"
	"time"

	"github.com/lthummus/auththingie2/internal/durations"
	"github.com/lthummus/auththingie2/internal/middlewares/session"
	"github.com/lthummus/auththingie2/internal/render"
	"github.com/lthummus/auththingie2/internal/user"
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
			durationString = fmt.Sprintf("%s ago", durations.NiceDuration(loginDuration))
		}
	}

	render.Render(w, "index.gohtml", &indexParams{
		User:         u,
		LoginTime:    timeString,
		DurationTime: durationString,
	})
}
