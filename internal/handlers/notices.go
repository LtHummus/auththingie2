package handlers

import (
	"net/http"

	"github.com/spf13/viper"

	"github.com/lthummus/auththingie2/internal/middlewares/session"
	"github.com/lthummus/auththingie2/internal/notices"
	"github.com/lthummus/auththingie2/internal/render"
)

func (e *Env) ShowNotices(w http.ResponseWriter, r *http.Request) {
	u := session.GetUserFromRequest(r)
	if u == nil || !u.Admin {
		http.Error(w, "you cannot access this page", http.StatusForbidden)
		return
	}

	redirectURL := getRedirectURIFromRequest(r)
	if redirectURL == "" {
		redirectURL = "/"
	}

	if viper.GetBool("unsafe_hide_admin_messages") {
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	messages := notices.GetMessages()

	if len(messages) == 0 {
		// not sure how we ended up here if there are no messages, but just redirect the user to where they
		// were going
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	render.Render(w, "notices.gohtml", map[string]any{
		"Messages":    messages,
		"Destination": redirectURL,
	})
}
