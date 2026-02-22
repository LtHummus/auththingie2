package handlers

import (
	"errors"
	"net/http"

	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"

	"github.com/lthummus/auththingie2/internal/config"
	"github.com/lthummus/auththingie2/internal/middlewares/session"
	"github.com/lthummus/auththingie2/internal/render"
	"github.com/lthummus/auththingie2/internal/user"
)

type selfEditPageParams struct {
	Error          string
	User           *user.User
	EnablePasskeys bool
}

func (e *Env) HandleSelfConfigGet(w http.ResponseWriter, r *http.Request) {
	u := session.GetUserFromRequest(r)
	if u == nil {
		http.Error(w, "you must be logged in to access this page", http.StatusForbidden)
		return
	}

	render.Render(w, "self_config.gohtml", &selfEditPageParams{
		User:           u,
		EnablePasskeys: !viper.GetBool(config.KeyPasskeysDisabled),
	})
}

type selfConfigPasswordParams struct {
	Error string
}

func (e *Env) HandleSelfConfigPasswordGet(w http.ResponseWriter, r *http.Request) {
	render.Render(w, "self_change_password.gohtml", &selfConfigPasswordParams{})
}

func (e *Env) HandleSelfConfigPasswordPost(w http.ResponseWriter, r *http.Request) {
	u := session.GetUserFromRequest(r)
	if u == nil {
		http.Error(w, "you must be logged in to access this page", http.StatusUnauthorized)
		return
	}

	oldPw := r.FormValue("old_pw")

	err := u.CheckPassword(oldPw)
	if err != nil {
		render.Render(w, "self_change_password.gohtml", &selfConfigPasswordParams{
			Error: "Incorrect old password",
		})
		return
	}

	newPw := r.FormValue("pw1")
	newPw2 := r.FormValue("pw2")

	if newPw == "" {
		render.Render(w, "self_change_password.gohtml", &selfConfigPasswordParams{
			Error: "New password may not be blank",
		})
		return
	}

	if newPw != newPw2 {
		render.Render(w, "self_change_password.gohtml", &selfConfigPasswordParams{
			Error: "New passwords do not match",
		})
		return
	}

	err = u.SetPassword(newPw)
	if err != nil {
		if errors.Is(err, user.ErrInvalidPasswordChars) {
			render.Render(w, "self_change_password.gohtml", &selfConfigPasswordParams{
				Error: "Password contains invalid characters. Please choose a new one",
			})
			return
		}
		log.Error().Err(err).Msg("could not update user password")
		render.Render(w, "self_change_password.gohtml", &selfConfigPasswordParams{
			Error: "Error hashing new password",
		})
		return
	}

	err = e.Database.SaveUser(r.Context(), u)
	if err != nil {
		log.Error().Err(err).Msg("could not save updated user")
		render.Render(w, "self_change_password.gohtml", &selfConfigPasswordParams{
			Error: "Could not save updated password to database",
		})
		return
	}

	http.Redirect(w, r, "/", http.StatusFound)
}
