package handlers

import (
	"html/template"
	"net/http"

	"github.com/gorilla/csrf"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"

	"github.com/lthummus/auththingie2/config"
	"github.com/lthummus/auththingie2/middlewares/session"
	"github.com/lthummus/auththingie2/render"
	"github.com/lthummus/auththingie2/user"
)

type selfEditPageParams struct {
	Error          string
	User           *user.User
	CSRFToken      string
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
		CSRFToken:      csrf.Token(r),
		EnablePasskeys: !viper.GetBool(config.KeyPasskeysDisabled),
	})
}

type selfConfigPasswordParams struct {
	CSRFField template.HTML
	Error     string
}

func (e *Env) HandleSelfConfigPasswordGet(w http.ResponseWriter, r *http.Request) {
	render.Render(w, "self_change_password.gohtml", &selfConfigPasswordParams{
		CSRFField: csrf.TemplateField(r),
	})
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
			CSRFField: csrf.TemplateField(r),
			Error:     "Incorrect old password",
		})
		return
	}

	newPw := r.FormValue("pw1")
	newPw2 := r.FormValue("pw2")

	if newPw == "" {
		render.Render(w, "self_change_password.gohtml", &selfConfigPasswordParams{
			CSRFField: csrf.TemplateField(r),
			Error:     "New password may not be blank",
		})
		return
	}

	if newPw != newPw2 {
		render.Render(w, "self_change_password.gohtml", &selfConfigPasswordParams{
			CSRFField: csrf.TemplateField(r),
			Error:     "New passwords do not match",
		})
		return
	}

	err = u.SetPassword(newPw)
	if err != nil {
		log.Error().Err(err).Msg("could not update user password")
		render.Render(w, "self_change_password.gohtml", &selfConfigPasswordParams{
			CSRFField: csrf.TemplateField(r),
			Error:     "Error hashing new password",
		})
		return
	}

	err = e.Database.SaveUser(r.Context(), u)
	if err != nil {
		log.Error().Err(err).Msg("could not save updated user")
		render.Render(w, "self_change_password.gohtml", &selfConfigPasswordParams{
			CSRFField: csrf.TemplateField(r),
			Error:     "Could not save updated password to database",
		})
		return
	}

	http.Redirect(w, r, "/", http.StatusFound)
}
