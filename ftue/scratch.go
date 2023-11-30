package ftue

import (
	"net/http"

	"github.com/gorilla/csrf"
	"github.com/rs/zerolog/log"

	"github.com/lthummus/auththingie2/render"
	"github.com/lthummus/auththingie2/user"
)

func (fe *ftueEnv) HandleFTUEScratch(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		fe.handleScratchAdminCrate(w, r)
	} else if r.Method == http.MethodGet {
		render.Render(w, "ftuescratch.gohtml", &ftueParams{
			CSRFField: csrf.TemplateField(r),
		})
	} else {
		http.Error(w, "not found", http.StatusNotFound)
	}
}

func (fe *ftueEnv) handleScratchAdminCrate(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	if username == "" {
		render.Render(w, "ftuescratch.gohtml", &ftueParams{
			CSRFField: csrf.TemplateField(r),
			Error:     "username must be specified",
		})
		return
	}

	password := r.FormValue("password")
	password2 := r.FormValue("password2")

	if password == "" || password != password2 {
		render.Render(w, "ftuescratch.gohtml", &ftueParams{
			CSRFField: csrf.TemplateField(r),
			Error:     "password mismatch or is blank!",
		})
		return
	}

	u := &user.User{
		Username: username,
		Admin:    true,
	}

	err := u.SetPassword(password)
	if err != nil {
		log.Error().Err(err).Msg("could not hash password")
		http.Error(w, "could not hash password", http.StatusInternalServerError)
		return
	}

	err = fe.database.CreateUser(r.Context(), u)
	if err != nil {
		log.Error().Err(err).Msg("could not create admin user")
		http.Error(w, "could not create admin user", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/ftue/restart", http.StatusFound)
}
