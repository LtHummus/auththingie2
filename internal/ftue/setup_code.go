package ftue

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/lthummus/auththingie2/internal/render"
)

func (fe *ftueEnv) HandleSetupCodeGET(w http.ResponseWriter, r *http.Request) {
	render.Render(w, "ftue_setupcode.gohtml", nil)
}

func (fe *ftueEnv) HandleSetupCodePOST(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		log.Error().Err(err).Msg("could not parse form")
		http.Error(w, "could not parse form data", http.StatusBadRequest)
		return
	}

	givenSetupCode := strings.TrimSpace(r.FormValue("setup_code"))
	if subtle.ConstantTimeCompare([]byte(givenSetupCode), []byte(fe.setupCode)) != 1 {
		log.Error().Err(err).Msg("invalid setup code")
		render.Render(w, "ftue_setupcode.gohtml", map[string]any{
			"Errors": []string{
				"Invalid setup code. Check the AuthThingie2 logs to find it",
			},
		})
		return
	}

	fe.protector.WriteSession(w, givenSetupCode)

	http.Redirect(w, r, "/begin", http.StatusFound)
}
