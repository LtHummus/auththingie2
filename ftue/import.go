package ftue

import (
	"encoding/hex"
	"net/http"

	"github.com/gorilla/csrf"
	"github.com/gorilla/securecookie"
	"github.com/jellydator/ttlcache/v3"
	"github.com/rs/zerolog/log"

	"github.com/lthummus/auththingie2/importer"
	"github.com/lthummus/auththingie2/render"
	"github.com/lthummus/auththingie2/rules"
)

func (fe *ftueEnv) HandleImport(w http.ResponseWriter, r *http.Request) {
	initCache()
	if r.Method == http.MethodGet {
		render.Render(w, "ftue_import.gohtml", &ftueParams{
			CSRFField: csrf.TemplateField(r),
		})
	} else if r.Method == http.MethodPost {
		fe.handleFileUpload(w, r)
	} else {
		http.Error(w, "not found", http.StatusNotFound)
	}
}

func (fe *ftueEnv) handleFileUpload(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		log.Error().Err(err).Msg("could not parse form")
		http.Error(w, "shrug", http.StatusBadRequest)
		return
	}

	// TODO: handle file uploads here

	configText := r.FormValue("config_file_text")
	if configText == "" {
		http.Error(w, "no contents", http.StatusBadRequest)
		return
	}

	data, err := importer.Import(configText)
	if err != nil {
		log.Error().Err(err).Msg("could not parse config file")
		http.Error(w, "could not parse config file", http.StatusBadRequest)
		return
	}

	log.Info().Int("num_rules", len(data.Rules)).Int("num_users", len(data.Users)).Msg("config file parsed")

	dr := make([]*rules.DisplayableRule, len(data.Rules))
	for i := range data.Rules {
		dr[i] = rules.RuleToDisplayableRule(data.Rules[i])
	}

	importKey := securecookie.GenerateRandomKey(32)
	if err != nil {
		log.Error().Err(err).Msg("could not generate import key")
		http.Error(w, "could not generate import key", http.StatusInternalServerError)
		return
	}

	importKeyString := hex.EncodeToString(importKey)

	importCache.Set(importKeyString, data, ttlcache.DefaultTTL)

	p := &ftueImportConfirmParams{
		Rules:     dr,
		Users:     data.Users,
		CSRFField: csrf.TemplateField(r),
		ImportKey: importKeyString,
	}

	render.Render(w, "ftue_import_confirm.gohtml", p)
}

func (fe *ftueEnv) HandleImportConfirm(w http.ResponseWriter, r *http.Request) {
	importKeyString := r.FormValue("import_key")
	if importKeyString == "" {
		log.Warn().Msg("empty import key")
		http.Error(w, "empty import key", http.StatusBadRequest)
		return
	}

	importData := importCache.Get(importKeyString)
	if importData == nil {
		log.Warn().Str("import_key", importKeyString).Msg("no import data found")
		http.Error(w, "no import data found", http.StatusBadRequest)
		return
	}

	data := importData.Value()

	for i := range data.Users {
		err := fe.database.CreateUser(r.Context(), &data.Users[i])
		if err != nil {
			log.Error().Err(err).Str("username", data.Users[i].Username).Msg("could not create user")
			http.Error(w, "could not create user", http.StatusInternalServerError)
			return
		}
	}

	for _, currRule := range data.Rules {
		fe.analyzer.AddRule(currRule)
	}

	err := fe.analyzer.WriteConfig()
	if err != nil {
		log.Error().Err(err).Msg("could not write updated config file")
		http.Error(w, "could not write config file", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/ftue/restart", http.StatusFound)
}
