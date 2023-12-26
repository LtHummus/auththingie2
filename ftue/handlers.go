package ftue

import (
	"encoding/json"
	"html/template"
	"net/http"
	"sync"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/rs/zerolog/log"

	"github.com/lthummus/auththingie2/db"
	"github.com/lthummus/auththingie2/importer"
	"github.com/lthummus/auththingie2/rules"
	"github.com/lthummus/auththingie2/user"
)

var importCache *ttlcache.Cache[string, *importer.Results]
var initCache = sync.OnceFunc(func() {
	importCache = ttlcache.New[string, *importer.Results](ttlcache.WithTTL[string, *importer.Results](24 * time.Hour))
})

type ftueEnv struct {
	database db.DB
	analyzer rules.Analyzer
}

type ftueParams struct {
	CSRFField template.HTML
	Error     string
}

type ftueImportConfirmParams struct {
	Rules     []*rules.DisplayableRule
	Users     []user.User
	ImportKey string
	CSRFField template.HTML
}

func HandlePathComplete(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Path string `json:"path"`
	}
	defer r.Body.Close()
	err := json.NewDecoder(r.Body).Decode(&input)
	if err != nil {
		log.Error().Err(err).Msg("could not decode path input")
		http.Error(w, "could not decode path input", http.StatusBadRequest)
		return
	}

	paths := make([]string, 0)
	if input.Path != "" {
		paths = PathAutoComplete(input.Path)
	}
	respBytes, err := json.Marshal(paths)
	if err != nil {
		log.Error().Err(err).Msg("could not serialize paths back")
		http.Error(w, "could not serialize response", http.StatusInternalServerError)
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(respBytes)
}
