package ftue

import (
	"encoding/json"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/jellydator/ttlcache/v3"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"

	"github.com/lthummus/auththingie2/internal/config"
	"github.com/lthummus/auththingie2/internal/db"
	"github.com/lthummus/auththingie2/internal/importer"
	"github.com/lthummus/auththingie2/internal/middlewares/securityheaders"
	"github.com/lthummus/auththingie2/internal/render"
	"github.com/lthummus/auththingie2/internal/rules"
	"github.com/lthummus/auththingie2/internal/user"
)

var importCache *ttlcache.Cache[string, *importer.Results]
var initCache = sync.OnceFunc(func() {
	log.Debug().Msg("initializing import cache")
	importCache = ttlcache.New[string, *importer.Results](ttlcache.WithTTL[string, *importer.Results](72 * time.Hour))
	go importCache.Start()
})

type ftueEnv struct {
	database db.DB
	analyzer rules.Analyzer
}

type ftueParams struct {
	Error string
}

type ftueImportConfirmParams struct {
	Rules     []*rules.DisplayableRule
	Users     []user.User
	ImportKey string
}

func (fe *ftueEnv) buildMux(step Step) http.Handler {
	m := mux.NewRouter()

	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if step == StepConfigExists {
			http.Redirect(w, r, "/ftue/step1", http.StatusFound)
			return
		}

		http.Redirect(w, r, "/ftue/step0", http.StatusFound)
	})

	m.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		requestHost := r.Header.Get("X-Forwarded-Host")
		allowHost := os.Getenv("FTUE_ALLOW_HOST")

		if allowHost == requestHost {
			log.Debug().Str("ftue_allow_host", allowHost).Str("xfh", requestHost).Msg("allowing during FTUE")
			w.WriteHeader(http.StatusNoContent)
		} else {
			log.Debug().Str("ftue_allow_host", allowHost).Str("xfh", requestHost).Msg("blocking during FTUE")
			http.Error(w, "blocked during auththingie2 setup", http.StatusForbidden)
		}
	})

	// TODO: remove CSRF exemption here
	m.HandleFunc("/ftue/path", HandlePathComplete)

	m.HandleFunc("/ftue/step0", fe.HandleFTUEStep0GET).Methods(http.MethodGet)
	m.HandleFunc("/ftue/step0", fe.HandleFTUEStep0POST).Methods(http.MethodPost)

	m.HandleFunc("/ftue/step1", fe.HandleFTUEStep1).Methods(http.MethodGet)

	m.HandleFunc("/ftue/scratch", fe.HandleFTUEScratchRenderPage).Methods(http.MethodGet)
	m.HandleFunc("/ftue/scratch", fe.HandleFTUEScratchRenderPOST).Methods(http.MethodPost)

	m.HandleFunc("/ftue/import", fe.HandleRenderImportPage).Methods(http.MethodGet)
	m.HandleFunc("/ftue/import", fe.HandlerImportPageUpload).Methods(http.MethodPost)
	m.HandleFunc("/ftue/import/confirm", fe.HandleImportConfirm)

	m.HandleFunc("/ftue/restart", HandleRestartPage).Methods(http.MethodGet)
	m.HandleFunc("/ftue/restart", HandleRestartPost).Methods(http.MethodPost)

	m.PathPrefix("/static/").Handler(render.StaticFSHandler())

	cop := http.NewCrossOriginProtection()
	cop.AddInsecureBypassPattern("/ftue/path")

	handler := cop.Handler(m)

	if !viper.GetBool(config.DisableSecurityHeaders) {
		handler = securityheaders.NewSecurityHeadersMiddleware(handler)
	} else {
		log.Warn().Msg("not enabling security headers")
	}

	return handler
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
	_, err = w.Write(respBytes)
	if err != nil {
		log.Error().Caller(0).Err(err).Msg("could not write path completion data to response")
	}
}
