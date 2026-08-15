package ftue

import (
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"

	"github.com/lthummus/auththingie2/internal/config"
	"github.com/lthummus/auththingie2/internal/db"
	"github.com/lthummus/auththingie2/internal/ftue/session"
	"github.com/lthummus/auththingie2/internal/importer"
	"github.com/lthummus/auththingie2/internal/middlewares/maxbytes"
	"github.com/lthummus/auththingie2/internal/middlewares/securityheaders"
	"github.com/lthummus/auththingie2/internal/render"
	"github.com/lthummus/auththingie2/internal/rules"
	"github.com/lthummus/auththingie2/internal/user"
)

const (
	MaxBodySize = 10 * 1024 * 1024 // 10 MB
)

var importCache *ttlcache.Cache[string, *importer.Results]
var initCache = sync.OnceFunc(func() {
	log.Debug().Msg("initializing import cache")
	importCache = ttlcache.New[string, *importer.Results](ttlcache.WithTTL[string, *importer.Results](72 * time.Hour))
	go importCache.Start()
})

type ftueEnv struct {
	setupCode    string
	startingStep Step
	protector    *session.Middleware

	database db.DB
	analyzer rules.Analyzer
	config   *viper.Viper
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
	mux := http.NewServeMux()

	mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		requestHost := r.Header.Get("X-Forwarded-Host")
		allowHost := os.Getenv("FTUE_ALLOW_HOST")

		if allowHost == "" {
			http.Error(w, "environment varibale FTUE_ALLOW_HOST must be set to your host to set things up behind the proxy", http.StatusForbidden)
			return
		}

		if allowHost == requestHost {
			log.Debug().Str("ftue_allow_host", allowHost).Str("xfh", requestHost).Msg("allowing during FTUE")
			w.WriteHeader(http.StatusNoContent)
		} else {
			log.Debug().Str("ftue_allow_host", allowHost).Str("xfh", requestHost).Msg("blocking during FTUE")
			http.Error(w, "blocked during auththingie2 setup", http.StatusForbidden)
		}
	})

	mux.Handle("/static/", render.StaticFSHandler())

	mux.HandleFunc("GET /{$}", fe.HandleSetupCodeGET)
	mux.HandleFunc("POST /{$}", fe.HandleSetupCodePOST)

	mux.Handle("GET /begin", fe.protector.ProtectFunc(func(w http.ResponseWriter, r *http.Request) {
		if step == StepConfigExists {
			http.Redirect(w, r, "/ftue/step1", http.StatusFound)
			return
		}
		http.Redirect(w, r, "/ftue/step0", http.StatusFound)
	}))

	mux.Handle("GET /ftue/step0", fe.protector.ProtectFunc(fe.HandleFTUEStep0GET))
	mux.Handle("POST /ftue/step0", fe.protector.ProtectFunc(fe.HandleFTUEStep0POST))

	mux.Handle("GET /ftue/step1", fe.protector.ProtectFunc(fe.HandleFTUEStep1))

	mux.Handle("GET /ftue/scratch", fe.protector.ProtectFunc(fe.HandleFTUEScratchRenderPage))
	mux.Handle("POST /ftue/scratch", fe.protector.ProtectFunc(fe.HandleFTUEScratchRenderPOST))

	mux.Handle("GET /ftue/import", fe.protector.ProtectFunc(fe.HandleRenderImportPage))
	mux.Handle("POST /ftue/import", fe.protector.ProtectFunc(fe.HandlerImportPageUpload))
	mux.Handle("POST /ftue/import/confirm", fe.protector.ProtectFunc(fe.HandleImportConfirm))

	mux.Handle("GET /ftue/restart", fe.protector.ProtectFunc(HandleRestartPage))
	mux.Handle("POST /ftue/restart", fe.protector.ProtectFunc(HandleRestartPost))

	cop := http.NewCrossOriginProtection()
	cop.AddInsecureBypassPattern("/auth")

	handler := cop.Handler(mux)

	if !fe.config.GetBool(config.ConfigKeyDisableSecurityHeaders) {
		handler = securityheaders.NewSecurityHeadersMiddleware(handler)
	} else {
		log.Warn().Msg("not enabling security headers")
	}

	handler = maxbytes.NewMaxBytesMiddleware(handler, MaxBodySize)

	return handler
}
