package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/gorilla/csrf"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"

	"github.com/lthummus/auththingie2/ainit"
	"github.com/lthummus/auththingie2/config"
	"github.com/lthummus/auththingie2/db/sqlite"
	"github.com/lthummus/auththingie2/ftue"
	"github.com/lthummus/auththingie2/handlers"
	"github.com/lthummus/auththingie2/middlewares/session"
	"github.com/lthummus/auththingie2/render"
	"github.com/lthummus/auththingie2/rules"
	"github.com/lthummus/auththingie2/salt"
	"github.com/lthummus/auththingie2/util/csrfskip"
)

func RunServer() {
	ainit.InitLogger(true)
	render.Init()

	err := config.Init()
	var fileNotFoundError viper.ConfigFileNotFoundError

	if errors.As(err, &fileNotFoundError) {
		log.Warn().Msg("no config file found; starting FTUE")
		ftue.RunFTUEServer(ftue.StepStartFromBeginning)
		return
	}

	salt.CheckOrMakeSalt()

	configErrors := config.ValidateConfig()
	if configErrors != nil {
		log.Error().Msg("invalid configuration")
		config.RunErrorServer(configErrors)
		os.Exit(1)
	}
	f, err := rules.NewFromConfig()
	if err != nil {
		log.Warn().Err(err).Msg("could not parse rules from config")
	}

	config.Lock.RLock()
	port := viper.GetInt("server.port")
	if port == 0 {
		log.Warn().Msg("no port specified, using port 9000")
		port = 9000
	}
	config.Lock.RUnlock()

	database, err := sqlite.NewSQLiteFromConfig()
	if err != nil {
		log.Fatal().Err(err).Msg("could not initialize database")
	}

	needsSetup, err := database.NeedsSetup(context.Background())
	if err != nil {
		log.Fatal().Err(err).Msg("could not check if setup is needed")
	}
	if needsSetup {
		log.Warn().Msg("no users detected, forwarding to setup")
		ftue.RunFTUEServer(ftue.StepConfigExists)
		return
	}

	muxer := mux.NewRouter()

	wan, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "AuthThingie 2",
		RPID:          viper.GetString("server.domain"),
		RPOrigins:     []string{viper.GetString("server.auth_url")},
	})
	if err != nil {
		log.Fatal().Err(err).Msg("could not initialize webauthn")
	}

	e := handlers.Env{
		Analyzer: f,
		Database: database,
		WebAuthn: wan,
	}
	log.Info().Msg("services initialized")

	log.Info().Msg("setting up listeners")

	skipper := csrfskip.NewSkipper([]string{
		"/forward",
		"/auth",
		"/forbidden",
	})

	muxer.HandleFunc("/forward", e.HandleCheckRequest)
	muxer.HandleFunc("/auth", e.HandleCheckRequest)
	muxer.HandleFunc("/forbidden", e.HandleNotAllowed)

	muxer.HandleFunc("/debug", e.HandleDebug)

	muxer.HandleFunc("/login", e.HandleLoginPage)
	muxer.HandleFunc("/logout", e.HandleLogout)

	muxer.HandleFunc("/", e.HandleIndex).Methods(http.MethodGet)

	muxer.HandleFunc("/totp", e.HandleTOTPValidation)
	muxer.HandleFunc("/enable_totp", e.HandleTOTPSetup)
	muxer.HandleFunc("/disable_totp", e.HandleTOTPDisable)

	muxer.HandleFunc("/admin/users/create", e.HandleCreateUserPage).Methods(http.MethodGet)
	muxer.HandleFunc("/admin/users/create", e.HandleCreateUserPost).Methods(http.MethodPost)
	muxer.HandleFunc("/admin/users/{userId}", e.RenderUserEditPage).Methods(http.MethodGet)
	muxer.HandleFunc("/admin/users/{userId}", e.HandleEditUserSubmission).Methods(http.MethodPost)
	muxer.HandleFunc("/admin/users/{userId}/totp_unenroll", e.HandleAdminUnenrollTOTP).Methods(http.MethodPost)
	muxer.HandleFunc("/admin/users/{userId}/delete", e.HandleUserDelete).Methods(http.MethodPost)
	muxer.HandleFunc("/admin/users/{userId}/tags", e.HandleUserPatchTagsModification).Methods(http.MethodPatch)
	muxer.HandleFunc("/admin/users/{userId}/tags/{tag}", e.HandleUserTagDelete).Methods(http.MethodDelete)
	muxer.HandleFunc("/admin/ruletest", e.HandleTestRule).Methods(http.MethodGet)
	muxer.HandleFunc("/admin", e.HandleAdminPage).Methods(http.MethodGet)

	muxer.HandleFunc("/edit_self", e.HandleSelfConfigGet).Methods(http.MethodGet)
	muxer.HandleFunc("/edit_self/password", e.HandleSelfConfigPasswordGet).Methods(http.MethodGet)
	muxer.HandleFunc("/edit_self/password", e.HandleSelfConfigPasswordPost).Methods(http.MethodPost)

	muxer.HandleFunc("/webauthn/manage", e.HandleRenderWebAuthnManage)
	muxer.HandleFunc("/webauthn/register", e.HandleWebAuthnBeginRegistration)
	muxer.HandleFunc("/webauthn/finishregister", e.HandleWebAuthnFinishRegistration)
	muxer.HandleFunc("/webauthn/discover", e.HandleWebAuthnBeginDiscoverableLogin)
	muxer.HandleFunc("/webauthn/finishdiscover", e.HandleWebAuthnFinishDiscoverableLogin)
	muxer.HandleFunc("/webauthn/keys/{keyId}", e.HandleWebAuthnEditKey)
	muxer.HandleFunc("/webauthn/keys/{keyId}/edit", e.HandleWebAuthnEditKey)

	muxer.PathPrefix("/static/").Handler(render.StaticFSHandler())

	listenEnableDebugPage()
	listenEnableDebugLogging()

	log.Info().Msg("listeners installed")

	log.Info().Int("port", port).Msg("initializing server")

	sessionMiddleware := session.NewMiddleware(muxer, e.Database)

	csrfMiddleware := csrf.Protect(salt.GenerateCSRFKey(),
		csrf.FieldName("csrf_token"),
		csrf.CookieName("auththingie2_csrf"))

	srv := &http.Server{
		Addr:         fmt.Sprintf("0.0.0.0:%d", port),
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
		IdleTimeout:  15 * time.Second,
		Handler:      skipper(csrfMiddleware(sessionMiddleware)),
	}

	log.Info().Int("port", port).Msg("starting server")
	go func() {
		if viper.GetBool("server.tls.enabled") {
			keyFile := viper.GetString("server.tls.key_file")
			certFile := viper.GetString("server.tls.cert_file")
			log.Info().Int("port", port).Str("key_file", keyFile).Str("cert_file", certFile).Msg("starting with tls enabled")
			if err := srv.ListenAndServeTLS(certFile, keyFile); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Panic().Err(err).Msg("error starting server")
			}
		} else {
			log.Info().Int("port", port).Msg("starting plain HTTP server")
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Panic().Err(err).Msg("error starting server")
			}
		}
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	<-c

	log.Warn().Msg("interrupt received")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var wg sync.WaitGroup

	wg.Add(2)
	go func() {
		log.Info().Msg("shutting down server")
		err := srv.Shutdown(ctx)
		if err != nil {
			log.Warn().Err(err).Msg("error shutting down server")
		}
		wg.Done()
	}()
	go func() {
		log.Info().Msg("closing database")
		err := database.Close()
		if err != nil {
			log.Warn().Err(err).Msg("error closing database")
		}
		wg.Done()
	}()
	wg.Wait()
	log.Info().Msg("shutdown complete")

	os.Exit(0)
}
