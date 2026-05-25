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

	"github.com/lthummus/auththingie2/internal/config"
	"github.com/lthummus/auththingie2/internal/db/sqlite"
	"github.com/lthummus/auththingie2/internal/debugsignals"
	"github.com/lthummus/auththingie2/internal/ftue"
	"github.com/lthummus/auththingie2/internal/handlers"
	"github.com/lthummus/auththingie2/internal/loginlimit"
	"github.com/lthummus/auththingie2/internal/pwvalidate"
	"github.com/lthummus/auththingie2/internal/redirects"
	"github.com/lthummus/auththingie2/internal/render"
	"github.com/lthummus/auththingie2/internal/rules"
	"github.com/lthummus/auththingie2/internal/salt"
	"github.com/lthummus/auththingie2/internal/trueip"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

func RunServer() {
	render.Init()

	// TODO: rethink this so potentially a configuration can be passed in to this. Maybe this check should be done
	//       at a layer above this so the server doesn't have to be responsible for determining to run the first
	//       time setup? Might make this more testable, which is a bonus
	err := config.Init()
	if _, ok := errors.AsType[viper.ConfigFileNotFoundError](err); ok {
		log.Warn().Msg("no config file found; starting FTUE")
		ftue.RunFTUEServer(ftue.StepStartFromBeginning)
		return
	}

	cfg := viper.GetViper()

	salt.CheckOrMakeSalt()

	configErrors := config.ValidateConfig()
	if configErrors != nil {
		log.Error().Msg("invalid configuration")
		config.RunErrorServer(configErrors)
		os.Exit(1)
	}
	ruriv, err := redirects.NewFromConfig(cfg)
	if err != nil {
		log.Warn().Err(err).Msg("could not initialize redirect uri handler")
		config.RunErrorServer([]string{err.Error()})
		os.Exit(1)
	}

	f, err := rules.NewFromConfig(cfg)
	if err != nil {
		log.Warn().Err(err).Msg("could not parse rules from config")
	}
	err = trueip.Initialize(context.Background(), cfg)
	if err != nil {
		log.Error().Err(err).Msg("invalid trusted proxy configuration")
		config.RunErrorServer([]string{err.Error()})
		os.Exit(1)
	}

	config.Lock.RLock()
	port := cfg.GetInt(config.ConfigKeyServerPort)
	if port == 0 {
		log.Warn().Msg("no port specified, using port 9000")
		port = 9000
	}
	config.Lock.RUnlock()

	database, err := sqlite.NewSQLiteFromConfig(cfg)
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

	wan, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "AuthThingie 2",
		RPID:          cfg.GetString(config.ConfigKeyServerDomain),
		RPOrigins:     []string{cfg.GetString(config.ConfigKeyServerAuthURL)},
	})
	if err != nil {
		log.Fatal().Err(err).Msg("could not initialize webauthn")
	}

	ll := loginlimit.NewInMemoryLimiter(cfg)
	pwv := pwvalidate.NewValidator(database, ll, cfg)

	e := handlers.Env{
		Analyzer:             f,
		Database:             database,
		WebAuthn:             wan,
		LoginLimiter:         ll,
		PasswordValidator:    pwv,
		RedirectURLValidator: ruriv,
		Configuration:        cfg,
	}
	log.Info().Msg("services initialized")

	debugPageStopListener := make(chan struct{})
	debugListenerEnabled := debugsignals.ListenEnableDebugPage(debugPageStopListener)
	if !debugListenerEnabled {
		close(debugPageStopListener)
	}

	debugLogStopListener := make(chan struct{})
	debugLogListenerEnabled := debugsignals.ListenEnableDebugLogging(debugLogStopListener)
	if !debugLogListenerEnabled {
		close(debugLogStopListener)
	}

	log.Info().Msg("listeners installed")

	log.Info().Int("port", port).Msg("initializing server")

	srv := &http.Server{
		Addr:         fmt.Sprintf("0.0.0.0:%d", port),
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
		IdleTimeout:  15 * time.Second,
		Handler:      e.BuildRouter(),
	}

	log.Info().Int("port", port).Msg("starting server")
	go func() {
		if cfg.GetBool(config.ConfigKeyServerTLSEnabled) {
			keyFile := cfg.GetString(config.ConfigKeyServerTLSKeyFile)
			certFile := cfg.GetString(config.ConfigKeyServerTLSCertFile)
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

	if debugLogListenerEnabled {
		close(debugLogStopListener)
	}

	if debugListenerEnabled {
		close(debugPageStopListener)
	}

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
