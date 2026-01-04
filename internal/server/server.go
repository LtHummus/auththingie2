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
	"github.com/lthummus/auththingie2/internal/ftue"
	"github.com/lthummus/auththingie2/internal/handlers"
	"github.com/lthummus/auththingie2/internal/loginlimit"
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
	trueip.Initialize(context.Background())

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

	wan, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "AuthThingie 2",
		RPID:          viper.GetString("server.domain"),
		RPOrigins:     []string{viper.GetString("server.auth_url")},
	})
	if err != nil {
		log.Fatal().Err(err).Msg("could not initialize webauthn")
	}

	e := handlers.Env{
		Analyzer:     f,
		Database:     database,
		WebAuthn:     wan,
		LoginLimiter: loginlimit.NewInMemoryLimiter(),
	}
	log.Info().Msg("services initialized")

	listenEnableDebugPage()
	listenEnableDebugLogging()

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
