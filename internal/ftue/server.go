package ftue

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"

	"github.com/lthummus/auththingie2/internal/db/sqlite"
	"github.com/lthummus/auththingie2/internal/ftue/session"
	"github.com/lthummus/auththingie2/internal/rules"
)

type Step int

const (
	StepStartFromBeginning Step = iota
	StepConfigExists
)

func RunFTUEServer(step Step) {
	setupCode, err := session.GenerateSetupCode()
	if err != nil {
		log.Fatal().Err(err).Msg("could not generate setup code")
	}

	fe := &ftueEnv{
		setupCode:    setupCode,
		startingStep: step,
		config:       viper.GetViper(),
		protector:    session.NewMiddleware(setupCode),
	}

	if step == StepConfigExists {
		log.Info().Msg("noticed there's a config file; attempting to initialize systems")
		analyzer, err := rules.NewFromConfig(fe.config)
		if err != nil {
			log.Fatal().Err(err).Msg("could not initialize rules engine")
		}
		database, err := sqlite.NewSQLiteFromConfig(fe.config)
		if err != nil {
			log.Fatal().Err(err).Msg("could not initialize database")
		}

		fe.analyzer = analyzer
		fe.database = database
	}

	port := DefaultPort

	h := fe.buildMux(step)

	initCache()

	srv := &http.Server{
		Addr:         fmt.Sprintf("0.0.0.0:%d", port),
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
		IdleTimeout:  15 * time.Second,
		Handler:      h,
	}

	log.Info().Int("port", port).Msg("starting FTUE server")
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Panic().Err(err).Msg("error starting server")
		}
	}()

	log.Info().Str("setup_code", setupCode).Msg("here is the setup code!")

	fmt.Printf("!!!!!!!!!!!!!!!!!!!!!!!!!!\n!!! AUTHTHINGIE2 SETUP !!!\n!!!!!!!!!!!!!!!!!!!!!!!!!!\nGo to the AuthThingie page (whereever it's hosted) and use the code %s for setup\n", setupCode)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	<-c

	log.Warn().Msg("interrupt received")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	log.Info().Msg("shutting own server")
	err = srv.Shutdown(ctx)
	if err != nil {
		log.Warn().Err(err).Msg("error shutting down server")
	}

	log.Info().Msg("shutdown complete")

	os.Exit(0)

}
