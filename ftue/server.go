package ftue

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/gorilla/handlers"
	"github.com/rs/zerolog/log"

	"github.com/lthummus/auththingie2/db/sqlite"
	"github.com/lthummus/auththingie2/rules"
)

type Step int

const (
	StepStartFromBeginning Step = iota
	StepConfigExists
)

func RunFTUEServer(step Step) {

	fe := &ftueEnv{}
	
	if step == StepConfigExists {
		log.Info().Msg("noticed there's a config file; attempting to initialize systems")
		analyzer, err := rules.NewFromConfig()
		if err != nil {
			log.Fatal().Err(err).Msg("could not initialize rules engine")
		}
		database, err := sqlite.NewSQLiteFromConfig()
		if err != nil {
			log.Fatal().Err(err).Msg("could not initialize database")
		}

		fe.analyzer = analyzer
		fe.database = database
	}

	port := DefaultPort

	h := fe.buildMux(step)

	if os.Getenv("FTUE_REQUEST_LOGGER") == "true" {
		log.Warn().Msg("initializing request logging")
		h = handlers.LoggingHandler(os.Stdout, h)
	}

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

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	<-c

	log.Warn().Msg("interrupt received")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	log.Info().Msg("shutting own server")
	err := srv.Shutdown(ctx)
	if err != nil {
		log.Warn().Err(err).Msg("error shutting down server")
	}

	log.Info().Msg("shutdown complete")

	os.Exit(0)

}
