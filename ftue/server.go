package ftue

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/gorilla/csrf"
	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
	"github.com/rs/zerolog/log"

	"github.com/lthummus/auththingie2/db/sqlite"
	"github.com/lthummus/auththingie2/render"
	"github.com/lthummus/auththingie2/rules"
	"github.com/lthummus/auththingie2/util/csrfskip"
)

type Step int

const (
	StepStartFromBeginning Step = iota
	StepConfigExists
)

func RunFTUEServer(step Step) {

	m := mux.NewRouter()

	csrfMiddleware := csrf.Protect(securecookie.GenerateRandomKey(32),
		csrf.FieldName("csrf_token"),
		csrf.CookieName("auththingie2_ftue_csrf"),
	)

	skip := csrfskip.NewSkipper([]string{"/ftue/path"})

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

	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if step == StepConfigExists {
			http.Redirect(w, r, "/ftue/step1", http.StatusFound)
			return
		}

		http.Redirect(w, r, "/ftue/step0", http.StatusFound)
	})

	// TODO: remove CSRF exemption here
	m.HandleFunc("/ftue/path", HandlePathComplete)

	m.HandleFunc("/ftue/step0", fe.HandleFTUEStep0GET).Methods(http.MethodGet)
	m.HandleFunc("/ftue/step0", fe.HandleFTUEStep0POST).Methods(http.MethodPost)

	m.HandleFunc("/ftue/step1", fe.HandleFTUEStep1).Methods(http.MethodGet)

	m.HandleFunc("/ftue/scratch", fe.HandleFTUEScratch)

	m.HandleFunc("/ftue/import", fe.HandleImport)
	m.HandleFunc("/ftue/import/confirm", fe.HandleImportConfirm)

	m.HandleFunc("/ftue/restart", HandleRestartPage).Methods(http.MethodGet)
	m.HandleFunc("/ftue/restart", HandleRestartPost).Methods(http.MethodPost)
	
	m.PathPrefix("/static/").Handler(render.StaticFSHandler())

	port := DefaultPort

	srv := &http.Server{
		Addr:         fmt.Sprintf("0.0.0.0:%d", port),
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
		IdleTimeout:  15 * time.Second,
		Handler:      skip(csrfMiddleware(m)),
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
