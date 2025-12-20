package config

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

	"github.com/lthummus/auththingie2/internal/render"
)

func RunErrorServer(errorsFound []string) {

	port := viper.GetInt("server.port")
	if port == 0 {
		port = 9000
	}

	errorParams := struct {
		ErrorsFound []string
	}{errorsFound}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		render.Render(w, "config_errors.gohtml", errorParams)
	})
	mux.Handle("/static/", render.StaticFSHandler())

	srv := &http.Server{
		Addr:         fmt.Sprintf("0.0.0.0:%d", port),
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
		IdleTimeout:  15 * time.Second,
		Handler:      mux,
	}

	go func() {
		log.Warn().Int("port", port).Msg("starting error message server")
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Panic().Err(err).Msg("error starting server")
		}
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	<-c

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := srv.Shutdown(ctx)
	if err != nil {
		log.Warn().Err(err).Msg("error shutting down server")
	}
}
