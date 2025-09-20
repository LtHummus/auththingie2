package ftue

import (
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/lthummus/auththingie2/config"
	"github.com/lthummus/auththingie2/render"
	"github.com/lthummus/auththingie2/restarter"
)

type restartParams struct {
	IsDocker    bool
	ShowRestart bool
}

func HandleRestartPage(w http.ResponseWriter, r *http.Request) {
	render.Render(w, "ftue_restart.gohtml", &restartParams{
		ShowRestart: !config.IsDocker() && runtime.GOOS != "windows",
		IsDocker:    config.IsDocker(),
	})
}

func HandleRestartPost(w http.ResponseWriter, r *http.Request) {
	if r.FormValue("restart-button") != "" {
		log.Debug().Msg("restart button pressed")
		render.Render(w, "restarting_screen.gohtml", nil)
		go func() {
			time.Sleep(1 * time.Second)
			restarter.Restart()
		}()
	} else if r.FormValue("shutdown-button") != "" {
		log.Debug().Msg("shutdown button pressed")
		render.Render(w, "ftue_shutdown_screen.gohtml", nil)
		go func() {
			time.Sleep(1 * time.Second)
			os.Exit(0)
		}()
	} else {
		log.Debug().Msg("neither shutdown or restart pressed")
		render.Render(w, "ftue_restart.gohtml", &restartParams{
			IsDocker:    config.IsDocker(),
			ShowRestart: !config.IsDocker() && runtime.GOOS != "windows",
		})
		return
	}
}
