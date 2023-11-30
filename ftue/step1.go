package ftue

import (
	"net/http"

	"github.com/gorilla/csrf"

	"github.com/lthummus/auththingie2/render"
)

func (fe *ftueEnv) HandleFTUEStep1(w http.ResponseWriter, r *http.Request) {
	render.Render(w, "ftue_step1.gohtml", &ftueParams{
		CSRFField: csrf.TemplateField(r),
	})
}
