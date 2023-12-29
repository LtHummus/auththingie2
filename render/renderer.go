package render

import (
	"embed"
	"encoding/json"
	"html/template"
	"io/fs"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/oxtoacart/bpool"
)

//go:embed templates
var templateFS embed.FS

//go:embed static
var staticFS embed.FS // is there a better way to do this?

const (
	BufferPoolSize = 64
)

var (
	templates map[string]*template.Template

	bufpool *bpool.BufferPool
)

func Init() {
	log.Info().Msg("starting initialization of template system")

	templates = make(map[string]*template.Template)
	bufpool = bpool.NewBufferPool(BufferPoolSize)

	bases, err := fs.Glob(templateFS, "templates/bases/*.gohtml")
	if err != nil {
		log.Fatal().Err(err).Msg("could not load base HTML templates")
	}

	includes, err := fs.Glob(templateFS, "templates/includes/*.gohtml")
	if err != nil {
		log.Fatal().Err(err).Msg("could not load includes HTML templates")
	}

	layouts, err := fs.Glob(templateFS, "templates/*.gohtml")
	if err != nil {
		log.Fatal().Err(err).Msg("could not load layout HTML templates")
	}

	for _, curr := range includes {
		t, err := template.ParseFS(templateFS, curr)
		if err != nil {
			log.Fatal().Err(err).Str("template", curr).Msg("could not parse include template")
		}
		templates[filepath.Base(curr)] = t
	}

	for _, curr := range layouts {
		files := append(bases, includes...)
		files = append(files, curr)
		t, err := template.ParseFS(templateFS, files...)
		if err != nil {
			log.Fatal().Err(err).Str("template", curr).Msg("could not parse template")
		}
		templates[filepath.Base(curr)] = t
	}

	log.Debug().Int("num_templates", len(templates)).Msg("templates loaded")
}

type simpleMessageParams struct {
	DivName string
	Message string
}

func RenderSimpleMessage(w http.ResponseWriter, divName string, message string) {
	Render(w, "simple_message_include.gohtml", &simpleMessageParams{
		DivName: divName,
		Message: message,
	})
}

type errorIncludeParams struct {
	DivName string
	Error   string
}

func RenderError(w http.ResponseWriter, divName string, error string) {
	Render(w, "error_include.gohtml", &errorIncludeParams{
		DivName: divName,
		Error:   error,
	})
}

type fullPageErrorParams struct {
	ErrorTitle  string
	ErrorHeader string
	Error       string
}

func RenderFullPageError(w http.ResponseWriter, title, header, error string) {
	Render(w, "full_page_error.gohtml", &fullPageErrorParams{
		ErrorTitle:  title,
		ErrorHeader: header,
		Error:       error,
	})
}

func RenderHTMXCompatibleError(w http.ResponseWriter, r *http.Request, msg string, idName string) {
	if r.Header.Get("HX-Request") != "true" {
		// not HTMX request, return normal error
		http.Error(w, msg, http.StatusUnprocessableEntity)
		return
	}

	strippedIDName := strings.TrimPrefix(idName, "#")

	w.Header().Set("HX-Retarget", "#"+idName)
	w.Header().Set("HX-Reswap", "outerHTML")

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusUnprocessableEntity)

	params := map[string]string{
		"Message": msg,
		"IdName":  strippedIDName,
	}

	Render(w, "htmx_error.gohtml", params)
}

func Render(w http.ResponseWriter, name string, data any) {
	// TODO: should this render an error to the response writer when we fail?

	templ := templates[name]
	if templ == nil {
		log.Error().Str("name", name).Msg("could not find template")
		return
	}

	buf := bufpool.Get()
	defer bufpool.Put(buf)

	err := templ.Execute(buf, data)
	if err != nil {
		log.Error().Err(err).Str("name", name).Msg("could not render response")
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, err = buf.WriteTo(w)
	if err != nil {
		log.Error().Err(err).Str("name", name).Msg("error writing response to buffer")
	}
}

func RenderJSONError(w http.ResponseWriter, msg string, errorCode string, statusCode int) {
	resp := struct {
		Message   string `json:"message"`
		ErrorCode string `json:"error_code"`
		Failed    bool   `json:"failed"`
	}{
		Message:   msg,
		ErrorCode: errorCode,
		Failed:    true,
	}

	// this can never fail to marshal
	bytes, _ := json.Marshal(resp)

	w.WriteHeader(statusCode)
	_, err := w.Write(bytes)
	if err != nil {
		log.Error().Err(err).Caller(1).Msg("could not write JSON error to response")
	}
}

func StaticFSHandler() http.Handler {
	return http.FileServer(http.FS(staticFS))
}
