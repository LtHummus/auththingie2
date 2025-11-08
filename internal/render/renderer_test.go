package render

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRender(t *testing.T) {
	Init()

	t.Run("easy case", func(t *testing.T) {
		w := httptest.NewRecorder()

		Render(w, "index.gohtml", map[string]any{
			"User": nil,
		})

		resp := w.Result()
		assert.Equal(t, "text/html; charset=utf-8", resp.Header.Get("Content-Type"))

		assert.Contains(t, w.Body.String(), `<h1>Welcome to AuthThingie!</h1>`)
		assert.Contains(t, w.Body.String(), `<title>AuthThingie 2</title>`)
		assert.Contains(t, w.Body.String(), `<script src="/static/js/auththingie.js"></script>`)
	})

	t.Run("test simple message", func(t *testing.T) {
		w := httptest.NewRecorder()

		RenderSimpleMessage(w, "test-div", "hello world")

		assert.Contains(t, w.Body.String(), `<div id="test-div">`)
		assert.Contains(t, w.Body.String(), `<p class="notice">`)
		assert.Contains(t, w.Body.String(), "hello world")
	})

	t.Run("test render error", func(t *testing.T) {
		w := httptest.NewRecorder()

		RenderError(w, "test-div", "hello world")

		assert.Contains(t, w.Body.String(), `<div id="test-div">`)
		assert.Contains(t, w.Body.String(), `<p class="notice">`)
		assert.Contains(t, w.Body.String(), "hello world")
	})

	t.Run("test render full page error", func(t *testing.T) {
		w := httptest.NewRecorder()

		RenderFullPageError(w, "title", "error header", "oh no!")

		assert.Contains(t, w.Body.String(), `<article class="grid">`)
		assert.Contains(t, w.Body.String(), `<h1>error header</h1>`)
		assert.Contains(t, w.Body.String(), "oh no!")
	})

	t.Run("test htmx compatible error", func(t *testing.T) {
		t.Run("normal error when not HTMX request", func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			w := httptest.NewRecorder()

			RenderHTMXCompatibleError(w, r, "oh no!", "test-id")

			resp := w.Result()

			assert.Equal(t, http.StatusUnprocessableEntity, resp.StatusCode)
			assert.Equal(t, "oh no!\n", w.Body.String())
		})

		t.Run("put proper data in headers when HTMX request", func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			w := httptest.NewRecorder()
			r.Header.Set("HX-Request", "true")

			RenderHTMXCompatibleError(w, r, "oh no!", "test-id")

			resp := w.Result()

			assert.Equal(t, "#test-id", resp.Header.Get("HX-Retarget"))
			assert.Equal(t, "outerHTML", resp.Header.Get("HX-Reswap"))

			assert.Equal(t, http.StatusUnprocessableEntity, resp.StatusCode)

			assert.Equal(t, `<div id="test-id" class="error-box ">oh no!</div>`, strings.TrimSpace(w.Body.String()))
		})
	})

}

func TestWriteJSONError(t *testing.T) {
	t.Run("basic example", func(t *testing.T) {
		w := httptest.NewRecorder()

		RenderJSONError(w, "test error message", "1234", http.StatusInternalServerError)

		resp := w.Result()

		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)

		assert.JSONEq(t, `{"message":"test error message", "error_code":"1234", "failed":true}`, w.Body.String())
	})
}
