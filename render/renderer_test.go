package render

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func getResponseBody(t *testing.T, resp *http.Response) string {
	bodyBytes, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	resp.Body.Close()

	return string(bodyBytes)
}

func TestRender(t *testing.T) {
	Init()

	t.Run("easy case", func(t *testing.T) {
		w := httptest.NewRecorder()

		Render(w, "index.gohtml", map[string]any{
			"User": nil,
		})

		resp := w.Result()
		assert.Equal(t, "text/html; charset=utf-8", resp.Header.Get("Content-Type"))

		body := getResponseBody(t, resp)

		assert.Contains(t, body, `<h1>Welcome to AuthThingie!</h1>`)
		assert.Contains(t, body, `<title>AuthThingie 2</title>`)
		assert.Contains(t, body, `<script src="/static/js/auththingie.js"></script>`)
	})

	t.Run("test simple message", func(t *testing.T) {
		w := httptest.NewRecorder()

		RenderSimpleMessage(w, "test-div", "hello world")

		resp := w.Result()
		body := getResponseBody(t, resp)

		assert.Contains(t, body, `<div id="test-div">`)
		assert.Contains(t, body, `<p class="notice">`)
		assert.Contains(t, body, "hello world")
	})

	t.Run("test render error", func(t *testing.T) {
		w := httptest.NewRecorder()

		RenderError(w, "test-div", "hello world")

		resp := w.Result()
		body := getResponseBody(t, resp)

		assert.Contains(t, body, `<div id="test-div">`)
		assert.Contains(t, body, `<p class="notice">`)
		assert.Contains(t, body, "hello world")
	})

	t.Run("test render full page error", func(t *testing.T) {
		w := httptest.NewRecorder()

		RenderFullPageError(w, "title", "error header", "oh no!")

		resp := w.Result()
		body := getResponseBody(t, resp)

		assert.Contains(t, body, `<article class="grid">`)
		assert.Contains(t, body, `<h1>error header</h1>`)
		assert.Contains(t, body, "oh no!")
	})

	t.Run("test htmx compatible error", func(t *testing.T) {
		t.Run("normal error when not HTMX request", func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			w := httptest.NewRecorder()

			RenderHTMXCompatibleError(w, r, "oh no!", "test-id")

			resp := w.Result()
			body := getResponseBody(t, resp)

			assert.Equal(t, http.StatusUnprocessableEntity, resp.StatusCode)
			assert.Equal(t, "oh no!\n", body)
		})

		t.Run("put proper data in headers when HTMX request", func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			w := httptest.NewRecorder()
			r.Header.Set("HX-Request", "true")

			RenderHTMXCompatibleError(w, r, "oh no!", "test-id")

			resp := w.Result()
			body := getResponseBody(t, resp)

			assert.Equal(t, "#test-id", resp.Header.Get("HX-Retarget"))
			assert.Equal(t, "outerHTML", resp.Header.Get("HX-Reswap"))

			assert.Equal(t, http.StatusUnprocessableEntity, resp.StatusCode)

			assert.Equal(t, `<div id="test-id" class="error-box ">oh no!</div>`, strings.TrimSpace(body))
		})
	})

}

func TestWriteJSONError(t *testing.T) {
	t.Run("basic example", func(t *testing.T) {
		w := httptest.NewRecorder()

		RenderJSONError(w, "test error message", "1234", http.StatusInternalServerError)

		resp := w.Result()

		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		require.NoError(t, err)

		assert.JSONEq(t, `{"message":"test error message", "error_code":"1234", "failed":true}`, string(body))
	})
}
