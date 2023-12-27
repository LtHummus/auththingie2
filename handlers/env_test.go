package handlers

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteJSONError(t *testing.T) {
	t.Run("basic example", func(t *testing.T) {
		w := httptest.NewRecorder()

		writeJSONError(w, "test error message", "1234", http.StatusInternalServerError)

		resp := w.Result()

		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		require.NoError(t, err)

		assert.JSONEq(t, `{"message":"test error message", "error_code":"1234", "failed":true}`, string(body))
	})
}
