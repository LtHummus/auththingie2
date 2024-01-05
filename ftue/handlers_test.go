package ftue

import (
	"net/http"
	"testing"

	"github.com/gorilla/csrf"

	"github.com/lthummus/auththingie2/mocks"
)

func makeTestEnv(t *testing.T) (*mocks.DB, *mocks.Analyzer, *ftueEnv) {
	mockDB := mocks.NewDB(t)
	mockAnalyzer := mocks.NewAnalyzer(t)

	e := &ftueEnv{
		database: mockDB,
		analyzer: mockAnalyzer,
	}

	return mockDB, mockAnalyzer, e
}

func bypassCSRF(r *http.Request) *http.Request {
	return csrf.UnsafeSkipCheck(r)
}
