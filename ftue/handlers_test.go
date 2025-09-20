package ftue

import (
	"net/http"
	"testing"

	"github.com/gorilla/csrf"

	"github.com/lthummus/auththingie2/mocks"
)

func makeTestEnv(t *testing.T) (*mocks.MockDB, *mocks.MockAnalyzer, *ftueEnv) {
	mockDB := mocks.NewMockDB(t)
	mockAnalyzer := mocks.NewMockAnalyzer(t)

	e := &ftueEnv{
		database: mockDB,
		analyzer: mockAnalyzer,
	}

	return mockDB, mockAnalyzer, e
}

func bypassCSRF(r *http.Request) *http.Request {
	return csrf.UnsafeSkipCheck(r)
}
