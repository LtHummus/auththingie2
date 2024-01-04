package ftue

import (
	"testing"

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
