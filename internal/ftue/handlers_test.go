package ftue

import (
	"testing"

	"github.com/lthummus/auththingie2/internal/mocks"
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
