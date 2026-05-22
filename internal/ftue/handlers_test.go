package ftue

import (
	"testing"

	"github.com/spf13/viper"

	"github.com/lthummus/auththingie2/internal/mocks"
)

func makeTestEnv(t *testing.T) (*mocks.MockDB, *mocks.MockAnalyzer, *viper.Viper, *ftueEnv) {
	mockDB := mocks.NewMockDB(t)
	mockAnalyzer := mocks.NewMockAnalyzer(t)
	v := viper.New()

	e := &ftueEnv{
		database: mockDB,
		analyzer: mockAnalyzer,
		config:   v,
	}

	return mockDB, mockAnalyzer, v, e
}
