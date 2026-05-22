package ftue

import (
	"testing"

	"github.com/spf13/viper"

	"github.com/lthummus/auththingie2/internal/argon"
	"github.com/lthummus/auththingie2/internal/mocks"
)

func makeTestEnv(t *testing.T) (*mocks.MockDB, *mocks.MockAnalyzer, *viper.Viper, *ftueEnv) {
	mockDB := mocks.NewMockDB(t)
	mockAnalyzer := mocks.NewMockAnalyzer(t)
	v := viper.New()
	v.SetDefault(argon.MemoryKey, argon.DefaultMemory)
	v.SetDefault(argon.IterationKey, argon.DefaultIterations)
	v.SetDefault(argon.ParallelismKey, argon.DefaultParallelism)
	v.SetDefault(argon.SaltLengthKey, argon.DefaultSaltLength)
	v.SetDefault(argon.KeyLengthKey, argon.DefaultKeyLength)

	e := &ftueEnv{
		database: mockDB,
		analyzer: mockAnalyzer,
		config:   v,
	}

	return mockDB, mockAnalyzer, v, e
}
