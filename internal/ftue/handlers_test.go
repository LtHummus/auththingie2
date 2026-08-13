package ftue

import (
	"net/http"
	"testing"

	"github.com/spf13/viper"

	"github.com/lthummus/auththingie2/internal/argon"
	"github.com/lthummus/auththingie2/internal/ftue/session"
	"github.com/lthummus/auththingie2/internal/mocks"
)

const testSetupCode = "TESTSETUPCODE"

func buildFTUEAuthCookie(fe *ftueEnv) *http.Cookie {
	encoded, err := fe.protector.EncodeValidCookie(fe.setupCode)
	if err != nil {
		panic(err)
	}

	return &http.Cookie{
		Name:  session.FTUESessionCookieName,
		Value: encoded,
	}
}

func attachSetupAuthCookie(r *http.Request, fe *ftueEnv) {
	r.AddCookie(buildFTUEAuthCookie(fe))
}

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
		database:  mockDB,
		analyzer:  mockAnalyzer,
		config:    v,
		setupCode: testSetupCode,
		protector: session.NewMiddleware(testSetupCode),
	}

	return mockDB, mockAnalyzer, v, e
}
