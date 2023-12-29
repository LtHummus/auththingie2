package rules

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

const sampleRules = `
rules:
    - name: foo role
      host_pattern: a.example.com
      permitted_roles:
        - aaa
        - bbb
      public: false
    - name: /css* on test.example.com
      host_pattern: test.example.com
      path_pattern: /css*
      public: true
    - name: /js* on test.example.com
      host_pattern: test.example.com
      path_pattern: /js*
      public: true
    - name: /animals* on test.example.com
      host_pattern: test.example.com
      path_pattern: /animals*
      public: false
    - name: /colors* on test.example.com
      host_pattern: test.example.coma
      path_pattern: /colors*
      public: false
      permitted_roles:
          - ddd
    - name: test.example.com root
      host_pattern: test.example.com
      path_pattern: /
      public: true
`

func TestViperConfigAnalyzer_UpdateFromConfigFile(t *testing.T) {
	t.Run("happy case", func(t *testing.T) {
		t.Cleanup(func() {
			viper.Reset()
		})

		viper.SetConfigType("yaml")
		_ = viper.ReadConfig(strings.NewReader(sampleRules))

		a := ViperConfigAnalyzer{}
		assert.Empty(t, a.rules)

		err := a.UpdateFromConfigFile()
		assert.NoError(t, err)

		assert.Len(t, a.rules, 6)

		assert.Equal(t, "foo role", a.rules[0].Name)

		assert.ElementsMatch(t, []string{"aaa", "bbb", "ddd"}, a.knownRoles)
		assert.WithinDuration(t, time.Now(), a.lastUpdate, 1*time.Second)
		assert.Empty(t, a.errors)
	})

	t.Run("rules contain errors", func(t *testing.T) {
		t.Cleanup(func() {
			viper.Reset()
		})

		viper.SetConfigType("yaml")
		badRules := `
rules:
    - name: bad
      source_address: abcdefg
`

		viper.SetConfigType("yaml")
		_ = viper.ReadConfig(strings.NewReader(badRules))

		a := ViperConfigAnalyzer{}
		err := a.UpdateFromConfigFile()
		assert.Error(t, err)

		assert.Len(t, a.errors, 1)
	})
}

func TestViperConfigAnalyzer_MatchesRule(t *testing.T) {
	t.Run("base case", func(t *testing.T) {
		t.Cleanup(func() {
			viper.Reset()
		})

		viper.SetConfigType("yaml")
		_ = viper.ReadConfig(strings.NewReader(sampleRules))

		a := ViperConfigAnalyzer{}
		assert.Empty(t, a.rules)

		err := a.UpdateFromConfigFile()
		assert.NoError(t, err)

		r := a.MatchesRule(&RequestInfo{
			Method:     "GET",
			Protocol:   "http",
			Host:       "test.example.com",
			RequestURI: "/css/test.css",
			SourceIP:   net.ParseIP("10.0.0.1"),
		})

		assert.NotNil(t, r)
		assert.Equal(t, "/css* on test.example.com", r.Name)
	})

	t.Run("no rule matched", func(t *testing.T) {
		t.Cleanup(func() {
			viper.Reset()
		})

		viper.SetConfigType("yaml")
		_ = viper.ReadConfig(strings.NewReader(sampleRules))

		a := ViperConfigAnalyzer{}
		assert.Empty(t, a.rules)

		r := a.MatchesRule(&RequestInfo{
			Method:     "GET",
			Protocol:   "http",
			Host:       "aaaaa.example.com",
			RequestURI: "/css/test.css",
			SourceIP:   net.ParseIP("10.0.0.1"),
		})
		assert.Nil(t, r)
	})
}
