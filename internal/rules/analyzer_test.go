package rules

import (
	"bytes"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
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
    - name: any JS
      host_pattern: js.example.com
      path_pattern: '*.js'
      public: true

`

func TestViperConfigAnalyzer_UpdateFromConfigFile(t *testing.T) {
	t.Run("happy case", func(t *testing.T) {
		v := viper.New()
		v.SetConfigType("yaml")
		err := v.ReadConfig(strings.NewReader(sampleRules))
		require.NoError(t, err)

		a := ViperConfigAnalyzer{
			cfg: v,
		}
		assert.Empty(t, a.rules)

		err = a.UpdateFromConfigFile()
		require.NoError(t, err)

		assert.Len(t, a.rules, 7)

		assert.Equal(t, "foo role", a.rules[0].Name)

		assert.ElementsMatch(t, []string{"aaa", "bbb", "ddd"}, a.knownRoles)
		assert.WithinDuration(t, time.Now(), a.lastUpdate, 1*time.Second)
		assert.Empty(t, a.errors)
	})

	t.Run("rules contain errors", func(t *testing.T) {
		v := viper.New()

		badRules := `
rules:
    - name: bad
      source_address: abcdefg
`

		v.SetConfigType("yaml")
		_ = v.ReadConfig(strings.NewReader(badRules))

		a := ViperConfigAnalyzer{
			cfg: v,
		}
		err := a.UpdateFromConfigFile()
		assert.Error(t, err)

		assert.Len(t, a.errors, 1)
	})
}

func TestViperConfigAnalyzer_MatchesRule(t *testing.T) {
	t.Run("base case", func(t *testing.T) {
		v := viper.New()

		v.SetConfigType("yaml")
		err := v.ReadConfig(strings.NewReader(sampleRules))
		require.NoError(t, err)

		a := ViperConfigAnalyzer{
			cfg: v,
		}
		assert.Empty(t, a.rules)

		err = a.UpdateFromConfigFile()
		require.NoError(t, err)

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
		v := viper.New()

		v.SetConfigType("yaml")
		_ = v.ReadConfig(strings.NewReader(sampleRules))

		a := ViperConfigAnalyzer{
			cfg: v,
		}
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

	t.Run("do not match on query strings", func(t *testing.T) {
		v := viper.New()

		v.SetConfigType("yaml")
		_ = v.ReadConfig(strings.NewReader(sampleRules))

		a := ViperConfigAnalyzer{
			cfg: v,
		}
		assert.Empty(t, a.rules)

		err := a.UpdateFromConfigFile()
		require.NoError(t, err)

		r := a.MatchesRule(&RequestInfo{
			Method:     "GET",
			Protocol:   "http",
			Host:       "js.example.com",
			RequestURI: "/js/test.js",
			SourceIP:   net.ParseIP("10.0.0.1"),
		})
		assert.NotNil(t, r)

		r = a.MatchesRule(&RequestInfo{
			Method:      "GET",
			Protocol:    "http",
			Host:        "js.example.com",
			RequestURI:  "/admin/admin.html",
			QueryString: "foo=something.js",
			SourceIP:    net.ParseIP("10.0.0.1"),
		})
		assert.Nil(t, r)
	})
}

func TestRuleRoundTrip(t *testing.T) {
	_, sourceCIDR, err := net.ParseCIDR("10.0.0.0/8")
	require.NoError(t, err)
	r := &Rule{
		Name:            "Some Test Rule",
		SourceAddress:   sourceCIDR,
		ProtocolPattern: new("https"),
		HostPattern:     new("test.example.com"),
		PathPattern:     new("/public/*"),
		Timeout:         new(10 * time.Minute),
		Public:          false,
		PermittedRoles:  []string{"a", "b"},
	}

	parts := ruleConverter(r.toSerializableMap())

	marshalledRule, err := yaml.Marshal(parts)
	require.NoError(t, err)

	v := viper.New()
	v.SetConfigType("yaml")
	err = v.ReadConfig(bytes.NewReader(marshalledRule))
	require.NoError(t, err)

	roundTrippedRule, err := New(v)
	require.NoError(t, err)

	assert.Equal(t, r.Name, roundTrippedRule.Name)
	assert.Equal(t, r.SourceAddress, roundTrippedRule.SourceAddress)
	assert.Equal(t, r.ProtocolPattern, roundTrippedRule.ProtocolPattern)
	assert.Equal(t, r.HostPattern, roundTrippedRule.HostPattern)
	assert.Equal(t, r.PathPattern, roundTrippedRule.PathPattern)
	assert.Equal(t, r.Timeout, roundTrippedRule.Timeout)
	assert.Equal(t, r.Public, roundTrippedRule.Public)
	assert.Equal(t, r.PermittedRoles, roundTrippedRule.PermittedRoles)
}
