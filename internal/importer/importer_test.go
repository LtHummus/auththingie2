package importer

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBasic(t *testing.T) {
	t.Run("simple config", func(t *testing.T) {
		input := `auththingie {
domain: "example.com"
authSiteUrl: "https://auth.example.com"

users: [
    {
      htpasswdLine: "ben:$2y$05$WvtSdzLmwYqZqUe/EdLt1uG250dUmHAdQ4nKEDP.J5KRM2u3JbTCS"
      admin: true
      roles: []
    },
    {
      htpasswdLine: "dog:$2y$05$/WME1Gi5RRG/or8To0BjQewJ6lg0z/IyaRjLyhW8yx0ygVwMoJjGO"
      admin: false
      totpSecret: "T2LMGZPFG4ANKCXKNPGETW7MOTVGPCLH"
      roles: ["animal_role", "foo_role"]
    }
]

rules: [
   {
      "name": "Keys",
      "hostPattern": "keys.example.com",
      "pathPattern": "*",
      "permittedRoles": [],
      "public": true
    },
    {
      "name": "Play Test",
      "hostPattern": "guess.example.com",
      "pathPattern": "*",
      "permittedRoles": ["a", "b"],
      "public": false
    }]
}`

		c, err := Import(input)
		assert.NoError(t, err)

		assert.Equal(t, "example.com", c.Domain)
		assert.Equal(t, "https://auth.example.com", c.AuthURL)

		assert.Len(t, c.Rules, 2)

		assert.Equal(t, "Keys", c.Rules[0].Name)
		assert.Nil(t, c.Rules[0].ProtocolPattern)
		assert.Equal(t, "keys.example.com", *c.Rules[0].HostPattern)
		assert.Equal(t, "*", *c.Rules[0].PathPattern)
		assert.Empty(t, c.Rules[0].PermittedRoles)
		assert.True(t, c.Rules[0].Public)

		assert.Equal(t, "Play Test", c.Rules[1].Name)
		assert.Nil(t, c.Rules[1].ProtocolPattern)
		assert.Equal(t, "guess.example.com", *c.Rules[1].HostPattern)
		assert.Equal(t, "*", *c.Rules[1].PathPattern)
		assert.Equal(t, []string{"a", "b"}, c.Rules[1].PermittedRoles)
		assert.False(t, c.Rules[1].Public)

		assert.Len(t, c.Users, 2)

		assert.NotEmpty(t, c.Users[0].Id)
		assert.Equal(t, "ben", c.Users[0].Username)
		assert.Equal(t, "$2y$05$WvtSdzLmwYqZqUe/EdLt1uG250dUmHAdQ4nKEDP.J5KRM2u3JbTCS", string(c.Users[0].PasswordHash))
		assert.True(t, c.Users[0].Admin)
		assert.Nil(t, c.Users[0].TOTPSeed)

		assert.NotEmpty(t, c.Users[1].Id)
		assert.Equal(t, "dog", c.Users[1].Username)
		assert.Equal(t, "$2y$05$/WME1Gi5RRG/or8To0BjQewJ6lg0z/IyaRjLyhW8yx0ygVwMoJjGO", string(c.Users[1].PasswordHash))
		assert.False(t, c.Users[1].Admin)
		assert.Equal(t, "T2LMGZPFG4ANKCXKNPGETW7MOTVGPCLH", *c.Users[1].TOTPSeed)
		assert.Equal(t, []string{"animal_role", "foo_role"}, c.Users[1].Roles)
	})
}
