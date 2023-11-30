package user

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"

	"github.com/lthummus/auththingie2/argon"
)

var (
	passwordBcrypt []byte
	passwordArgon  string
)

func init() {
	passwordBcrypt, _ = bcrypt.GenerateFromPassword([]byte("password"), 10)
	passwordArgon, _ = argon.GenerateFromPassword("password")
}

func TestUser_CheckPassword(t *testing.T) {
	t.Run("bcrypt", func(t *testing.T) {
		u := User{}

		assert.Equal(t, ErrNoPasswordSet, u.CheckPassword(string([]byte{0x01})))

		u.PasswordHash = string(passwordBcrypt)
		assert.Equal(t, ErrIncorrectPassword, u.CheckPassword("p@ssw0rd"))
		assert.NoError(t, u.CheckPassword("password"))

		u.PasswordHash = string([]byte{0x01, 0x02})
		assert.Equal(t, ErrInvalidHash, u.CheckPassword("password"))
	})

	t.Run("argon", func(t *testing.T) {
		u := User{}
		assert.ErrorIs(t, ErrNoPasswordSet, u.CheckPassword("aaa"))

		u.PasswordHash = passwordArgon
		assert.ErrorIs(t, ErrIncorrectPassword, u.CheckPassword("wrongpw"))
		assert.NoError(t, u.CheckPassword("password"))

		u.PasswordHash = "nope"
		assert.ErrorIs(t, ErrInvalidHash, u.CheckPassword("password"))
	})
}

func TestUser_GroupsOverlap(t *testing.T) {
	u := User{}

	assert.False(t, u.GroupsOverlap([]string{"a", "b"}))

	u.Roles = []string{"a", "b"}
	assert.True(t, u.GroupsOverlap([]string{"a"}))
	assert.True(t, u.GroupsOverlap([]string{"b"}))
	assert.False(t, u.GroupsOverlap([]string{"c"}))
	assert.True(t, u.GroupsOverlap([]string{"a", "b", "c"}))
	assert.True(t, u.GroupsOverlap([]string{"a", "b"}))
}

var throwaway bool

func BenchmarkUser_GroupsOverlap(b *testing.B) {
	u := User{
		Roles: []string{"foo", "bar", "baz", "quox"},
	}

	ruleGroups := []string{"a", "b", "c", "d", "e", "f", "g"}
	b.ResetTimer()
	var r bool
	for n := 0; n < b.N; n++ {
		r = u.GroupsOverlap(ruleGroups)
	}
	throwaway = r
}

func FuzzUser_SetPassword(f *testing.F) {
	f.Add("hello")
	f.Add("world")
	f.Add("123456")
	f.Add(" ")
	f.Fuzz(func(t *testing.T, input string) {
		u := User{}
		err := u.SetPassword(input)
		assert.NoError(t, err)

		assert.NoErrorf(t, u.CheckPassword(input), "failure setting password to %s", input)
	})
}
