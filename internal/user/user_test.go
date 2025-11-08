package user

import (
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/lthummus/auththingie2/internal/argon"
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

func TestUser_HasRole(t *testing.T) {
	u := User{Roles: []string{"a", "b", "c"}}

	assert.True(t, u.HasRole("a"))
	assert.True(t, u.HasRole("b"))
	assert.True(t, u.HasRole("c"))
	assert.False(t, u.HasRole("d"))
	assert.False(t, u.HasRole("e"))
}

func TestUser_CheckTOTP(t *testing.T) {
	totpSecret, err := totp.Generate(totp.GenerateOpts{
		AccountName: "test",
		Issuer:      "test",
	})
	require.NoError(t, err)

	secret := totpSecret.Secret()

	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)

	u := User{}
	assert.False(t, u.TOTPEnabled())
	assert.False(t, u.CheckTOTP(code))

	u.TOTPSeed = &secret
	assert.True(t, u.TOTPEnabled())

	assert.True(t, u.CheckTOTP(code))
}

func TestUser_WebAuthnName(t *testing.T) {
	u := User{
		Username: "testuser",
	}

	assert.Equal(t, "testuser", u.WebAuthnName())
}

func TestUser_WebAuthnDisplayName(t *testing.T) {
	u := User{
		Username: "testuser",
	}

	assert.Equal(t, "testuser", u.WebAuthnDisplayName())
}

func TestUser_WebAuthnCredentials(t *testing.T) {
	t.Run("single credential", func(t *testing.T) {
		u := User{
			StoredCredentials: []Passkey{
				{
					Credential: webauthn.Credential{
						ID:              []byte{0x01, 0x02},
						PublicKey:       []byte{0x03, 0x04},
						AttestationType: "",
						Transport:       make([]protocol.AuthenticatorTransport, 0),
						Flags: webauthn.CredentialFlags{
							UserPresent:    true,
							UserVerified:   true,
							BackupEligible: false,
							BackupState:    false,
						},
						Authenticator: webauthn.Authenticator{
							AAGUID:       []byte{0x05, 0x06},
							SignCount:    0,
							CloneWarning: false,
							Attachment:   protocol.Platform,
						},
					},
				},
			},
		}

		creds := u.WebAuthnCredentials()
		assert.Len(t, creds, 1)

		assert.Equal(t, []byte{0x01, 0x02}, creds[0].ID)
		assert.Equal(t, []byte{0x03, 0x04}, creds[0].PublicKey)
	})

	t.Run("no creds", func(t *testing.T) {
		u := User{}

		assert.Empty(t, u.WebAuthnCredentials())
	})
}

func TestUser_WebAuthnIcon(t *testing.T) {
	u := User{}
	assert.Equal(t, "", u.WebAuthnIcon())
}

func TestUser_WebAuthnID(t *testing.T) {
	t.Run("valid uuid", func(t *testing.T) {
		rawUUID := uuid.New()
		bytes, err := rawUUID.MarshalBinary()
		require.NoError(t, err)

		u := User{
			Id: rawUUID.String(),
		}

		assert.Equal(t, bytes, u.WebAuthnID())
	})

	t.Run("invalid uuid", func(t *testing.T) {
		u := User{
			Id: "not-a-valid-guid",
		}

		assert.Panics(t, func() {
			u.WebAuthnID()
		})
	})

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
