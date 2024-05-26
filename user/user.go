package user

import (
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"github.com/rs/zerolog/log"

	"github.com/lthummus/auththingie2/argon"

	"github.com/go-webauthn/webauthn/webauthn"

	"golang.org/x/crypto/bcrypt"
)

var (
	ErrNoPasswordSet     = errors.New("user: no password set")
	ErrIncorrectPassword = errors.New("user: wrong password")
	ErrInvalidHash       = errors.New("user: invalid password hash")
)

var _ webauthn.User = (*User)(nil)

type Passkey struct {
	webauthn.Credential
	FriendlyName *string
	LastUsed     *time.Time
}

type User struct {
	Id                string
	Username          string
	PasswordHash      string
	Roles             []string
	Admin             bool
	TOTPSeed          *string
	RecoveryCodes     []string
	PasswordTimestamp int64
	StoredCredentials []Passkey
	Disabled          bool
}

type AdminListUser struct {
	Id       string
	Username string
	Roles    []string
	Admin    bool
	UsesTOTP bool
	Disabled bool
}

func (u *User) CheckPassword(candidate string) error {
	if len(u.PasswordHash) == 0 {
		return ErrNoPasswordSet
	}

	if strings.HasPrefix(u.PasswordHash, "$2") {
		// password is bcrypt
		err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(candidate))
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return ErrIncorrectPassword
		}

		if err != nil {
			return ErrInvalidHash
		}

		return nil
	}

	err := argon.ValidatePassword(candidate, u.PasswordHash)
	if errors.Is(err, argon.ErrWrongPassword) {
		return ErrIncorrectPassword
	}

	if err != nil {
		return ErrInvalidHash
	}

	return nil
}

func (u *User) HasRole(r string) bool {
	// O(n) ... but whatever
	for _, curr := range u.Roles {
		if curr == r {
			return true
		}
	}

	return false
}

func (u *User) GroupsOverlap(groups []string) bool {
	// yes, i know this is O(n^2), but in practice, n is small enough where putting the data in to any other sort
	// of structure to reduce to O(n) or whatever will have so much overhead it's not worth it. There's a benchmark
	// test and everything looks gravy
	for _, i := range groups {
		for _, j := range u.Roles {
			if i == j {
				return true
			}
		}
	}

	return false
}

func (u *User) CheckTOTP(code string) bool {
	if u.TOTPSeed == nil {
		return false
	}
	return totp.Validate(code, *u.TOTPSeed)
}

func (u *User) TOTPEnabled() bool {
	return u.TOTPSeed != nil
}

func (u *User) SetPassword(password string) error {
	hash, err := argon.GenerateFromPassword(password)
	if err != nil {
		log.Error().Err(err).Msg("could not hash password")
		return err
	}
	u.PasswordHash = hash
	u.PasswordTimestamp = time.Now().Unix()
	return nil
}

func (u *User) WebAuthnID() []byte {
	parsed, err := uuid.Parse(u.Id)
	if err != nil {
		log.Panic().Str("user_id", u.Id).Msg("could not parse uuid")
	}

	bytes, _ := parsed.MarshalBinary()
	return bytes
}

func (u *User) WebAuthnName() string {
	return u.Username
}

func (u *User) WebAuthnDisplayName() string {
	return u.Username
}

func (u *User) WebAuthnCredentials() []webauthn.Credential {
	res := make([]webauthn.Credential, len(u.StoredCredentials))
	for i := range u.StoredCredentials {
		res[i] = u.StoredCredentials[i].Credential
	}
	return res
}

func (u *User) WebAuthnIcon() string {
	return ""
}
