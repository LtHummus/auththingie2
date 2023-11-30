package db

import (
	"context"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/lthummus/auththingie2/user"
)

type DB interface {
	GetUserByGuid(ctx context.Context, guid string) (*user.User, error)
	GetUserByUsername(ctx context.Context, username string) (*user.User, error)
	SaveUser(ctx context.Context, user *user.User) error
	CreateUser(ctx context.Context, user *user.User) error
	SaveCredentialForUser(ctx context.Context, userId string, credential *webauthn.Credential) error
	FindUserByCredentialInfo(ctx context.Context, rid []byte, handle []byte) (*user.User, error)
	UpdateCredentialOnLogin(ctx context.Context, credential *webauthn.Credential) error

	FindKeyById(ctx context.Context, keyID string) (user.Passkey, error)
	UpdateKeyName(ctx context.Context, keyID string, name *string) error
	DeleteKey(ctx context.Context, keyID string) error

	Close() error
	GetAllUsers(ctx context.Context) ([]*user.AdminListUser, error)
	DeleteUser(ctx context.Context, userId string) error

	NeedsSetup(ctx context.Context) (bool, error)
	UpdateTOTPSeed(ctx context.Context, userID string, secret string) error
	UpdatePassword(ctx context.Context, user *user.User) error
}
