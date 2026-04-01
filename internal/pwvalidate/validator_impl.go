package pwvalidate

import (
	"context"
	"errors"
	"fmt"

	"github.com/rs/zerolog/log"

	"github.com/lthummus/auththingie2/internal/argon"
	"github.com/lthummus/auththingie2/internal/db"
	"github.com/lthummus/auththingie2/internal/loginlimit"
	"github.com/lthummus/auththingie2/internal/pwmigrate"
	"github.com/lthummus/auththingie2/internal/user"
)

// fakeArgonHash is a hash of an arbitrary string that we can check against later when logging in with a user that does
// not exist. We want a valid argon hash to check against so we don't leak user existence via timing. We generate one
// here to use because we want to generate one that uses the configured argon parameters
var fakeArgonHash string

func init() {
	var err error
	fakeArgonHash, err = argon.GenerateFromPassword("hello world this is my fake password")
	if err != nil {
		log.Fatal().Err(err).Msg("could not generate fake hash -- is your argon configuration ok?")
	}
}

type ValidatorImpl struct {
	db db.DB
	ll loginlimit.LoginLimiter
}

func NewValidator(db db.DB, ll loginlimit.LoginLimiter) *ValidatorImpl {
	return &ValidatorImpl{
		db: db,
		ll: ll,
	}
}

func (v *ValidatorImpl) generateInvalidCredentialsError(sourceIP string, username string, sourceIPKey string, accountKey string) error {
	accountRemaining, err := v.ll.MarkFailedAttempt(accountKey)
	accountLocked := false
	if err != nil {
		if errors.Is(err, loginlimit.ErrAccountLocked) {
			accountLocked = true
			log.Info().Str("ip", sourceIP).Str("username", username).Msg("account locked due to too many failures")
		} else {
			log.Warn().Err(err).Str("ip", sourceIP).Str("username", username).Msg("could not mark username as failed login")
			return err
		}
	}

	ipRemaining, err := v.ll.MarkFailedAttempt(sourceIPKey)
	if err != nil {
		// we want to return ip blocked as highest priority since we don't want to leak any more info if an IP is hammering us
		if errors.Is(err, loginlimit.ErrAccountLocked) {
			log.Info().Str("ip", sourceIP).Str("username", username).Msg("ip blocked due to too many failures")
			return &IPBlockedError{}
		}
		log.Warn().Err(err).Str("ip", sourceIP).Str("username", username).Msg("could not mark username as failed login")
		return err
	}

	if accountLocked {
		return &AccountLockedError{}
	}

	return &InvalidUsernamePasswordError{
		AccountRemainingBeforeLocked: accountRemaining,
		IPRemainingBeforeLocked:      ipRemaining,
	}
}

func (v *ValidatorImpl) Validate(ctx context.Context, username string, password string, sourceIP string) (*user.User, error) {
	sourceIPKey := fmt.Sprintf("ip|%s", sourceIP)
	accountKey := fmt.Sprintf("username|%s", username)

	if v.ll.IsAccountLocked(sourceIPKey) {
		return nil, &IPBlockedError{}
	}

	if v.ll.IsAccountLocked(accountKey) {
		return nil, &AccountLockedError{}
	}

	u, err := v.db.GetUserByUsername(ctx, username)
	if err != nil {
		log.Error().Err(err).Msg("could not query for user")
		return nil, err
	}

	if u == nil {
		log.Warn().Str("ip", sourceIP).Msg("invalid login")

		// do an argon validation even though it won't work because we want to consume some time so the existence of a user can't
		// be detected via timing
		_ = argon.ValidatePassword("aaaaaaaaaa", fakeArgonHash)

		return nil, v.generateInvalidCredentialsError(sourceIP, username, sourceIPKey, accountKey)
	}

	err = u.CheckPassword(password)
	if err != nil {
		log.Warn().Str("ip", sourceIP).Str("username", username).Err(err).Msg("invalid login")

		return nil, v.generateInvalidCredentialsError(sourceIP, username, sourceIPKey, accountKey)
	}

	if argon.NeedsMigration(u.PasswordHash) {
		go func() { // #nosec G118 -- we want this to run in the background
			pwmigrate.MigrateUser(context.Background(), u, password, v.db)
		}()
	}

	v.ll.MarkSuccessfulAttempt(accountKey)
	v.ll.MarkSuccessfulAttempt(sourceIPKey)

	if u.Disabled {
		return u, &AccountDisabledError{}
	}

	return u, nil
}
