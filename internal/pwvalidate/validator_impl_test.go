package pwvalidate

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/lthummus/auththingie2/internal/argon"
	"github.com/lthummus/auththingie2/internal/loginlimit"
	"github.com/lthummus/auththingie2/internal/mocks"
	"github.com/lthummus/auththingie2/internal/user"
)

func makeMocks(t *testing.T) (*mocks.MockDB, *mocks.MockLoginLimiter, *ValidatorImpl) {
	mdb := mocks.NewMockDB(t)
	mll := mocks.NewMockLoginLimiter(t)

	return mdb, mll, &ValidatorImpl{
		db: mdb,
		ll: mll,
	}
}

func TestValidatorImpl_Validate(t *testing.T) {
	correctPassword := "P@ssw0rd!"
	correctPasswordHash, _ := argon.GenerateFromPassword(correctPassword)

	t.Run("ip is being blocked", func(t *testing.T) {
		_, mll, v := makeMocks(t)

		mll.On("IsAccountLocked", "ip|127.0.0.1").Return(true)

		u, err := v.Validate(context.TODO(), "username", "password", "127.0.0.1")
		assert.Nil(t, u)

		var ipbl *IPBlockedError
		assert.ErrorAs(t, err, &ipbl)
	})

	t.Run("account is locked", func(t *testing.T) {
		_, mll, v := makeMocks(t)

		mll.On("IsAccountLocked", "ip|127.0.0.1").Return(false)
		mll.On("IsAccountLocked", "username|username").Return(true)

		u, err := v.Validate(context.TODO(), "username", "password", "127.0.0.1")
		assert.Nil(t, u)

		var ale *AccountLockedError
		assert.ErrorAs(t, err, &ale)
	})

	t.Run("database error when looking up user", func(t *testing.T) {
		mdb, mll, v := makeMocks(t)

		mll.On("IsAccountLocked", "ip|127.0.0.1").Return(false)
		mll.On("IsAccountLocked", "username|username").Return(false)

		mdb.On("GetUserByUsername", mock.Anything, "username").Return(nil, errors.New("whoops"))

		u, err := v.Validate(context.Background(), "username", "password", "127.0.0.1")
		assert.Nil(t, u)
		assert.Error(t, err)
	})

	t.Run("user not found", func(t *testing.T) {
		mdb, mll, v := makeMocks(t)

		mll.On("IsAccountLocked", "ip|127.0.0.1").Return(false)
		mll.On("IsAccountLocked", "username|username").Return(false)

		mdb.On("GetUserByUsername", mock.Anything, "username").Return(nil, nil)

		mll.On("MarkFailedAttempt", "ip|127.0.0.1").Return(4, nil)
		mll.On("MarkFailedAttempt", "username|username").Return(6, nil)

		u, err := v.Validate(context.Background(), "username", "password", "127.0.0.1")
		assert.Nil(t, u)

		var iupe *InvalidUsernamePasswordError
		assert.ErrorAs(t, err, &iupe)

		assert.Equal(t, 6, iupe.AccountRemainingBeforeLocked)
		assert.Equal(t, 4, iupe.IPRemainingBeforeLocked)
	})

	t.Run("error marking username failure", func(t *testing.T) {
		mdb, mll, v := makeMocks(t)

		mll.On("IsAccountLocked", "ip|127.0.0.1").Return(false)
		mll.On("IsAccountLocked", "username|username").Return(false)

		mdb.On("GetUserByUsername", mock.Anything, "username").Return(nil, nil)

		mll.On("MarkFailedAttempt", "username|username").Return(0, errors.New("oops"))

		u, err := v.Validate(context.Background(), "username", "password", "127.0.0.1")
		assert.Nil(t, u)
		assert.Error(t, err)

		var iupe *InvalidUsernamePasswordError
		assert.NotErrorAs(t, err, &iupe)
	})

	t.Run("error marking ip failure", func(t *testing.T) {
		mdb, mll, v := makeMocks(t)

		mll.On("IsAccountLocked", "ip|127.0.0.1").Return(false)
		mll.On("IsAccountLocked", "username|username").Return(false)

		mdb.On("GetUserByUsername", mock.Anything, "username").Return(nil, nil)

		mll.On("MarkFailedAttempt", "username|username").Return(4, nil)
		mll.On("MarkFailedAttempt", "ip|127.0.0.1").Return(0, errors.New("oops"))

		u, err := v.Validate(context.Background(), "username", "password", "127.0.0.1")
		assert.Nil(t, u)
		assert.Error(t, err)

		var iupe *InvalidUsernamePasswordError
		assert.NotErrorAs(t, err, &iupe)
	})

	t.Run("incorrect password", func(t *testing.T) {
		mdb, mll, v := makeMocks(t)

		mll.On("IsAccountLocked", "ip|127.0.0.1").Return(false)
		mll.On("IsAccountLocked", "username|username").Return(false)

		mdb.On("GetUserByUsername", mock.Anything, "username").Return(&user.User{
			PasswordHash: correctPasswordHash,
		}, nil)

		mll.On("MarkFailedAttempt", "ip|127.0.0.1").Return(4, nil)
		mll.On("MarkFailedAttempt", "username|username").Return(6, nil)

		u, err := v.Validate(context.Background(), "username", "bad_password", "127.0.0.1")
		assert.Nil(t, u)

		var iupe *InvalidUsernamePasswordError
		require.ErrorAs(t, err, &iupe)
		assert.Equal(t, 6, iupe.AccountRemainingBeforeLocked)
		assert.Equal(t, 4, iupe.IPRemainingBeforeLocked)
	})

	t.Run("incorrect password -- account locked", func(t *testing.T) {
		mdb, mll, v := makeMocks(t)

		mll.On("IsAccountLocked", "ip|127.0.0.1").Return(false)
		mll.On("IsAccountLocked", "username|username").Return(false)

		mdb.On("GetUserByUsername", mock.Anything, "username").Return(&user.User{
			PasswordHash: correctPasswordHash,
		}, nil)

		mll.On("MarkFailedAttempt", "ip|127.0.0.1").Return(4, nil)
		mll.On("MarkFailedAttempt", "username|username").Return(0, loginlimit.ErrAccountLocked)

		u, err := v.Validate(context.Background(), "username", "bad_password", "127.0.0.1")
		assert.Nil(t, u)

		var ale *AccountLockedError
		assert.ErrorAs(t, err, &ale)
	})

	t.Run("incorrect password -- ip blocked", func(t *testing.T) {
		mdb, mll, v := makeMocks(t)

		mll.On("IsAccountLocked", "ip|127.0.0.1").Return(false)
		mll.On("IsAccountLocked", "username|username").Return(false)

		mdb.On("GetUserByUsername", mock.Anything, "username").Return(&user.User{
			PasswordHash: correctPasswordHash,
		}, nil)

		mll.On("MarkFailedAttempt", "ip|127.0.0.1").Return(0, loginlimit.ErrAccountLocked)
		mll.On("MarkFailedAttempt", "username|username").Return(4, nil)

		u, err := v.Validate(context.Background(), "username", "bad_password", "127.0.0.1")
		assert.Nil(t, u)

		var ipbl *IPBlockedError
		assert.ErrorAs(t, err, &ipbl)
	})

	t.Run("successful login", func(t *testing.T) {
		mdb, mll, v := makeMocks(t)

		mll.On("IsAccountLocked", "ip|127.0.0.1").Return(false)
		mll.On("IsAccountLocked", "username|username").Return(false)

		mdb.On("GetUserByUsername", mock.Anything, "username").Return(&user.User{
			PasswordHash: correctPasswordHash,
		}, nil)

		mll.On("MarkSuccessfulAttempt", "ip|127.0.0.1")
		mll.On("MarkSuccessfulAttempt", "username|username")

		u, err := v.Validate(context.TODO(), "username", correctPassword, "127.0.0.1")
		require.NoError(t, err)
		require.NotNil(t, u)

		assert.Equal(t, correctPasswordHash, u.PasswordHash)
	})

	t.Run("account disabled", func(t *testing.T) {
		mdb, mll, v := makeMocks(t)

		mll.On("IsAccountLocked", "ip|127.0.0.1").Return(false)
		mll.On("IsAccountLocked", "username|username").Return(false)

		mdb.On("GetUserByUsername", mock.Anything, "username").Return(&user.User{
			PasswordHash: correctPasswordHash,
			Disabled:     true,
		}, nil)

		mll.On("MarkSuccessfulAttempt", "ip|127.0.0.1")
		mll.On("MarkSuccessfulAttempt", "username|username")

		u, err := v.Validate(context.TODO(), "username", correctPassword, "127.0.0.1")
		require.NotNil(t, u)

		var ade *AccountDisabledError
		assert.ErrorAs(t, err, &ade)
	})

	t.Run("successful login -- needs migration", func(t *testing.T) {
		mdb, mll, v := makeMocks(t)

		mll.On("IsAccountLocked", "ip|127.0.0.1").Return(false)
		mll.On("IsAccountLocked", "username|username").Return(false)

		viper.Set(argon.IterationKey, 1)
		t.Cleanup(func() {
			viper.Reset()
		})

		mdb.On("GetUserByUsername", mock.Anything, "username").Return(&user.User{
			PasswordHash: correctPasswordHash,
		}, nil)

		mll.On("MarkSuccessfulAttempt", "ip|127.0.0.1")
		mll.On("MarkSuccessfulAttempt", "username|username")

		mdb.On("UpdatePassword", mock.Anything, mock.AnythingOfType("*user.User")).Return(nil)

		u, err := v.Validate(context.TODO(), "username", correctPassword, "127.0.0.1")
		require.NoError(t, err)
		require.NotNil(t, u)

		assert.Equal(t, correctPasswordHash, u.PasswordHash)

		assert.Eventually(t, func() bool {
			return len(mdb.Mock.Calls) >= 2
		}, 5*time.Second, 250*time.Millisecond)

		updatedUser := mdb.Mock.Calls[1].Arguments[1].(*user.User)
		assert.True(t, strings.HasPrefix(updatedUser.PasswordHash, "$argon2id$v=19$m=65536,t=1,p=2$"))
		assert.WithinDuration(t, time.Now(), time.Unix(updatedUser.PasswordTimestamp, 0), 2*time.Second)
		assert.NoError(t, argon.ValidatePassword(correctPassword, updatedUser.PasswordHash))
	})
}
