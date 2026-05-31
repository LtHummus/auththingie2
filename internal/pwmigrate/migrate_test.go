package pwmigrate

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/lthummus/auththingie2/internal/argon"
	"github.com/lthummus/auththingie2/internal/mocks"
	"github.com/lthummus/auththingie2/internal/user"
)

func makeTestUser() *user.User {
	return &user.User{
		Id:                strings.Trim(uuid.New().String(), "-"),
		Username:          "test",
		PasswordHash:      "",
		Roles:             []string{"a"},
		Admin:             false,
		TOTPSeed:          nil,
		RecoveryCodes:     nil,
		PasswordTimestamp: 0,
		StoredCredentials: nil,
	}

}

func TestMigrateUser(t *testing.T) {
	cfg := viper.New()
	cfg.SetDefault(argon.MemoryKey, argon.DefaultMemory)
	cfg.SetDefault(argon.IterationKey, argon.DefaultIterations)
	cfg.SetDefault(argon.ParallelismKey, argon.DefaultParallelism)
	cfg.SetDefault(argon.SaltLengthKey, argon.DefaultSaltLength)
	cfg.SetDefault(argon.KeyLengthKey, argon.DefaultKeyLength)

	t.Run("basic test", func(t *testing.T) {
		db := mocks.NewMockDB(t)
		u := makeTestUser()

		db.On("UpdatePassword", mock.Anything, u).Return(nil)

		MigrateUser(context.TODO(), u, "test-pw", db, cfg)

		assert.NotEmpty(t, u.PasswordHash)
	})

	t.Run("don't update if you can't get the lock", func(t *testing.T) {
		db := mocks.NewMockDB(t)
		u := makeTestUser()

		attemptLockUser(u.Id)

		MigrateUser(context.TODO(), u, "test-pw", db, cfg)

		// no calls expected
		unlockUser(u.Id)
	})

	t.Run("gracefull handle failed write", func(t *testing.T) {
		db := mocks.NewMockDB(t)
		u := makeTestUser()

		db.On("UpdatePassword", mock.Anything, u).Return(errors.New("oops"))

		MigrateUser(context.TODO(), u, "test-pw", db, cfg)

		assert.NotEmpty(t, u.PasswordHash)
	})
}
