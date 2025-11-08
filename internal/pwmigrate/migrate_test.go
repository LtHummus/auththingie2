package pwmigrate

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/lthummus/auththingie2/internal/user"
	"github.com/lthummus/auththingie2/mocks"
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
	t.Run("basic test", func(t *testing.T) {
		db := mocks.NewMockDB(t)
		u := makeTestUser()

		db.On("UpdatePassword", mock.Anything, u).Return(nil)

		MigrateUser(context.TODO(), u, "test-pw", db)

		assert.NotEmpty(t, u.PasswordHash)
	})

	t.Run("don't update if you can't get the lock", func(t *testing.T) {
		db := mocks.NewMockDB(t)
		u := makeTestUser()

		attemptLockUser(u.Id)

		MigrateUser(context.TODO(), u, "test-pw", db)

		// no calls expected
		unlockUser(u.Id)
	})

	t.Run("gracefull handle failed write", func(t *testing.T) {
		db := mocks.NewMockDB(t)
		u := makeTestUser()

		db.On("UpdatePassword", mock.Anything, u).Return(errors.New("oops"))

		MigrateUser(context.TODO(), u, "test-pw", db)

		assert.NotEmpty(t, u.PasswordHash)
	})
}
