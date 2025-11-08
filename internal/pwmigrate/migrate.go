package pwmigrate

import (
	"context"

	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"

	"github.com/lthummus/auththingie2/internal/db"
	"github.com/lthummus/auththingie2/internal/user"
)

func MigrateUser(ctx context.Context, u *user.User, password string, database db.DB) {
	if viper.GetBool("security.disable_migrate_on_login") {
		return
	}

	log.Warn().Str("username", u.Username).Msg("password needs migration")
	lockGranted := attemptLockUser(u.Id)
	if !lockGranted {
		log.Trace().Str("username", u.Username).Msg("lock held, ignoring")
		return
	}
	defer unlockUser(u.Id)

	err := u.SetPassword(password)
	if err != nil {
		log.Error().Err(err).Str("username", u.Username).Msg("unable to migrate password on login")
		return
	}

	err = database.UpdatePassword(ctx, u)
	if err != nil {
		log.Error().Err(err).Str("username", u.Username).Msg("could not persist updated password")
		return
	}

	log.Warn().Str("username", u.Username).Msg("migrated password to new params")
}
