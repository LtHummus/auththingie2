package sqlite

import (
	"database/sql"
	"embed"
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/sqlite3"
	_ "github.com/golang-migrate/migrate/v4/database/sqlite3"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

//go:embed migrations/*
var migrations embed.FS

const latestVersion = 3

func migrateDatabase(db *sql.DB) error {
	d, err := iofs.New(migrations, "migrations")
	if err != nil {
		log.Error().Err(err).Msg("could not load migration files")
		return fmt.Errorf("db: migrateDatabase: could not load migration files: %w", err)
	}

	driver, err := sqlite3.WithInstance(db, &sqlite3.Config{})
	if err != nil {
		log.Error().Err(err).Msg("could not load instance driver")
		return fmt.Errorf("db: migrateDatabase: could not load instance driver: %w", err)
	}
	defer driver.Close()

	m, err := migrate.NewWithInstance("iofs", d, "sqlite3", driver)
	if err != nil {
		log.Error().Err(err).Msg("could not create migration")
		return fmt.Errorf("db: migrateDatabase: could not create migration instance: %w", err)
	}
	m.Log = &migrationLogger{}

	if err = m.Migrate(latestVersion); err != nil {
		if err == migrate.ErrNoChange {
			log.Info().Int("latest_version", latestVersion).Msg("database is at latest version")
			return nil
		}
		log.Error().Err(err).Int("latest_version", latestVersion).Msg("could not migrate to latest database version")
		return fmt.Errorf("db: migrateDatabase: could not migrate to current database version: %w", err)
	}

	return nil
}

var _ migrate.Logger = (*migrationLogger)(nil)

type migrationLogger struct{}

func (m *migrationLogger) Printf(format string, v ...interface{}) {
	log.Printf(strings.TrimSpace(format), v...)
}

func (m *migrationLogger) Verbose() bool {
	return true
}
