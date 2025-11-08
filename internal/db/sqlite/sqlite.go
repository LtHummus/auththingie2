package sqlite

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"

	"github.com/lthummus/auththingie2/internal/config"
	"github.com/lthummus/auththingie2/internal/db"
	"github.com/lthummus/auththingie2/internal/user"
	"github.com/lthummus/auththingie2/internal/util"

	_ "github.com/mattn/go-sqlite3"
)

type SQLite struct {
	setupLock *sync.Mutex
	db        *sql.DB

	setupNeeded *bool
}

var (
	ErrNoUsersAffected = fmt.Errorf("database: no users affected on update")

	Base64Encoder = base64.URLEncoding.WithPadding(base64.NoPadding)
)

var _ db.DB = (*SQLite)(nil)

func NewSQLiteFromConfig() (*SQLite, error) {
	config.Lock.RLock()
	defer config.Lock.RUnlock()
	file := viper.GetString("db.file")
	if file == "" {
		return nil, errors.New("db: NewSQLiteFromConfig: db file not set")
	}

	absDBFile, err := filepath.Abs(file)
	if err != nil {
		log.Warn().Str("raw_db_file", file).Err(err).Msg("could not get db file absolute path")
	}

	log.Info().Str("raw_db_file", file).Str("abs_db_file", absDBFile).Msg("starting database initialization")

	database, err := sql.Open("sqlite3", file)
	if err != nil {
		return nil, fmt.Errorf("db: NewSQLiteFromConfig: could not open db: %w", err)
	}

	err = migrateDatabase(database)
	if err != nil {
		return nil, fmt.Errorf("db: NewSQLiteFromConfig: could not check configuration state: %w", err)
	}

	// reopen database now that migration is complete
	database, err = sql.Open("sqlite3", file)
	if err != nil {
		return nil, fmt.Errorf("db: NewSQLiteFromConfig: could not open db: %w", err)
	}

	_, err = database.Exec("PRAGMA foreign_keys = ON")
	if err != nil {
		return nil, fmt.Errorf("db: NewSQLiteFromConfig: could not enable foreign keys: %w", err)
	}

	log.Info().Str("raw_db_file", file).Str("abs_db_file", absDBFile).Msg("finished database initialization")

	return &SQLite{
		db:        database,
		setupLock: &sync.Mutex{},
	}, nil
}

func (s *SQLite) getCredentials(ctx context.Context, guid string) ([]user.Passkey, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT id, user_id, friendly_name, last_used, public_key, attestation_type, transports, flags, aaguid, sign_count, clone_warning, authenticator_attachment FROM webauthn_keys WHERE user_id = $1", guid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []user.Passkey
	for rows.Next() {
		var id string
		var userId string
		var friendlyName *string
		var lastUsed int64
		var publicKey string
		var attestationType string
		var transports string
		var flags int
		var aaguid string
		var signCount uint32
		var cloneWarning int
		var authenticatorAttachment protocol.AuthenticatorAttachment
		err = rows.Scan(&id, &userId, &friendlyName, &lastUsed, &publicKey, &attestationType, &transports, &flags, &aaguid, &signCount, &cloneWarning, &authenticatorAttachment)
		if err != nil {
			return nil, err
		}

		decodedId, err := Base64Encoder.DecodeString(id)
		if err != nil {
			log.Warn().Err(err).Msg("could not decode key id")
			return nil, err
		}

		decodedPublicKey, err := Base64Encoder.DecodeString(publicKey)
		if err != nil {
			log.Warn().Err(err).Msg("could not decode public key")
			return nil, err
		}

		var decodedTransports []protocol.AuthenticatorTransport
		err = json.Unmarshal([]byte(transports), &decodedTransports)
		if err != nil {
			log.Warn().Err(err).Msg("could not decode transports")
			return nil, err
		}

		decodedFlags := decodeFlags(flags)
		decodedAAGUID, err := Base64Encoder.DecodeString(aaguid)
		if err != nil {
			log.Warn().Err(err).Msg("could not decode AAGUID")
			return nil, err
		}

		pk := user.Passkey{
			Credential: webauthn.Credential{
				ID:              decodedId,
				PublicKey:       decodedPublicKey,
				AttestationType: attestationType,
				Transport:       decodedTransports,
				Flags:           decodedFlags,
				Authenticator: webauthn.Authenticator{
					AAGUID:       decodedAAGUID,
					SignCount:    signCount,
					CloneWarning: cloneWarning != 0,
					Attachment:   authenticatorAttachment,
				},
			},
			FriendlyName: friendlyName,
		}

		if lastUsed != 0 {
			t := time.Unix(lastUsed, 0)
			pk.LastUsed = &t
		}

		keys = append(keys, pk)
	}

	return keys, nil
}

// TODO: refactor this common code between GetUserByX functions
func (s *SQLite) GetUserByGuid(ctx context.Context, guid string) (*user.User, error) {
	var id string
	var username string
	var password string
	var roles string
	var admin bool
	var totpSeed *string
	var passwordTimestamp int64
	var disabled int64
	err := s.db.QueryRowContext(ctx, "SELECT id, username, password, roles, admin, totp_seed, password_timestamp, disabled FROM users WHERE id = $1", guid).Scan(&id, &username, &password, &roles, &admin, &totpSeed, &passwordTimestamp, &disabled)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Debug().Str("guid", guid).Msg("user not found")
			return nil, nil
		}
		return nil, err
	}
	var decodedRoles []string
	err = json.Unmarshal([]byte(roles), &decodedRoles)
	if err != nil {
		return nil, fmt.Errorf("db: sqlite: GetUserByUsername: could not decode role JSON: %w", err)
	}

	credentials, err := s.getCredentials(ctx, id)
	if err != nil {
		log.Warn().Err(err).Msg("could not load credentials")
		return nil, err
	}

	return &user.User{
		Id:                id,
		Username:          username,
		PasswordHash:      password,
		Roles:             decodedRoles,
		Admin:             admin,
		TOTPSeed:          totpSeed,
		PasswordTimestamp: passwordTimestamp,
		StoredCredentials: credentials,
		Disabled:          disabled != 0,
	}, nil
}
func (s *SQLite) GetUserByUsername(ctx context.Context, username string) (*user.User, error) {
	var id string
	var password string
	var roles string
	var admin bool
	var totpSeed *string
	var passwordTimestamp int64
	var disabled int64
	err := s.db.QueryRowContext(ctx, "SELECT id, password, roles, admin, totp_seed, password_timestamp, disabled FROM users WHERE username = $1", username).Scan(&id, &password, &roles, &admin, &totpSeed, &passwordTimestamp, &disabled)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Debug().Str("username", username).Msg("user not found")
			return nil, nil
		}
		return nil, err
	}
	var decodedRoles []string
	err = json.Unmarshal([]byte(roles), &decodedRoles)
	if err != nil {
		return nil, fmt.Errorf("db: sqlite: GetUserByUsername: could not decode role JSON: %w", err)
	}

	credentials, err := s.getCredentials(ctx, id)
	if err != nil {
		log.Warn().Err(err).Msg("could not load credentials")
		return nil, err
	}

	return &user.User{
		Id:                id,
		Username:          username,
		PasswordHash:      password,
		Roles:             decodedRoles,
		Admin:             admin,
		TOTPSeed:          totpSeed,
		PasswordTimestamp: passwordTimestamp,
		StoredCredentials: credentials,
		Disabled:          disabled != 0,
	}, nil

}

func (s *SQLite) FindUserByCredentialInfo(ctx context.Context, rid []byte, handle []byte) (*user.User, error) {
	encodedRid := Base64Encoder.EncodeToString(rid)
	encodedUuid, err := uuid.FromBytes(handle)
	if err != nil {
		log.Warn().Err(err).Hex("uuid", handle).Msg("could not parse uuid")
		return nil, err
	}

	var userId string
	err = s.db.QueryRowContext(ctx, "SELECT user_id FROM webauthn_keys WHERE id = $1 AND user_id = $2", encodedRid, encodedUuid.String()).Scan(&userId)
	if err != nil {
		log.Warn().Err(err).Msg("could not find user")
		return nil, err
	}

	return s.GetUserByGuid(ctx, userId)
}

func encodeFlags(flags webauthn.CredentialFlags) int {
	res := 0
	if flags.UserPresent {
		res += 1 << 3
	}
	if flags.UserVerified {
		res += 1 << 2
	}
	if flags.BackupEligible {
		res += 1 << 1
	}
	if flags.BackupState {
		res += 1 << 0
	}

	return res
}

func (s *SQLite) FindKeyById(ctx context.Context, keyID string) (user.Passkey, error) {
	var id string
	var userId string
	var friendlyName *string
	var lastUsed int64
	var publicKey string
	var attestationType string
	var transports string
	var flags int
	var aaguid string
	var signCount uint32
	var cloneWarning int
	var authenticatorAttachment protocol.AuthenticatorAttachment
	err := s.db.QueryRowContext(ctx,
		"SELECT id, user_id, friendly_name, last_used, public_key, attestation_type, transports, flags, aaguid, sign_count, clone_warning, authenticator_attachment FROM webauthn_keys WHERE id = $1", keyID).
		Scan(&id, &userId, &friendlyName, &lastUsed, &publicKey, &attestationType, &transports, &flags, &aaguid, &signCount, &cloneWarning, &authenticatorAttachment)

	if err != nil {
		return user.Passkey{}, err
	}

	decodedId, err := Base64Encoder.DecodeString(id)
	if err != nil {
		log.Warn().Err(err).Msg("could not decode key id")
		return user.Passkey{}, err
	}

	decodedPublicKey, err := Base64Encoder.DecodeString(publicKey)
	if err != nil {
		log.Warn().Err(err).Msg("could not decode public key")
		return user.Passkey{}, err
	}

	var decodedTransports []protocol.AuthenticatorTransport
	err = json.Unmarshal([]byte(transports), &decodedTransports)
	if err != nil {
		log.Warn().Err(err).Msg("could not decode transports")
		return user.Passkey{}, err
	}

	decodedFlags := decodeFlags(flags)
	decodedAAGUID, err := Base64Encoder.DecodeString(aaguid)
	if err != nil {
		log.Warn().Err(err).Msg("could not decode AAGUID")
		return user.Passkey{}, err
	}

	pk := user.Passkey{
		Credential: webauthn.Credential{
			ID:              decodedId,
			PublicKey:       decodedPublicKey,
			AttestationType: attestationType,
			Transport:       decodedTransports,
			Flags:           decodedFlags,
			Authenticator: webauthn.Authenticator{
				AAGUID:       decodedAAGUID,
				SignCount:    signCount,
				CloneWarning: cloneWarning != 0,
				Attachment:   authenticatorAttachment,
			},
		},
		FriendlyName: friendlyName,
	}

	if lastUsed != 0 {
		t := time.Unix(lastUsed, 0)
		pk.LastUsed = &t
	}

	return pk, nil

}

// TODO: add mark key used

func (s *SQLite) UpdateKeyName(ctx context.Context, keyID string, name *string) error {
	_, err := s.db.ExecContext(ctx, "UPDATE webauthn_keys SET friendly_name = $1 WHERE id = $2", name, keyID)
	return err
}

func (s *SQLite) DeleteKey(ctx context.Context, keyID string) error {
	res, err := s.db.ExecContext(ctx, "DELETE FROM webauthn_keys WHERE id = $1", keyID)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("sqlite: DeleteKey: key not found: %s", keyID)
	}
	return err
}

func decodeFlags(x int) webauthn.CredentialFlags {
	return webauthn.CredentialFlags{
		UserPresent:    x&(1<<3) != 0,
		UserVerified:   x&(1<<2) != 0,
		BackupEligible: x&(1<<1) != 0,
		BackupState:    x&(1<<0) != 0,
	}
}

func (s *SQLite) UpdateCredentialOnLogin(ctx context.Context, credential *webauthn.Credential) error {
	encodedId := Base64Encoder.EncodeToString(credential.ID)
	log.Debug().Str("key_id", encodedId).Uint32("sign_count", credential.Authenticator.SignCount).Msg("should update credential")
	timestamp := time.Now().Unix()

	_, err := s.db.ExecContext(ctx, "UPDATE webauthn_keys SET last_used = $1, sign_count = $2 WHERE id = $3", timestamp, credential.Authenticator.SignCount, encodedId)
	return err
}

func (s *SQLite) SaveCredentialForUser(ctx context.Context, userId string, credential *webauthn.Credential) error {
	encodedCredential := Base64Encoder.EncodeToString(credential.ID)
	encodedPublicKey := Base64Encoder.EncodeToString(credential.PublicKey)
	encodedTransports, err := json.Marshal(credential.Transport)
	if err != nil {
		log.Error().Err(err).Msg("could not encode transports")
		return err
	}

	encodedFlags := encodeFlags(credential.Flags)
	encodedAAGUID := Base64Encoder.EncodeToString(credential.Authenticator.AAGUID)

	encodedCloneWarning := 0
	if credential.Authenticator.CloneWarning {
		encodedCloneWarning = 1
	}

	_, err = s.db.ExecContext(ctx,
		"INSERT INTO webauthn_keys (id, user_id, public_key, attestation_type, transports, flags, aaguid, sign_count, clone_warning, authenticator_attachment) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
		encodedCredential,
		userId,
		encodedPublicKey,
		credential.AttestationType,
		encodedTransports,
		encodedFlags,
		encodedAAGUID,
		credential.Authenticator.SignCount,
		encodedCloneWarning,
		credential.Authenticator.Attachment,
	)
	if err != nil {
		log.Warn().Err(err).Msg("could not insert credential")
		return err
	}

	return nil
}

func (s *SQLite) DeleteUser(ctx context.Context, userId string) error {
	res, err := s.db.ExecContext(ctx, "DELETE FROM users WHERE id = $1", userId)
	if err != nil {
		return err
	}
	r, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if r != 1 {
		return errors.New("unable to delete, no rows affected")
	}

	s.setupLock.Lock()
	s.setupNeeded = nil
	s.setupLock.Unlock()

	return nil
}

func (s *SQLite) SaveUser(ctx context.Context, user *user.User) error {
	roleBytes, err := json.Marshal(user.Roles)
	if err != nil {
		// can you ever fail to serialize a slice of strings!?
		return err
	}
	res, err := s.db.ExecContext(ctx, "UPDATE users SET password = $1, roles = $2, admin = $3, totp_seed = $4, password_timestamp = $5 WHERE id = $6",
		user.PasswordHash,
		string(roleBytes),
		user.Admin,
		user.TOTPSeed,
		user.PasswordTimestamp,
		user.Id)
	if err != nil {
		return err
	}

	ra, err := res.RowsAffected()
	if err != nil {
		return err
	}

	if ra == 0 {
		log.Warn().Str("id", user.Id).Str("username", user.Username).Msg("attempted to update; no rows changed")
		return ErrNoUsersAffected
	}

	return nil
}

func (s *SQLite) CreateUser(ctx context.Context, user *user.User) error {
	s.setupLock.Lock()
	defer s.setupLock.Unlock()
	s.setupNeeded = nil

	generatedUuid := uuid.NewString()

	_, err := s.db.ExecContext(ctx, "INSERT INTO users (id, username, password, roles, admin, totp_seed, password_timestamp) VALUES ($1, $2, $3, $4, $5, $6, $7)",
		generatedUuid,
		user.Username,
		string(user.PasswordHash),
		serializeRoles(user),
		user.Admin,
		user.TOTPSeed,
		user.PasswordTimestamp)

	if err != nil {
		log.Error().Err(err).Msg("could not save user")
		return err
	}

	return nil
}

func (s *SQLite) Close() error {
	return s.db.Close()
}

func (s *SQLite) NeedsSetup(ctx context.Context) (bool, error) {
	s.setupLock.Lock()
	defer s.setupLock.Unlock()

	if s.setupNeeded != nil {
		return *s.setupNeeded, nil
	}

	var userCount int
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&userCount)
	if err != nil {
		return false, err
	}
	s.setupNeeded = util.P(userCount == 0)
	return userCount == 0, nil
}

func (s *SQLite) UpdateTOTPSeed(ctx context.Context, userID string, secret string) error {
	res, err := s.db.ExecContext(ctx, "UPDATE users SET totp_seed = $1 WHERE id = $2", secret, userID)
	if err != nil {
		return err
	}

	ra, err := res.RowsAffected()
	if err != nil {
		return err
	}

	if ra != 1 {
		log.Warn().Str("user_id", userID).Msg("could not update TOTP seed, no rows affected")
		return errors.New("no rows affected on totp update")
	}

	return nil
}

func (s *SQLite) GetAllUsers(ctx context.Context) ([]*user.AdminListUser, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id, username, admin, roles, totp_seed FROM users")
	if err != nil {
		return nil, err
	}

	var ret []*user.AdminListUser

	defer rows.Close()
	for rows.Next() {
		var id string
		var username string
		var admin bool
		var rawRoles string
		var seed *string
		err = rows.Scan(&id, &username, &admin, &rawRoles, &seed)
		if err != nil {
			return nil, err
		}

		var roles []string
		err = json.Unmarshal([]byte(rawRoles), &roles)
		if err != nil {
			return nil, err
		}

		ret = append(ret, &user.AdminListUser{
			Id:       id,
			Username: username,
			Roles:    roles,
			Admin:    admin,
			UsesTOTP: seed != nil,
		})
	}

	return ret, nil
}

func serializeRoles(u *user.User) string {
	if len(u.Roles) == 0 {
		return "[]"
	}

	j, _ := json.Marshal(u.Roles)
	return string(j)
}

func (s *SQLite) UpdatePassword(ctx context.Context, user *user.User) error {
	_, err := s.db.ExecContext(ctx, "UPDATE users SET password = $1, password_timestamp = $2 WHERE username = $3", user.PasswordHash, user.PasswordTimestamp, user.Username)
	return err
}

func (s *SQLite) SetUserEnabled(ctx context.Context, userId string, enabled bool) error {
	disabledValue := 0
	if !enabled {
		disabledValue = 1
	}
	_, err := s.db.ExecContext(ctx, "UPDATE users SET disabled = $1 WHERE id = $2", disabledValue, userId)
	return err
}
