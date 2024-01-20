package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/gorilla/securecookie"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lthummus/auththingie2/argon"
	"github.com/lthummus/auththingie2/user"
)

func buildTestDatabase(t *testing.T) *SQLite {
	dbName := fmt.Sprintf("at_test_%s.db", hex.EncodeToString(securecookie.GenerateRandomKey(16)))

	tmpDir, err := os.MkdirTemp("", "at2dbtests")
	require.NoError(t, err)

	dbFile := filepath.Join(tmpDir, dbName)

	viper.Set("db.file", dbFile)

	t.Cleanup(func() {
		viper.Set("db.file", "")
		os.RemoveAll(tmpDir)
	})

	db, err := NewSQLiteFromConfig()
	require.NoError(t, err)

	_, err = db.db.Exec(`INSERT INTO users (id, username, password, roles, admin, totp_seed, password_timestamp) VALUES ('8744ac1b-9074-4a70-a202-5ad6d4a6e5e0', 'ben', '$argon2id$v=19$m=65536,t=3,p=2$f5DrCPQlwRJ5q1fA4K+i/g$c8XhJISMUI3wjIUULHvn0HIJinvOBBb4KnvOcvuJ4e0', '[]', 1, null, 1704055267)`)
	require.NoError(t, err)
	_, err = db.db.Exec(`INSERT INTO users (id, username, password, roles, admin, totp_seed, password_timestamp) VALUES ('65d453ce-ee95-4377-94cf-f7938ce4412e', 'test', '$argon2id$v=19$m=32768,t=4,p=4$w4G65Zi1dnuQUYz/suyOc+593CQvP5IrpaJiOcEbDog$m7GySJ+XIwF6TzGUbfzx7vqzNCYAuGCpKkmNhIgr8vw', '["a","b"]', 0, 'JBSWY3DPEHPK3PXP', 1698000063)`)
	require.NoError(t, err)
	_, err = db.db.Exec(`INSERT INTO webauthn_keys (id, user_id, friendly_name, last_used, public_key, attestation_type, transports, flags, aaguid, sign_count, clone_warning, authenticator_attachment) VALUES ('ICSCHqqe14nQqUIXkBNtww', '8744ac1b-9074-4a70-a202-5ad6d4a6e5e0', 'aaaaa', 1704057575, 'pQECAyYgASFYIPQo25N4hFhcNGt2HFFHnEmOegOGtJYzpIM24_n9f_hwIlggWWv2IpfnmmIx_F33cohJ8Is7tSHwbU-qwZgtYW6MjGw', 'none', 'null', 15, 'utpVZqeqQB-9lkVhmlUSDQ', 0, 0, 'platform')`)
	require.NoError(t, err)

	return db
}

func TestSQLite_GetUserByX(t *testing.T) {
	db := buildTestDatabase(t)
	_, err := db.db.Exec(`INSERT INTO users (id, username, password, roles, admin, totp_seed, password_timestamp) VALUES ('65d453ce-ee95-4377-94cf-f7938ce4412f', 'badwebauthn', '$argon2id$v=19$m=32768,t=4,p=4$w4G65Zi1dnuQUYz/suyOc+593CQvP5IrpaJiOcEbDog$m7GySJ+XIwF6TzGUbfzx7vqzNCYAuGCpKkmNhIgr8vw', '["a","b"]', 0, 'JBSWY3DPEHPK3PXP', 1698000063)`)
	require.NoError(t, err)
	_, err = db.db.Exec(`INSERT INTO webauthn_keys (id, user_id, friendly_name, last_used, public_key, attestation_type, transports, flags, aaguid, sign_count, clone_warning, authenticator_attachment) VALUES ('ICSCHqqe14nQqUIXkBNtww!', '65d453ce-ee95-4377-94cf-f7938ce4412f', 'aaaaa', 1704057575, 'pQECAyYgASFYIPQo25N4hFhcNGt2HFFHnEmOegOGtJYzpIM24_n9f_hwIlggWWv2IpfnmmIx_F33cohJ8Is7tSHwbU-qwZgtYW6MjGw!', 'none', 'null', 15, 'utpVZqeqQB-9lkVhmlUSDQ!', 0, 0, 'platform')`)
	require.NoError(t, err)

	credentialIDBytes := []byte{32, 36, 130, 30, 170, 158, 215, 137, 208, 169, 66, 23, 144, 19, 109, 195}
	credentialPubKeyBytes := []byte{165, 1, 2, 3, 38, 32, 1, 33, 88, 32, 244, 40, 219, 147, 120, 132, 88, 92, 52, 107, 118, 28, 81, 71, 156, 73, 142, 122, 3, 134, 180, 150, 51, 164, 131, 54, 227, 249, 253, 127, 248, 112, 34, 88, 32, 89, 107, 246, 34, 151, 231, 154, 98, 49, 252, 93, 247, 114, 136, 73, 240, 139, 59, 181, 33, 240, 109, 79, 170, 193, 152, 45, 97, 110, 140, 140, 108}

	t.Run("by GUID -- happy path with credentials", func(t *testing.T) {
		u, err := db.GetUserByGuid(context.TODO(), "8744ac1b-9074-4a70-a202-5ad6d4a6e5e0")
		assert.NoError(t, err)
		assert.Equal(t, "8744ac1b-9074-4a70-a202-5ad6d4a6e5e0", u.Id)
		assert.Equal(t, "ben", u.Username)
		assert.Equal(t, "$argon2id$v=19$m=65536,t=3,p=2$f5DrCPQlwRJ5q1fA4K+i/g$c8XhJISMUI3wjIUULHvn0HIJinvOBBb4KnvOcvuJ4e0", u.PasswordHash)
		assert.Empty(t, u.Roles)
		assert.True(t, u.Admin)
		assert.Equal(t, int64(1704055267), u.PasswordTimestamp)
		require.Len(t, u.StoredCredentials, 1)

		assert.NotNil(t, u.StoredCredentials[0].FriendlyName)
		assert.Equal(t, "aaaaa", *u.StoredCredentials[0].FriendlyName)
		assert.Equal(t, credentialIDBytes, u.StoredCredentials[0].ID)
		assert.Equal(t, credentialPubKeyBytes, u.StoredCredentials[0].PublicKey)
	})

	t.Run("by GUID -- user with roles", func(t *testing.T) {
		u, err := db.GetUserByGuid(context.TODO(), "65d453ce-ee95-4377-94cf-f7938ce4412e")
		assert.NoError(t, err)

		assert.Equal(t, []string{"a", "b"}, u.Roles)
		assert.NotNil(t, u.TOTPSeed)
		assert.Equal(t, "JBSWY3DPEHPK3PXP", *u.TOTPSeed)
	})

	t.Run("by GUID -- user not found", func(t *testing.T) {
		u, err := db.GetUserByGuid(context.TODO(), "non-existing-user")
		assert.Nil(t, u)
		assert.NoError(t, err)
	})

	t.Run("by GUID -- bad credential decode", func(t *testing.T) {
		u, err := db.GetUserByGuid(context.TODO(), "65d453ce-ee95-4377-94cf-f7938ce4412f")
		assert.Nil(t, u)
		assert.Error(t, err)
	})

	t.Run("by username -- happy path", func(t *testing.T) {
		u, err := db.GetUserByUsername(context.TODO(), "ben")
		assert.NoError(t, err)
		assert.Equal(t, "8744ac1b-9074-4a70-a202-5ad6d4a6e5e0", u.Id)
		assert.Equal(t, "ben", u.Username)
		assert.Equal(t, "$argon2id$v=19$m=65536,t=3,p=2$f5DrCPQlwRJ5q1fA4K+i/g$c8XhJISMUI3wjIUULHvn0HIJinvOBBb4KnvOcvuJ4e0", u.PasswordHash)
		assert.Empty(t, u.Roles)
		assert.True(t, u.Admin)
		assert.Equal(t, int64(1704055267), u.PasswordTimestamp)
		require.Len(t, u.StoredCredentials, 1)

		assert.NotNil(t, u.StoredCredentials[0].FriendlyName)
		assert.Equal(t, "aaaaa", *u.StoredCredentials[0].FriendlyName)
		assert.Equal(t, credentialIDBytes, u.StoredCredentials[0].ID)
		assert.Equal(t, credentialPubKeyBytes, u.StoredCredentials[0].PublicKey)
	})

	t.Run("by username -- no user", func(t *testing.T) {
		u, err := db.GetUserByUsername(context.TODO(), "nouser")
		assert.NoError(t, err)
		assert.Nil(t, u)
	})

	t.Run("by credential -- valid credentials", func(t *testing.T) {
		uuidBytes := []byte{135, 68, 172, 27, 144, 116, 74, 112, 162, 2, 90, 214, 212, 166, 229, 224}
		u, err := db.FindUserByCredentialInfo(context.TODO(), credentialIDBytes, uuidBytes)
		assert.NoError(t, err)
		assert.Equal(t, "ben", u.Username)
	})

	t.Run("by credential -- credentials missing", func(t *testing.T) {
		uuidBytes := []byte{135, 68, 172, 27, 144, 116, 54, 112, 152, 2, 90, 214, 112, 166, 229, 224}
		u, err := db.FindUserByCredentialInfo(context.TODO(), []byte{1, 2, 3, 4, 5, 6, 7}, uuidBytes)
		assert.ErrorIs(t, err, sql.ErrNoRows)
		assert.Nil(t, u)
	})

	t.Run("find key by id", func(t *testing.T) {
		k, err := db.FindKeyById(context.TODO(), "ICSCHqqe14nQqUIXkBNtww")
		assert.NoError(t, err)

		assert.Equal(t, "aaaaa", *k.FriendlyName)
		assert.Equal(t, credentialIDBytes, k.ID)
		assert.Equal(t, credentialPubKeyBytes, k.PublicKey)
	})

	t.Run("find key by id doesn't eixst", func(t *testing.T) {
		_, err := db.FindKeyById(context.TODO(), "nononono")
		assert.ErrorIs(t, err, sql.ErrNoRows)
	})
}

func TestSQLite_UpdateKeyName(t *testing.T) {
	db := buildTestDatabase(t)

	t.Run("happy case", func(t *testing.T) {
		newName := "another_key"
		err := db.UpdateKeyName(context.TODO(), "ICSCHqqe14nQqUIXkBNtww", &newName)
		assert.NoError(t, err)

		var id string
		var name *string
		err = db.db.QueryRow("SELECT id, friendly_name FROM main.webauthn_keys WHERE id = $1", "ICSCHqqe14nQqUIXkBNtww").Scan(&id, &name)
		assert.NoError(t, err)
		assert.Equal(t, "ICSCHqqe14nQqUIXkBNtww", id)
		assert.Equal(t, newName, *name)
	})

	t.Run("set to nil", func(t *testing.T) {
		err := db.UpdateKeyName(context.TODO(), "ICSCHqqe14nQqUIXkBNtww", nil)
		assert.NoError(t, err)

		var id string
		var name *string
		err = db.db.QueryRow("SELECT id, friendly_name FROM main.webauthn_keys WHERE id = $1", "ICSCHqqe14nQqUIXkBNtww").Scan(&id, &name)
		assert.NoError(t, err)
		assert.Equal(t, "ICSCHqqe14nQqUIXkBNtww", id)
		assert.Nil(t, name)
	})

	t.Run("delete key", func(t *testing.T) {
		db2 := buildTestDatabase(t)

		err := db2.DeleteKey(context.TODO(), "ICSCHqqe14nQqUIXkBNtww")
		assert.NoError(t, err)

		var id string
		err = db2.db.QueryRow("SELECT id FROM main.webauthn_keys WHERE id = $1", "ICSCHqqe14nQqUIXkBNtww").Scan(&id)
		assert.ErrorIs(t, err, sql.ErrNoRows)

		err = db2.DeleteKey(context.TODO(), "ICSCHqqe14nQqUIXkBNtww")
		assert.Contains(t, err.Error(), "sqlite: DeleteKey: key not found")
	})
}

func TestSQLite_UpdateCredentialOnLogin(t *testing.T) {
	db := buildTestDatabase(t)

	k, err := db.FindKeyById(context.TODO(), "ICSCHqqe14nQqUIXkBNtww")
	assert.NoError(t, err)
	assert.Equal(t, uint32(0), k.Credential.Authenticator.SignCount)

	k.Credential.Authenticator.SignCount = 10
	err = db.UpdateCredentialOnLogin(context.TODO(), &k.Credential)
	assert.NoError(t, err)

	k, err = db.FindKeyById(context.TODO(), "ICSCHqqe14nQqUIXkBNtww")
	assert.NoError(t, err)

	assert.Equal(t, uint32(10), k.Credential.Authenticator.SignCount)
}

func TestSQLite_SaveCredentialForUser(t *testing.T) {
	db := buildTestDatabase(t)

	newCred := &webauthn.Credential{
		ID:              securecookie.GenerateRandomKey(16),
		PublicKey:       securecookie.GenerateRandomKey(32),
		AttestationType: "none",
		Transport:       nil,
		Flags: webauthn.CredentialFlags{
			UserPresent:    true,
			UserVerified:   true,
			BackupState:    true,
			BackupEligible: true,
		},
		Authenticator: webauthn.Authenticator{
			AAGUID:       securecookie.GenerateRandomKey(16),
			SignCount:    0,
			CloneWarning: false,
			Attachment:   "none",
		},
	}

	err := db.SaveCredentialForUser(context.TODO(), "8744ac1b-9074-4a70-a202-5ad6d4a6e5e0", newCred)
	assert.NoError(t, err)

	u, err := db.GetUserByGuid(context.TODO(), "8744ac1b-9074-4a70-a202-5ad6d4a6e5e0")
	assert.NoError(t, err)

	assert.Len(t, u.StoredCredentials, 2)

	var foundCred *webauthn.Credential
	for _, curr := range u.StoredCredentials {
		if bytes.Equal(curr.Credential.ID, newCred.ID) {
			foundCred = &curr.Credential
		}
	}
	assert.NotNil(t, foundCred)
}

func TestSQLite_DeleteUser(t *testing.T) {
	db := buildTestDatabase(t)

	t.Run("happy case", func(t *testing.T) {
		err := db.DeleteUser(context.TODO(), "8744ac1b-9074-4a70-a202-5ad6d4a6e5e0")
		assert.NoError(t, err)

		var count int
		err = db.db.QueryRow("SELECT COUNT(*) FROM users WHERE id = '8744ac1b-9074-4a70-a202-5ad6d4a6e5e0'").Scan(&count)
		assert.NoError(t, err)

		assert.Equal(t, 0, count)

		// make sure the key is deleted too
		err = db.db.QueryRow("SELECT COUNT(*) FROM webauthn_keys WHERE user_id = '8744ac1b-9074-4a70-a202-5ad6d4a6e5e0'").Scan(&count)
		assert.NoError(t, err)

		assert.Equal(t, 0, count)
	})

	t.Run("error on delete non existent user", func(t *testing.T) {
		err := db.DeleteUser(context.TODO(), "nononononono")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unable to delete, no rows affected")
	})
}

func TestSQLite_SaveUser(t *testing.T) {
	db := buildTestDatabase(t)

	t.Run("happy case", func(t *testing.T) {
		u, err := db.GetUserByGuid(context.TODO(), "65d453ce-ee95-4377-94cf-f7938ce4412e")
		assert.NoError(t, err)

		u.Roles = []string{"new", "roles", "end", "up", "here"}

		err = db.SaveUser(context.TODO(), u)
		assert.NoError(t, err)

		u2, err := db.GetUserByGuid(context.TODO(), "65d453ce-ee95-4377-94cf-f7938ce4412e")
		assert.NoError(t, err)

		assert.Len(t, u2.Roles, 5)
		assert.Equal(t, []string{"new", "roles", "end", "up", "here"}, u2.Roles)
	})

	t.Run("update non existent user", func(t *testing.T) {
		u := &user.User{
			Id:    "this-is-an-invalid-id",
			Roles: []string{},
		}
		err := db.SaveUser(context.TODO(), u)
		assert.ErrorIs(t, err, ErrNoUsersAffected)
	})
}

func TestSQLite_CreateUser(t *testing.T) {
	db := buildTestDatabase(t)

	t.Run("base case", func(t *testing.T) {
		u := &user.User{
			Id:                uuid.New().String(),
			Username:          "anewuser",
			PasswordHash:      "abcdefg",
			Roles:             []string{"a}"},
			Admin:             false,
			TOTPSeed:          nil,
			RecoveryCodes:     []string{},
			PasswordTimestamp: time.Now().Unix(),
		}
		err := db.CreateUser(context.TODO(), u)
		assert.NoError(t, err)

		u2, err := db.GetUserByUsername(context.TODO(), "anewuser")
		assert.NoError(t, err)

		assert.Equal(t, u.Username, u2.Username)
		assert.Equal(t, u.PasswordHash, u2.PasswordHash)
		assert.Equal(t, u.TOTPSeed, u2.TOTPSeed)
		assert.Equal(t, u.PasswordTimestamp, u2.PasswordTimestamp)
		assert.Equal(t, false, u.Disabled)
	})

	t.Run("duplicate username", func(t *testing.T) {
		u := &user.User{
			Id:                uuid.New().String(),
			Username:          "ben",
			PasswordHash:      "abcdefg",
			Roles:             []string{"a}"},
			Admin:             false,
			TOTPSeed:          nil,
			RecoveryCodes:     []string{},
			PasswordTimestamp: time.Now().Unix(),
		}

		err := db.CreateUser(context.TODO(), u)
		assert.Error(t, err)
	})
}

func TestSQLite_UpdateTOTPSeed(t *testing.T) {
	db := buildTestDatabase(t)

	t.Run("happy case", func(t *testing.T) {
		err := db.UpdateTOTPSeed(context.TODO(), "65d453ce-ee95-4377-94cf-f7938ce4412e", "ABCDEFG")
		assert.NoError(t, err)

		u, err := db.GetUserByGuid(context.TODO(), "65d453ce-ee95-4377-94cf-f7938ce4412e")
		assert.NoError(t, err)

		assert.Equal(t, "ABCDEFG", *u.TOTPSeed)
	})

	t.Run("user does not exist", func(t *testing.T) {
		err := db.UpdateTOTPSeed(context.TODO(), "abbbb", "ABCDEFG")
		assert.Error(t, err)
	})
}

func TestSQLite_GetAllUsers(t *testing.T) {
	db := buildTestDatabase(t)

	t.Run("happy case", func(t *testing.T) {
		users, err := db.GetAllUsers(context.TODO())
		assert.NoError(t, err)

		assert.Len(t, users, 2)
	})
}

func TestSQLite_UpdatePassword(t *testing.T) {
	db := buildTestDatabase(t)

	t.Run("basic stuff", func(t *testing.T) {
		u, err := db.GetUserByGuid(context.TODO(), "65d453ce-ee95-4377-94cf-f7938ce4412e")
		assert.NoError(t, err)

		err = u.SetPassword("newpassword")
		assert.NoError(t, err)

		err = db.UpdatePassword(context.TODO(), u)
		assert.NoError(t, err)

		u2, err := db.GetUserByGuid(context.TODO(), "65d453ce-ee95-4377-94cf-f7938ce4412e")
		assert.NoError(t, err)

		assert.NoError(t, argon.ValidatePassword("newpassword", u2.PasswordHash))
		assert.WithinDuration(t, time.Now(), time.Unix(u.PasswordTimestamp, 0), 2*time.Second)
	})
}

func TestFlags(t *testing.T) {
	tc := []struct {
		flags    webauthn.CredentialFlags
		expected int
	}{
		{
			flags: webauthn.CredentialFlags{
				UserPresent:    false,
				UserVerified:   false,
				BackupEligible: false,
				BackupState:    false,
			},
			expected: 0,
		},
		{
			flags: webauthn.CredentialFlags{
				UserPresent:    true,
				UserVerified:   true,
				BackupEligible: true,
				BackupState:    true,
			},
			expected: 15,
		},
		{
			flags: webauthn.CredentialFlags{
				UserPresent:    true,
				UserVerified:   true,
				BackupEligible: false,
				BackupState:    false,
			},
			expected: 12,
		},
	}

	for _, curr := range tc {
		e := encodeFlags(curr.flags)
		assert.Equal(t, curr.expected, e)
		d := decodeFlags(e)
		assert.Equal(t, curr.flags, d)
	}

}
