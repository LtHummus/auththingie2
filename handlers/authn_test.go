package handlers

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/descope/virtualwebauthn"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/gorilla/securecookie"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/lthummus/auththingie2/config"
	"github.com/lthummus/auththingie2/middlewares/session"
	"github.com/lthummus/auththingie2/render"
	"github.com/lthummus/auththingie2/salt"
	"github.com/lthummus/auththingie2/user"
)

var sampleCredential = webauthn.Credential{
	ID:              []byte{86, 7, 148, 97, 110, 70, 193, 56, 81, 75, 190, 23, 211, 102, 137, 71},
	PublicKey:       []byte{165, 1, 2, 3, 38, 32, 1, 33, 88, 32, 93, 166, 99, 29, 163, 204, 120, 247, 32, 174, 246, 70, 194, 51, 177, 15, 70, 183, 251, 124, 118, 45, 183, 79, 146, 29, 221, 234, 160, 47, 187, 236, 34, 88, 32, 75, 144, 209, 18, 170, 172, 69, 49, 211, 3, 238, 70, 62, 4, 28, 3, 120, 220, 85, 154, 189, 150, 127, 38, 167, 35, 144, 246, 66, 10, 155, 240},
	AttestationType: "",
	Transport:       nil,
	Flags: webauthn.CredentialFlags{
		UserPresent:    true,
		UserVerified:   true,
		BackupEligible: true,
		BackupState:    true,
	},
	Authenticator: webauthn.Authenticator{
		AAGUID:       []byte{186, 218, 85, 102, 167, 170, 64, 31, 189, 150, 69, 97, 154, 85, 18, 13},
		SignCount:    0,
		CloneWarning: false,
		Attachment:   protocol.Platform,
	},
}

func TestWebAuthnFlow(t *testing.T) {
	setupSalts(t)
	render.Init()

	sc := securecookie.New(salt.GenerateSigningKey(), salt.GenerateEncryptionKey())

	rp := virtualwebauthn.RelyingParty{
		Name:   "example.com",
		ID:     "example.com",
		Origin: "https://example.com",
	}

	t.Run("happy case", func(t *testing.T) {
		authenticator := virtualwebauthn.NewAuthenticator()

		// build test environment
		_, db, _, e := makeTestEnv(t)
		mux := e.BuildRouter()

		// call out to request a challenge for a new key
		r1 := makeTestRequest(t, http.MethodPost, "/webauthn/register", nil, withUser(sampleNonAdminUser, db))
		w1 := httptest.NewRecorder()

		mux.ServeHTTP(w1, r1)

		// make sure the call succeeded
		assert.Equal(t, http.StatusOK, w1.Result().StatusCode)
		assert.Len(t, w1.Result().Cookies(), 1)
		var sess *session.Session
		err := sc.Decode(session.SessionCookieName, w1.Result().Cookies()[0].Value, &sess)
		assert.NoError(t, err)

		// use the response data to generate some attestation options
		opts, err := virtualwebauthn.ParseAttestationOptions(w1.Body.String())
		assert.NoError(t, err)
		assert.NotNil(t, opts)

		authenticator.Options.UserHandle = []byte(opts.UserID)

		// create a new credential and generate a response
		cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
		resp := virtualwebauthn.CreateAttestationResponse(rp, authenticator, cred, *opts)
		authenticator.AddCredential(cred)

		// make sure we call the save
		db.On("SaveCredentialForUser", mock.Anything, sampleNonAdminUser.Id, mock.AnythingOfType("*webauthn.Credential")).Return(nil)

		// finish up the registration
		r2 := makeTestRequest(t, http.MethodPost, "/webauthn/finishregister", strings.NewReader(resp), withUser(sampleNonAdminUser, db), withCustomSession(func(s *session.Session) {
			s.CustomData = sess.CustomData
		}))
		r2.AddCookie(w1.Result().Cookies()[0])
		w2 := httptest.NewRecorder()

		mux.ServeHTTP(w2, r2)

		// make sure that everything worked
		assert.Equal(t, http.StatusOK, w2.Result().StatusCode)
		assert.Equal(t, `{"failed":false}`, w2.Body.String())

		addedCredential := db.Mock.Calls[2].Arguments[2].(*webauthn.Credential)

		assert.Equal(t, cred.ID, addedCredential.ID)

		// create a test user with our new credential
		userWithCredential := *sampleNonAdminUser
		userWithCredential.StoredCredentials = append(userWithCredential.StoredCredentials, user.Passkey{
			Credential:   *addedCredential,
			FriendlyName: nil,
			LastUsed:     nil,
		})

		// attempt to log in -- get our challenge
		r3 := makeTestRequest(t, http.MethodPost, "/webauthn/discover", nil)
		w3 := httptest.NewRecorder()

		mux.ServeHTTP(w3, r3)

		assert.Equal(t, http.StatusOK, w3.Result().StatusCode)
		err = sc.Decode(session.SessionCookieName, w3.Result().Cookies()[0].Value, &sess)
		assert.NoError(t, err)

		assertOptions, err := virtualwebauthn.ParseAssertionOptions(w3.Body.String())
		assert.NoError(t, err)
		assert.NotNil(t, assertOptions)

		// sign the challenge and send the response
		assertionResponse := virtualwebauthn.CreateAssertionResponse(rp, authenticator, cred, *assertOptions)

		// handle the response
		db.On("FindUserByCredentialInfo", mock.Anything, mock.AnythingOfType("[]uint8"), mock.AnythingOfType("[]uint8")).Return(&userWithCredential, nil)
		db.On("UpdateCredentialOnLogin", mock.Anything, mock.AnythingOfType("*webauthn.Credential")).Return(nil)

		r4 := makeTestRequest(t, http.MethodPost, "/webauthn/finishdiscover", strings.NewReader(assertionResponse), withCustomSession(func(s *session.Session) {
			s.CustomData = sess.CustomData
		}))
		w4 := httptest.NewRecorder()

		mux.ServeHTTP(w4, r4)

		// make sure we're logged in
		assert.Equal(t, http.StatusOK, w4.Result().StatusCode)

		assert.Len(t, w4.Result().Cookies(), 1)

		err = sc.Decode(session.SessionCookieName, w4.Result().Cookies()[0].Value, &sess)
		assert.NoError(t, err)

		assert.Equal(t, sampleNonAdminUser.Id, sess.UserID)
		assert.WithinDuration(t, time.Now(), sess.LoginTime, 1*time.Second)
	})

	// TODO: tons of duplicated code between this and the previous test, see if we can't refactor it a bit
	t.Run("disbaled user should not be able to log in", func(t *testing.T) {
		authenticator := virtualwebauthn.NewAuthenticator()

		// build test environment
		_, db, _, e := makeTestEnv(t)
		mux := e.BuildRouter()

		// call out to request a challenge for a new key
		r1 := makeTestRequest(t, http.MethodPost, "/webauthn/register", nil, withUser(sampleDisabledUser, db))
		w1 := httptest.NewRecorder()

		mux.ServeHTTP(w1, r1)

		// make sure the call succeeded
		assert.Equal(t, http.StatusOK, w1.Result().StatusCode)
		assert.Len(t, w1.Result().Cookies(), 1)
		var sess *session.Session
		err := sc.Decode(session.SessionCookieName, w1.Result().Cookies()[0].Value, &sess)
		assert.NoError(t, err)

		// use the response data to generate some attestation options
		opts, err := virtualwebauthn.ParseAttestationOptions(w1.Body.String())
		assert.NoError(t, err)
		assert.NotNil(t, opts)

		authenticator.Options.UserHandle = []byte(opts.UserID)

		// create a new credential and generate a response
		cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
		resp := virtualwebauthn.CreateAttestationResponse(rp, authenticator, cred, *opts)
		authenticator.AddCredential(cred)

		// make sure we call the save
		db.On("SaveCredentialForUser", mock.Anything, sampleDisabledUser.Id, mock.AnythingOfType("*webauthn.Credential")).Return(nil)

		// finish up the registration
		r2 := makeTestRequest(t, http.MethodPost, "/webauthn/finishregister", strings.NewReader(resp), withUser(sampleDisabledUser, db), withCustomSession(func(s *session.Session) {
			s.CustomData = sess.CustomData
		}))
		r2.AddCookie(w1.Result().Cookies()[0])
		w2 := httptest.NewRecorder()

		mux.ServeHTTP(w2, r2)

		// make sure that everything worked
		assert.Equal(t, http.StatusOK, w2.Result().StatusCode)
		assert.Equal(t, `{"failed":false}`, w2.Body.String())

		addedCredential := db.Mock.Calls[2].Arguments[2].(*webauthn.Credential)

		assert.Equal(t, cred.ID, addedCredential.ID)

		// create a test user with our new credential
		userWithCredential := *sampleDisabledUser
		userWithCredential.StoredCredentials = append(userWithCredential.StoredCredentials, user.Passkey{
			Credential:   *addedCredential,
			FriendlyName: nil,
			LastUsed:     nil,
		})

		// attempt to log in -- get our challenge
		r3 := makeTestRequest(t, http.MethodPost, "/webauthn/discover", nil)
		w3 := httptest.NewRecorder()

		mux.ServeHTTP(w3, r3)

		assert.Equal(t, http.StatusOK, w3.Result().StatusCode)
		err = sc.Decode(session.SessionCookieName, w3.Result().Cookies()[0].Value, &sess)
		assert.NoError(t, err)

		assertOptions, err := virtualwebauthn.ParseAssertionOptions(w3.Body.String())
		assert.NoError(t, err)
		assert.NotNil(t, assertOptions)

		// sign the challenge and send the response
		assertionResponse := virtualwebauthn.CreateAssertionResponse(rp, authenticator, cred, *assertOptions)

		// handle the response
		db.On("FindUserByCredentialInfo", mock.Anything, mock.AnythingOfType("[]uint8"), mock.AnythingOfType("[]uint8")).Return(&userWithCredential, nil)
		db.On("UpdateCredentialOnLogin", mock.Anything, mock.AnythingOfType("*webauthn.Credential")).Return(nil)

		r4 := makeTestRequest(t, http.MethodPost, "/webauthn/finishdiscover", strings.NewReader(assertionResponse), withCustomSession(func(s *session.Session) {
			s.CustomData = sess.CustomData
		}))
		w4 := httptest.NewRecorder()

		mux.ServeHTTP(w4, r4)

		assert.Equal(t, http.StatusForbidden, w4.Result().StatusCode)
		assert.Equal(t, `{"message":"Account is disabled","error_code":"authn.login.disabled","failed":true}`, w4.Body.String())
	})

	t.Run("log in with key not found", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)
		mux := e.BuildRouter()

		r1 := makeTestRequest(t, http.MethodPost, "/webauthn/discover", nil)
		w1 := httptest.NewRecorder()

		mux.ServeHTTP(w1, r1)

		assert.Equal(t, http.StatusOK, w1.Result().StatusCode)
		var sess session.Session
		err := sc.Decode(session.SessionCookieName, w1.Result().Cookies()[0].Value, &sess)
		assert.NoError(t, err)

		authenticator := virtualwebauthn.NewAuthenticator()
		authenticator.Options.UserHandle = []byte{0x01, 0x02, 0x03, 0x04, 0x05}

		cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
		authenticator.AddCredential(cred)

		assertOptions, err := virtualwebauthn.ParseAssertionOptions(w1.Body.String())
		assert.NoError(t, err)
		assert.NotNil(t, assertOptions)

		assertionResponse := virtualwebauthn.CreateAssertionResponse(rp, authenticator, cred, *assertOptions)

		r2 := makeTestRequest(t, http.MethodPost, "/webauthn/finishdiscover", strings.NewReader(assertionResponse), withCustomSession(func(s *session.Session) {
			s.CustomData = sess.CustomData
		}))
		w2 := httptest.NewRecorder()

		db.On("FindUserByCredentialInfo", mock.Anything, mock.AnythingOfType("[]uint8"), mock.AnythingOfType("[]uint8")).Return(nil, sql.ErrNoRows)

		mux.ServeHTTP(w2, r2)

		assert.Equal(t, http.StatusForbidden, w2.Result().StatusCode)
		assert.Contains(t, w2.Body.String(), "Key not registered to any user")
		assert.Contains(t, w2.Body.String(), "authn.login.unrecognized_key")

		passedUserHandle := db.Mock.Calls[0].Arguments[2].([]byte)
		assert.Equal(t, []byte{0x01, 0x02, 0x03, 0x04, 0x05}, passedUserHandle)

		passedCredentialID := db.Mock.Calls[0].Arguments[1].([]byte)
		assert.Equal(t, cred.ID, passedCredentialID)

		assert.Empty(t, w2.Result().Cookies())
	})
}

func TestEnv_HandleWebAuthnBeginRegistration(t *testing.T) {
	setupSalts(t)
	render.Init()

	sc := securecookie.New(salt.GenerateSigningKey(), salt.GenerateEncryptionKey())

	t.Run("fail if passkeys is disabled", func(t *testing.T) {
		viper.Set(config.KeyPasskeysDisabled, true)
		t.Cleanup(func() {
			viper.Set(config.KeyPasskeysDisabled, false)
		})

		_, _, _, e := makeTestEnv(t)
		mux := e.BuildRouter()

		r := makeTestRequest(t, http.MethodPost, "/webauthn/register", nil)
		w := httptest.NewRecorder()

		mux.ServeHTTP(w, r)

		assert.Equal(t, http.StatusUnauthorized, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "Passkeys are disabled")
	})

	t.Run("fail if not logged in", func(t *testing.T) {
		_, _, _, e := makeTestEnv(t)
		mux := e.BuildRouter()

		r := makeTestRequest(t, http.MethodPost, "/webauthn/register", nil)
		w := httptest.NewRecorder()

		mux.ServeHTTP(w, r)

		assert.Equal(t, http.StatusForbidden, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "authn.enroll.not_logged_in")
	})

	t.Run("get payload if everything went ok", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)
		mux := e.BuildRouter()

		r := makeTestRequest(t, http.MethodPost, "/webauthn/register", nil, withUser(sampleNonAdminUser, db))
		w := httptest.NewRecorder()

		mux.ServeHTTP(w, r)

		var createResponse *protocol.CredentialCreation

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		err := json.NewDecoder(w.Result().Body).Decode(&createResponse)
		assert.NoError(t, err)

		assert.Equal(t, "example.com", createResponse.Response.RelyingParty.Name)
		assert.Equal(t, "example.com", createResponse.Response.RelyingParty.ID)
		assert.Equal(t, sampleNonAdminUser.Username, createResponse.Response.User.Name)
		assert.Equal(t, sampleNonAdminUser.Username, createResponse.Response.User.DisplayName)

		decodedID, err := base64.RawURLEncoding.DecodeString(createResponse.Response.User.ID.(string))
		assert.NoError(t, err)

		idFromResponse, err := uuid.FromBytes(decodedID)
		assert.NoError(t, err)

		decodedChallenge, err := base64.RawURLEncoding.DecodeString(createResponse.Response.Challenge.String())
		assert.NoError(t, err)

		assert.Len(t, decodedChallenge, 32)
		assert.Equal(t, sampleNonAdminUser.Id, idFromResponse.String())

		assert.Len(t, w.Result().Cookies(), 1)
		var sess session.Session
		err = sc.Decode(session.SessionCookieName, w.Result().Cookies()[0].Value, &sess)
		assert.NoError(t, err)

		assert.NotNil(t, sess.CustomData[authenticationIDSessionKey])
	})
}

func TestEnv_HandleWebAuthnBeginDiscoverableLogin(t *testing.T) {
	setupSalts(t)
	render.Init()

	// sc := securecookie.New(salt.GenerateSigningKey(), salt.GenerateEncryptionKey())

	t.Run("fail if passkeys is disabled", func(t *testing.T) {
		viper.Set(config.KeyPasskeysDisabled, true)
		t.Cleanup(func() {
			viper.Set(config.KeyPasskeysDisabled, false)
		})

		_, _, _, e := makeTestEnv(t)
		mux := e.BuildRouter()

		r := makeTestRequest(t, http.MethodPost, "/webauthn/discover", nil)
		w := httptest.NewRecorder()

		mux.ServeHTTP(w, r)

		assert.Equal(t, http.StatusNotFound, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "Passkeys are disabled")
	})

	t.Run("fail if already logged in", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)
		mux := e.BuildRouter()

		r := makeTestRequest(t, http.MethodPost, "/webauthn/discover", nil, withUser(sampleNonAdminUser, db))
		w := httptest.NewRecorder()

		mux.ServeHTTP(w, r)

		assert.Equal(t, http.StatusForbidden, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "You are already logged in")
	})

	t.Run("all data is good if everything goes ok", func(t *testing.T) {
		_, _, _, e := makeTestEnv(t)
		mux := e.BuildRouter()

		r := makeTestRequest(t, http.MethodPost, "/webauthn/discover", nil)
		w := httptest.NewRecorder()

		mux.ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)

		var challengeData *protocol.CredentialAssertion
		err := json.NewDecoder(w.Result().Body).Decode(&challengeData)
		assert.NoError(t, err)

		assert.Equal(t, "example.com", challengeData.Response.RelyingPartyID)
		assert.Equal(t, protocol.VerificationPreferred, challengeData.Response.UserVerification)

		decodedChallenge, err := base64.RawURLEncoding.DecodeString(challengeData.Response.Challenge.String())
		assert.NoError(t, err)

		assert.Len(t, decodedChallenge, 32)
	})
}

func TestEnv_HandleRenderWebAuthnManage(t *testing.T) {
	setupSalts(t)
	render.Init()

	t.Run("fail if passkeys disabled", func(t *testing.T) {
		viper.Set(config.KeyPasskeysDisabled, true)
		t.Cleanup(func() {
			viper.Set(config.KeyPasskeysDisabled, false)
		})

		_, _, _, e := makeTestEnv(t)
		mux := e.BuildRouter()

		r := makeTestRequest(t, http.MethodPost, "/webauthn/manage", nil)
		w := httptest.NewRecorder()

		mux.ServeHTTP(w, r)

		assert.Equal(t, http.StatusNotFound, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "404 Not Found")
	})

	t.Run("fail if not logged in", func(t *testing.T) {
		_, _, _, e := makeTestEnv(t)
		mux := e.BuildRouter()

		r := makeTestRequest(t, http.MethodPost, "/webauthn/manage", nil)
		w := httptest.NewRecorder()

		mux.ServeHTTP(w, r)

		assert.Equal(t, http.StatusForbidden, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "you must be logged in for this")
	})

	t.Run("work if user has no keys", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)
		mux := e.BuildRouter()

		r := makeTestRequest(t, http.MethodPost, "/webauthn/manage", nil, withUser(sampleNonAdminUser, db))
		w := httptest.NewRecorder()

		mux.ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), `<button id="passkey-enroll-button" onclick="beginRegistration()">Enroll New Key</button>`)
	})

	t.Run("work if user has some keys", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)
		mux := e.BuildRouter()

		r := makeTestRequest(t, http.MethodPost, "/webauthn/manage", nil, withUser(sampleNonAdminWithCredentials, db))
		w := httptest.NewRecorder()

		mux.ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), `<button id="passkey-enroll-button" onclick="beginRegistration()">Enroll New Key</button>`)
		assert.Contains(t, w.Body.String(), `<td>VgeUYW5GwThRS74X02aJRw</td>`)
		assert.Contains(t, w.Body.String(), `<td><button hx-delete="/webauthn/keys/VgeUYW5GwThRS74X02aJRw" hx-on:click="clearWebauthnError()" hx-confirm="Are you sure?" class="contrast">Delete Key</button></td>`)
		assert.Contains(t, w.Body.String(), `<td><button hx-get="/webauthn/keys/VgeUYW5GwThRS74X02aJRw/edit" hx-on:click="clearWebauthnError()">Edit Friendly Name</button></td>`)
	})
}

func TestEnv_HandleWebAuthnEditKey(t *testing.T) {
	setupSalts(t)
	render.Init()

	t.Run("not logged in", func(t *testing.T) {
		_, _, _, e := makeTestEnv(t)
		mux := e.BuildRouter()

		r := makeTestRequest(t, http.MethodGet, "/webauthn/keys/VgeUYW5GwThRS74X02aJRw", nil, isHTMXRequest())
		w := httptest.NewRecorder()

		mux.ServeHTTP(w, r)

		assert.Equal(t, http.StatusUnprocessableEntity, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), `<div id="modify-error" class="error-box ">You must be logged in to do this</div>`)
		assert.Equal(t, "#modify-error", w.Header().Get("HX-Retarget"))
		assert.Equal(t, "outerHTML", w.Header().Get("HX-Reswap"))
	})

	t.Run("does not own key", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)
		mux := e.BuildRouter()

		r := makeTestRequest(t, http.MethodGet, "/webauthn/keys/VgeUYW5GwThRS74X02aJRw", nil, withUser(sampleNonAdminUser, db), isHTMXRequest())
		w := httptest.NewRecorder()

		mux.ServeHTTP(w, r)

		assert.Equal(t, http.StatusUnprocessableEntity, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "Could not find key with id VgeUYW5GwThRS74X02aJRw")
		assert.NotEmpty(t, w.Header().Get("HX-Retarget"))
	})

	t.Run("key not found", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)
		mux := e.BuildRouter()

		r := makeTestRequest(t, http.MethodGet, "/webauthn/keys/aaaaaaa", nil, withUser(sampleNonAdminUser, db), isHTMXRequest())
		w := httptest.NewRecorder()

		mux.ServeHTTP(w, r)

		assert.Equal(t, http.StatusUnprocessableEntity, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "Could not find key with id aaaaaaa")
		assert.NotEmpty(t, w.Header().Get("HX-Retarget"))
	})

	t.Run("renders non-editable row", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)
		mux := e.BuildRouter()

		db.On("FindKeyById", mock.Anything, "VgeUYW5GwThRS74X02aJRw").Return(user.Passkey{
			Credential: sampleCredential,
		}, nil)

		r := makeTestRequest(t, http.MethodGet, "/webauthn/keys/VgeUYW5GwThRS74X02aJRw", nil, withUser(sampleNonAdminWithCredentials, db), isHTMXRequest())
		w := httptest.NewRecorder()

		mux.ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "<td>VgeUYW5GwThRS74X02aJRw</td>")
		assert.Contains(t, w.Body.String(), `<td><button hx-get="/webauthn/keys/VgeUYW5GwThRS74X02aJRw/edit" hx-on:click="clearWebauthnError()">Edit Friendly Name</button></td>`)
	})

	t.Run("renders editable row", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)
		mux := e.BuildRouter()

		db.On("FindKeyById", mock.Anything, "VgeUYW5GwThRS74X02aJRw").Return(user.Passkey{
			Credential: sampleCredential,
		}, nil)

		r := makeTestRequest(t, http.MethodGet, "/webauthn/keys/VgeUYW5GwThRS74X02aJRw/edit", nil, withUser(sampleNonAdminWithCredentials, db), isHTMXRequest())
		w := httptest.NewRecorder()

		mux.ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), `<input name="name" value="" />`)
		assert.Contains(t, w.Body.String(), `<button hx-put="/webauthn/keys/VgeUYW5GwThRS74X02aJRw" hx-include="closest tr" hx-on:click="clearWebauthnError()">Save</button></td>`)
	})

	t.Run("delete key", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)
		mux := e.BuildRouter()

		db.On("FindKeyById", mock.Anything, "VgeUYW5GwThRS74X02aJRw").Return(user.Passkey{
			Credential: sampleCredential,
		}, nil)
		db.On("DeleteKey", mock.Anything, "VgeUYW5GwThRS74X02aJRw").Return(nil)

		r := makeTestRequest(t, http.MethodDelete, "/webauthn/keys/VgeUYW5GwThRS74X02aJRw", nil, withUser(sampleNonAdminWithCredentials, db), isHTMXRequest())
		w := httptest.NewRecorder()

		mux.ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
	})

	t.Run("error on delete key", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)
		mux := e.BuildRouter()

		db.On("FindKeyById", mock.Anything, "VgeUYW5GwThRS74X02aJRw").Return(user.Passkey{
			Credential: sampleCredential,
		}, nil)
		db.On("DeleteKey", mock.Anything, "VgeUYW5GwThRS74X02aJRw").Return(errors.New("nope not allowed"))

		r := makeTestRequest(t, http.MethodDelete, "/webauthn/keys/VgeUYW5GwThRS74X02aJRw", nil, withUser(sampleNonAdminWithCredentials, db), isHTMXRequest())
		w := httptest.NewRecorder()

		mux.ServeHTTP(w, r)

		assert.Equal(t, http.StatusUnprocessableEntity, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "Could not delete key:")
	})

	t.Run("update key name", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)
		mux := e.BuildRouter()

		db.On("FindKeyById", mock.Anything, "VgeUYW5GwThRS74X02aJRw").Return(user.Passkey{
			Credential: sampleCredential,
		}, nil)
		name := "some name"
		db.On("UpdateKeyName", mock.Anything, "VgeUYW5GwThRS74X02aJRw", &name).Return(nil)

		v := url.Values{}
		v.Add("name", name)

		r := makeTestRequest(t, http.MethodPut, "/webauthn/keys/VgeUYW5GwThRS74X02aJRw", strings.NewReader(v.Encode()), withUser(sampleNonAdminWithCredentials, db), isHTMXRequest())
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		mux.ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
	})

	t.Run("update key name db error", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)
		mux := e.BuildRouter()

		db.On("FindKeyById", mock.Anything, "VgeUYW5GwThRS74X02aJRw").Return(user.Passkey{
			Credential: sampleCredential,
		}, nil)
		name := "some name"
		db.On("UpdateKeyName", mock.Anything, "VgeUYW5GwThRS74X02aJRw", &name).Return(errors.New("couldn't do it"))

		v := url.Values{}
		v.Add("name", name)

		r := makeTestRequest(t, http.MethodPut, "/webauthn/keys/VgeUYW5GwThRS74X02aJRw", strings.NewReader(v.Encode()), withUser(sampleNonAdminWithCredentials, db), isHTMXRequest())
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		mux.ServeHTTP(w, r)

		assert.Equal(t, http.StatusUnprocessableEntity, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "Could not modify key:")
	})

}

func TestEnv_GetEnrolledPasskeyKeyIDs(t *testing.T) {
	setupSalts(t)
	render.Init()

	t.Run("happy case", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)
		mux := e.BuildRouter()

		r := makeTestRequest(t, http.MethodGet, "/webauthn/keys", nil, withUser(sampleNonAdminWithCredentials, db), isHTMXRequest())
		w := httptest.NewRecorder()

		mux.ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)

		var payload struct {
			Keys []string `json:"keys"`
		}
		err := json.NewDecoder(w.Result().Body).Decode(&payload)
		require.NoError(t, err)

		require.Len(t, payload.Keys, 1)
		assert.Equal(t, "VgeUYW5GwThRS74X02aJRw==", payload.Keys[0])
	})

	t.Run("with multiple passkeys", func(t *testing.T) {
		_, db, _, e := makeTestEnv(t)
		mux := e.BuildRouter()

		r := makeTestRequest(t, http.MethodGet, "/webauthn/keys", nil, withUser(sampleNonAdminWithMultiplePasskeys, db), isHTMXRequest())
		w := httptest.NewRecorder()

		mux.ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)

		var payload struct {
			Keys []string `json:"keys"`
		}
		err := json.NewDecoder(w.Result().Body).Decode(&payload)
		require.NoError(t, err)

		require.Len(t, payload.Keys, 2)
		assert.Equal(t, "VgeUYW5GwThRS74X02aJRw==", payload.Keys[0])
		assert.Equal(t, "tVfcIye/f4wewg8/z/WmOw==", payload.Keys[1])
	})

	t.Run("not logged in", func(t *testing.T) {
		_, _, _, e := makeTestEnv(t)
		mux := e.BuildRouter()

		r := makeTestRequest(t, http.MethodGet, "/webauthn/keys", nil, isHTMXRequest())
		w := httptest.NewRecorder()

		mux.ServeHTTP(w, r)

		assert.Equal(t, http.StatusUnprocessableEntity, w.Result().StatusCode)
		assert.Contains(t, w.Body.String(), "must be logged in")
		assert.Equal(t, "#modify-error", w.Header().Get("HX-Retarget"))
		assert.Equal(t, "outerHTML", w.Header().Get("HX-Reswap"))
	})
}
