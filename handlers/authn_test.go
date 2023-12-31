package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/gorilla/securecookie"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/lthummus/auththingie2/middlewares/session"
	"github.com/lthummus/auththingie2/render"
	"github.com/lthummus/auththingie2/salt"
	"github.com/lthummus/auththingie2/user"
)

func TestWebAuthnFlow(t *testing.T) {
	setupSalts(t)
	render.Init()

	sc := securecookie.New(salt.GenerateSigningKey(), salt.GenerateEncryptionKey())

	t.Run("happy case", func(t *testing.T) {
		// create our relaying party data and a new authenticator
		rp := virtualwebauthn.RelyingParty{
			Name:   "example.com",
			ID:     "example.com",
			Origin: "https://example.com",
		}
		authenticator := virtualwebauthn.NewAuthenticator()

		// build test environment
		_, db, e := makeTestEnv(t)
		mux := e.BuildRouter()

		// call out to request a challenge for a new key
		r1 := makeTestRequest(t, http.MethodPost, "/webauthn/register", nil, passesCSRF(), withUser(sampleNonAdminUser, db))
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
		r2 := makeTestRequest(t, http.MethodPost, "/webauthn/finishregister", strings.NewReader(resp), passesCSRF(), withUser(sampleNonAdminUser, db), withCustomSession(func(s *session.Session) {
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
		assert.Equal(t, cred.Key.SigningKey.KeyData(), addedCredential.PublicKey)

		// create a test user with our new credential
		userWithCredential := *sampleNonAdminUser
		userWithCredential.StoredCredentials = append(userWithCredential.StoredCredentials, user.Passkey{
			Credential:   *addedCredential,
			FriendlyName: nil,
			LastUsed:     nil,
		})

		// attempt to log in -- get our challenge
		r3 := makeTestRequest(t, http.MethodPost, "/webauthn/discover", nil, passesCSRF())
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

		r4 := makeTestRequest(t, http.MethodPost, "/webauthn/finishdiscover", strings.NewReader(assertionResponse), passesCSRF(), withCustomSession(func(s *session.Session) {
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

}
