package handlers

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/gorilla/securecookie"
	"github.com/jellydator/ttlcache/v3"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"

	"github.com/lthummus/auththingie2/internal/config"
	"github.com/lthummus/auththingie2/internal/middlewares/session"
	"github.com/lthummus/auththingie2/internal/render"
	"github.com/lthummus/auththingie2/internal/trueip"
	"github.com/lthummus/auththingie2/internal/user"
)

const (
	authenticationIDSessionKey = "web_authn_registration_id"
)

var sessionCache = ttlcache.New[string, *webauthn.SessionData](ttlcache.WithTTL[string, *webauthn.SessionData](10 * time.Minute))

func init() {
	log.Info().Msg("starting AuthN TTL cache cleanup thread")
	go sessionCache.Start()
}

func (e *Env) HandleWebAuthnBeginRegistration(w http.ResponseWriter, r *http.Request) {
	if viper.GetBool(config.KeyPasskeysDisabled) {
		log.Warn().Msg("attempted to begin passkey registration when passkeys disabled")
		http.Error(w, "Passkeys are disabled", http.StatusUnauthorized)
		return
	}

	u := session.GetUserFromRequest(r)
	if u == nil {
		render.RenderJSONError(w, "You must be logged in to enroll keys", "authn.enroll.not_logged_in", http.StatusForbidden)
		return
	}

	s := session.GetSessionFromRequest(r)
	authId := generateAuthID()
	s.CustomData[authenticationIDSessionKey] = authId

	err := session.WriteSession(w, r, s)
	if err != nil {
		log.Error().Err(err).Msg("could not update session")
		render.RenderJSONError(w, "Could not update user session", "authn.enroll.could_not_update_session", http.StatusInternalServerError)
		return
	}

	var excluded []protocol.CredentialDescriptor
	for _, curr := range u.StoredCredentials {
		excluded = append(excluded, protocol.CredentialDescriptor{
			Type:         "public-key",
			CredentialID: curr.ID,
		})
	}

	creation, sessionData, err := e.WebAuthn.BeginRegistration(u, webauthn.WithExclusions(excluded))
	if err != nil {
		log.Error().Err(err).Msg("could not create registration data")
		render.RenderJSONError(w, "Could not genereate registration challenge", "authn.enroll.could_not_gen_challenge", http.StatusInternalServerError)
		return
	}

	sessionCache.Set(authId, sessionData, ttlcache.DefaultTTL)

	data, err := json.Marshal(creation)
	if err != nil {
		log.Error().Err(err).Msg("could not serialize registration data")
		render.RenderJSONError(w, "Could not serialize registration challenge", "authn.enroll.serialization_failure", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, err = w.Write(data)
	if err != nil {
		log.Error().Caller(0).Err(err).Msg("could not write webauthn registration data to response")
	}
}

func (e *Env) HandleWebAuthnFinishRegistration(w http.ResponseWriter, r *http.Request) {
	log.Trace().Msg("inside HandleWebAuthnFinishRegistration")
	u := session.GetUserFromRequest(r)
	if u == nil {
		http.Error(w, "must be logged in to do this", http.StatusForbidden)
		return
	}

	response, err := protocol.ParseCredentialCreationResponse(r)
	if err != nil {
		log.Error().Err(err).Msg("could not parse response")
		http.Error(w, "could not parse response", http.StatusBadRequest)
		return
	}

	authID, err := getAuthID(r)
	if err != nil {
		log.Warn().Err(err).Msg("could not get auth id")
		http.Error(w, "could not get auth id", http.StatusBadRequest)
		return
	}

	sessionData := sessionCache.Get(authID).Value()

	credential, err := e.WebAuthn.CreateCredential(u, *sessionData, response)
	if err != nil {
		log.Error().Err(err).Msg("could not create credential")
		http.Error(w, "could not create credential", http.StatusInternalServerError)
		return
	}

	err = e.Database.SaveCredentialForUser(r.Context(), u.Id, credential)
	if err != nil {
		http.Error(w, "could not persist credential", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, err = w.Write([]byte(`{"failed":false}`))
	if err != nil {
		log.Error().Caller(0).Err(err).Msg("could not write webauthn registration result to response")
	}
}

func (e *Env) HandleWebAuthnBeginDiscoverableLogin(w http.ResponseWriter, r *http.Request) {
	if viper.GetBool(config.KeyPasskeysDisabled) {
		log.Warn().Msg("attempted to begin passkey signin when passkeys disabled")
		http.Error(w, "Passkeys are disabled", http.StatusNotFound)
		return
	}

	u := session.GetUserFromRequest(r)
	if u != nil {
		render.RenderJSONError(w, "You are already logged in", "authn.login.already_logged_in", http.StatusForbidden)
		return
	}

	res, sess, err := e.WebAuthn.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationPreferred))
	if err != nil {
		log.Error().Err(err).Msg("could not create discoverable login payload")
		render.RenderJSONError(w, "Could not create login challenge", "authn.login.could_not_create_challenge", http.StatusInternalServerError)
		return
	}

	authID := generateAuthID()
	sessionCache.Set(authID, sess, ttlcache.DefaultTTL)

	s := session.GetSessionFromRequest(r)
	s.CustomData[authenticationIDSessionKey] = authID
	err = session.WriteSession(w, r, s)
	if err != nil {
		log.Warn().Err(err).Msg("could not write session data")
		render.RenderJSONError(w, "Could not write session data", "authn.login.could_not_write_session", http.StatusInternalServerError)
		return
	}

	data, err := json.Marshal(res)
	if err != nil {
		log.Error().Err(err).Msg("could not serialize challenge")
		render.RenderJSONError(w, "Could not serialize challenge", "authn.login.could_not_serialize", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, err = w.Write(data)
	if err != nil {
		log.Error().Caller(0).Err(err).Msg("could not write webauthn login challenge to response")
	}
}

func (e *Env) HandleWebAuthnFinishDiscoverableLogin(w http.ResponseWriter, r *http.Request) {
	response, err := protocol.ParseCredentialRequestResponse(r)
	if err != nil {
		log.Error().Err(err).Msg("could not parse response")
		render.RenderJSONError(w, "Could not parse response", "authn.login.bad_parse", http.StatusBadRequest)
		return
	}

	authID, err := getAuthID(r)
	if err != nil {
		log.Warn().Err(err).Msg("could not get auth id")
		render.RenderJSONError(w, "Could not get auth session id", "authn.login.no_auth_session", http.StatusBadRequest)
		return
	}

	sessData := sessionCache.Get(authID).Value()
	var foundUser *user.User

	cred, err := e.WebAuthn.ValidateDiscoverableLogin(func(rid, handle []byte) (webauthn.User, error) {
		// rid = key id
		// handle = guid
		u, err := e.Database.FindUserByCredentialInfo(r.Context(), rid, handle)
		if err == nil {
			foundUser = u
		}
		return u, err
	}, *sessData, response)
	if err != nil {
		// TODO: maybe refactor this error handling logic
		if strings.Contains(err.Error(), "no rows in result set") {
			log.Warn().Str("ip", trueip.Find(r)).Msg("bad passkey attempt")
			render.RenderJSONError(w, "Key not registered to any user", "authn.login.unrecognized_key", http.StatusForbidden)
			return
		}
		log.Warn().Err(err).Str("ip", trueip.Find(r)).Msg("could not validate credential")
		render.RenderJSONError(w, "Could not validate credential", "authn.login.could_not_validate", http.StatusInternalServerError)
		return
	}

	if foundUser == nil {
		log.Warn().Str("ip", trueip.Find(r)).Msg("could not find user with that key")
		http.Error(w, "could not find user with that key", http.StatusForbidden)
		return
	}

	log.Info().Str("username", foundUser.Username).Msg("logged in via passkey")

	err = e.Database.UpdateCredentialOnLogin(r.Context(), cred)
	if err != nil {
		log.Warn().Err(err).Msg("could not update key info on login")
	}

	if foundUser.Disabled {
		log.Warn().Str("ip", trueip.Find(r)).Str("username", foundUser.Username).Msg("user is disabled")
		render.RenderJSONError(w, "Account is disabled", "authn.login.disabled", http.StatusForbidden)
		return
	}

	sess := session.GetSessionFromRequest(r)
	sess.PlaceUserInSession(foundUser)

	log.Info().Str("username", foundUser.Username).Str("ip", trueip.Find(r)).Msg("successful passkey auth")

	err = session.WriteSession(w, r, sess)
	if err != nil {
		log.Error().Err(err).Msg("could not log user in")
		render.RenderJSONError(w, "Could not write session data", "authn.login.could_not_update_session", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, err = w.Write([]byte(`{"failed":false}`))
	if err != nil {
		log.Error().Caller(0).Err(err).Msg("could not write webauthn login finish to response")
	}
}

type keyInfo struct {
	ID           string
	LastUsed     string
	FriendlyName string
}

type manageWebAuthnParams struct {
	Keys []keyInfo
}

func toKeyInfo(cred user.Passkey) keyInfo {
	fName := ""
	if cred.FriendlyName != nil {
		fName = *cred.FriendlyName
	}

	lu := "Never"
	if cred.LastUsed != nil {
		lu = cred.LastUsed.Format(time.RFC1123)
	}

	return keyInfo{
		ID:           base64.RawURLEncoding.EncodeToString(cred.ID),
		FriendlyName: fName,
		LastUsed:     lu,
	}
}

func (e *Env) HandleRenderWebAuthnManage(w http.ResponseWriter, r *http.Request) {
	if viper.GetBool(config.KeyPasskeysDisabled) {
		log.Warn().Msg("attempted to get to passkey management with passkeys disabled")
		http.Error(w, "404 Not Found", http.StatusNotFound)
		return
	}

	u := session.GetUserFromRequest(r)
	if u == nil {
		http.Error(w, "you must be logged in for this", http.StatusForbidden)
		return
	}

	keyIDs := make([]string, len(u.StoredCredentials))
	for i := range u.StoredCredentials {
		id := base64.RawURLEncoding.EncodeToString(u.StoredCredentials[i].ID)
		keyIDs[i] = id
	}

	keys := make([]keyInfo, len(u.StoredCredentials))
	for i := range keys {
		keys[i] = toKeyInfo(u.StoredCredentials[i])
	}

	render.Render(w, "webauthn_manage.gohtml", &manageWebAuthnParams{
		Keys: keys,
	})
}

func generateAuthID() string {
	return base64.URLEncoding.EncodeToString(securecookie.GenerateRandomKey(32))
}

func getAuthID(r *http.Request) (string, error) {
	s := session.GetSessionFromRequest(r)

	authIDTemp := s.CustomData[authenticationIDSessionKey]
	if authIDTemp == nil {
		return "", fmt.Errorf("authn: getAuthID: no auth id in session")
	}

	authID, ok := authIDTemp.(string)
	if !ok {
		log.Warn().Type("auth_id_type", authIDTemp).Msg("auth id is not string")
		return "", fmt.Errorf("authn: getAuthID: auth id is not string")
	}

	return authID, nil
}

func (e *Env) HandleWebAuthnEditKey(w http.ResponseWriter, r *http.Request) {
	u := session.GetUserFromRequest(r)
	if u == nil {
		render.RenderHTMXCompatibleError(w, r, "You must be logged in to do this", "modify-error")
		return
	}

	kID := r.PathValue("keyId")

	ownsKey := false
	for _, curr := range u.StoredCredentials {
		idStr := base64.RawURLEncoding.EncodeToString(curr.ID)
		if idStr == kID {
			ownsKey = true
			break
		}
	}

	if !ownsKey {
		log.Warn().Str("username", u.Username).Str("key_id", kID).Msg("user attempted to modify key they did not own")
		render.RenderHTMXCompatibleError(w, r, fmt.Sprintf("Could not find key with id %s", kID), "modify-error")
		return
	}

	k, err := e.Database.FindKeyById(r.Context(), kID)
	if err != nil {
		log.Warn().Err(err).Str("key_id", kID).Msg("could not find key id")
		render.RenderHTMXCompatibleError(w, r, fmt.Sprintf("Could not find key with id %s", kID), "modify-error")
		return
	}

	ki := toKeyInfo(k)

	if r.Method == http.MethodDelete {
		err = e.Database.DeleteKey(r.Context(), kID)
		if err != nil {
			log.Error().Err(err).Str("key_id", kID).Msg("could not delete key")
			render.RenderHTMXCompatibleError(w, r, fmt.Sprintf("Could not delete key: %s", err.Error()), "modify-error")
			return
		}
	} else if r.Method == http.MethodPut {
		newName := strings.TrimSpace(r.FormValue("name"))
		var nn *string
		if newName != "" {
			nn = &newName
		}
		log.Info().Str("key_id", kID).Str("name", newName).Msg("should set name")
		err = e.Database.UpdateKeyName(r.Context(), kID, nn)
		if err != nil {
			log.Error().Err(err).Str("key_id", kID).Str("new_name", newName).Msg("could not update key")
			render.RenderHTMXCompatibleError(w, r, fmt.Sprintf("Could not modify key: %s", err.Error()), "modify-error")
			return
		}

		ki.FriendlyName = ""
		if newName != "" {
			ki.FriendlyName = newName
		}

		render.Render(w, "authn_key_row.gohtml", ki)
	} else if r.Method == http.MethodGet {

		if strings.HasSuffix(r.URL.Path, "/edit") {
			render.Render(w, "authn_key_edit_row.gohtml", ki)
			return
		} else {
			render.Render(w, "authn_key_row.gohtml", ki)
		}
	}
}

func (e *Env) GetEnrolledPasskeyKeyIDs(w http.ResponseWriter, r *http.Request) {
	u := session.GetUserFromRequest(r)
	if u == nil {
		render.RenderHTMXCompatibleError(w, r, "You must be logged in to do this", "modify-error")
		return
	}

	foundKeys := make([]string, 0)

	for _, curr := range u.StoredCredentials {
		foundKeys = append(foundKeys, base64.StdEncoding.EncodeToString(curr.ID))
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"keys": foundKeys,
	})
}
