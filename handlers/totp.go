package handlers

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/gob"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/csrf"
	"github.com/pquerna/otp/totp"
	"github.com/rs/zerolog/log"
	"github.com/skip2/go-qrcode"

	"github.com/lthummus/auththingie2/middlewares/session"
	"github.com/lthummus/auththingie2/render"
	"github.com/lthummus/auththingie2/util"
)

const (
	TotpEnrollmentCustomDataKey = "totp_enrollment"
	TOTPPartialDataCustomKey    = "totp_validation"
	TotpEnrollmentValidityTime  = 7 * time.Minute
)

type totpEnrollment struct {
	Secret     string
	Expiration time.Time
}

type totpPartialAuthData struct {
	UserID     string
	Expiration time.Time
}

type totpEnrollmentPageParams struct {
	CSRFField     template.HTML
	QRCodeDataURL template.URL
	Error         string
}

type totpPromptParams struct {
	CSRFField   template.HTML
	Error       string
	RedirectURI string
}

func init() {
	gob.Register(totpEnrollment{})
	gob.Register(totpPartialAuthData{})
}

func generatePartialAuthData(userID string) *totpPartialAuthData {
	return &totpPartialAuthData{
		UserID:     userID,
		Expiration: time.Now().Add(TotpEnrollmentValidityTime),
	}
}

func (e *Env) HandleTOTPValidation(w http.ResponseWriter, r *http.Request) {
	sess := session.GetSessionFromRequest(r)

	partialAuthData, ok := sess.CustomData[TOTPPartialDataCustomKey].(totpPartialAuthData)
	if !ok {
		log.Warn().Msg("went to totp page with no totp partial auth data")
		http.Error(w, "login data not found", http.StatusBadRequest)
		return
	}

	if partialAuthData.Expiration.Before(time.Now()) {
		http.Error(w, "login has expired, please log in again", http.StatusBadRequest)
		return
	}

	if r.Method == http.MethodGet {
		e.handleTotpPrompt(w, r, &partialAuthData, "")
	} else if r.Method == http.MethodPost {
		e.handleTotpValidate(w, r, &partialAuthData)
	} else {
		http.Error(w, "not found", http.StatusNotFound)
	}
}

func (e *Env) handleTotpPrompt(w http.ResponseWriter, r *http.Request, data *totpPartialAuthData, errorMessage string) {
	params := &totpPromptParams{
		CSRFField:   csrf.TemplateField(r),
		Error:       errorMessage,
		RedirectURI: getRedirectURIFromRequest(r),
	}

	render.Render(w, "totp_prompt.gohtml", params)
}

func (e *Env) handleTotpValidate(w http.ResponseWriter, r *http.Request, data *totpPartialAuthData) {
	totpCode := strings.TrimSpace(r.FormValue("totp-code"))
	redirectURI := getRedirectURIFromRequest(r)

	user, err := e.Database.GetUserByGuid(r.Context(), data.UserID)
	if err != nil {
		log.Error().Err(err).Str("user_id", data.UserID).Msg("could not query user from database")
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}

	if user == nil {
		log.Error().Str("user_id", data.UserID).Msg("user not found for totp validation")
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}

	if user.TOTPSeed == nil {
		log.Error().Str("user_id", data.UserID).Msg("tried to validate totp for a user that does not have it enabled")
		http.Error(w, "tried to validate totp for user that does not have it enabled", http.StatusInternalServerError)
		return
	}

	codeOK := totp.Validate(totpCode, *user.TOTPSeed)
	if !codeOK {
		e.handleTotpPrompt(w, r, data, "Incorrect TOTP Code")
		return
	}

	sess := session.GetSessionFromRequest(r)
	sess.PlaceUserInSession(user)

	err = session.WriteSession(w, r, sess)
	if err != nil {
		log.Error().Err(err).Msg("could not log user in")
		http.Error(w, "could not write session data", http.StatusInternalServerError)
		return
	}

	log.Info().Str("ip", util.FindTrueIP(r)).Str("username", user.Username).Msg("successful login")
	if redirectURI == "" {
		redirectURI = "/"
	}
	http.Redirect(w, r, redirectURI, http.StatusFound)
}

func (e *Env) HandleTOTPSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		e.renderSetupPage(w, r, "")
	} else if r.Method == http.MethodPost {
		e.handleTotpEnableSubmission(w, r)
	} else {
		http.Error(w, "not found", http.StatusNotFound)
	}

}

func (e *Env) HandleTOTPDisable(w http.ResponseWriter, r *http.Request) {
	u := session.GetUserFromRequest(r)
	if u == nil {
		http.Error(w, "you must be logged in to do this", http.StatusUnauthorized)
		return
	}

	if !u.TOTPEnabled() {
		render.RenderError(w, "totp-delete-error", "totp is already disabled")
		return
	}

	u.TOTPSeed = nil
	err := e.Database.SaveUser(r.Context(), u)
	if err != nil {
		log.Error().Err(err).Str("user_id", u.Id).Msg("could not save updated user to database")
		render.RenderError(w, "totp-delete-error", "could not save updated user to database")
		return
	}

	render.Render(w, "totp_status_fragment.gohtml", map[string]any{
		"User": u,
	})
}

func (e *Env) handleTotpEnableSubmission(w http.ResponseWriter, r *http.Request) {
	sess := session.GetSessionFromRequest(r)

	totpEnrollmentData := sess.CustomData[TotpEnrollmentCustomDataKey].(totpEnrollment)

	if totpEnrollmentData.Expiration.Before(time.Now()) {
		e.renderSetupPage(w, r, "TOTP Enrollment Has Expired")
		return
	}

	submittedCode := strings.TrimSpace(r.FormValue("totp-code"))
	if submittedCode == "" {
		e.renderSetupPage(w, r, "TOTP Code Can Not Be Blank")
		return
	}

	valid := totp.Validate(submittedCode, totpEnrollmentData.Secret)
	if !valid {
		e.renderSetupPage(w, r, "Incorrect TOTP Code")
		return
	}

	user := session.GetUserFromRequest(r)
	if user == nil {
		http.Error(w, "you must be logged in to do this", http.StatusUnauthorized)
		return
	}

	err := e.Database.UpdateTOTPSeed(r.Context(), user.Id, totpEnrollmentData.Secret)
	if err != nil {
		log.Error().Err(err).Str("username", user.Username).Msg("could not persist totp secret")
		http.Error(w, "could not update totp secret in database", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/edit_self", http.StatusFound)
}

func (e *Env) renderSetupPage(w http.ResponseWriter, r *http.Request, errorMessage string) {
	u := session.GetUserFromRequest(r)
	if u == nil {
		http.Error(w, "you must be logged in to do this", http.StatusUnauthorized)
		log.Warn().Msg("attempted to set totp while not logged in")
		return
	}

	if u.TOTPEnabled() {
		http.Error(w, "you already have totp enabled", http.StatusBadRequest)
		return
	}
	sess := session.GetSessionFromRequest(r)

	var err error
	var secret []byte

	if oldEnrollment, ok := sess.CustomData[TotpEnrollmentCustomDataKey].(*totpEnrollment); ok {
		if oldEnrollment.Expiration.After(time.Now()) {
			secret, err = base32.StdEncoding.DecodeString(oldEnrollment.Secret)
			if err != nil {
				log.Warn().Err(err).Msg("could not decode already valid totp secret")
			}
		}
	}

	seed, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "AuthThingie", // todo: change to domain/url?
		AccountName: u.Username,
		Secret:      secret,
	})
	if err != nil {
		log.Error().Err(err).Msg("could not generate totp seed")
		http.Error(w, "could not generate totp seed", http.StatusInternalServerError)
		return
	}

	pngBytes, err := qrcode.Encode(seed.URL(), qrcode.High, 500)
	if err != nil {
		log.Error().Err(err).Msg("could not generate totp qr code")
		http.Error(w, "could not generate totp qr code", http.StatusInternalServerError)
		return
	}

	qrDataURL := fmt.Sprintf("data:image/png;base64,%s", base64.StdEncoding.EncodeToString(pngBytes))

	sess.CustomData[TotpEnrollmentCustomDataKey] = &totpEnrollment{
		Secret:     seed.Secret(),
		Expiration: time.Now().Add(TotpEnrollmentValidityTime),
	}
	err = session.WriteSession(w, r, sess)
	if err != nil {
		log.Error().Err(err).Msg("could not update session with totp enrollment data")
		http.Error(w, "could not update session with totp enrollment data", http.StatusInternalServerError)
		return
	}

	log.Debug().Str("totp_secret", seed.Secret()).Msg("generated secret")

	render.Render(w, "totp_enrollment.gohtml", &totpEnrollmentPageParams{
		Error:     errorMessage,
		CSRFField: csrf.TemplateField(r),
		//#nosec G203 -- contents are entirely generated server side
		QRCodeDataURL: template.URL(qrDataURL),
	})

}
