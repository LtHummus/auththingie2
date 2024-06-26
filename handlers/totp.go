package handlers

import (
	"encoding/base32"
	"encoding/base64"
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
	enrollment "github.com/lthummus/auththingie2/totp"
	"github.com/lthummus/auththingie2/util"
)

const (
	totpEnrollmentTicketFieldName = "totp-enrollment-ticket"
	totpLoginTicketFieldName      = "totp-login-ticket"
)

type totpEnrollmentPageParams struct {
	CSRFField        template.HTML
	QRCodeDataURL    template.URL
	Error            string
	EnrollmentTicket string
}

type totpPromptParams struct {
	CSRFField   template.HTML
	Error       string
	LoginTicket string
}

func (e *Env) HandleTOTPValidation(w http.ResponseWriter, r *http.Request) {
	rawTicket := r.FormValue(totpLoginTicketFieldName)
	if rawTicket == "" {
		log.Warn().Msg("totp login page hit with no ticket")
		http.Error(w, "no login ticket in request", http.StatusBadRequest)
		return
	}

	ticket, err := enrollment.DecodeLoginTicket(rawTicket)
	if err != nil {
		log.Error().Err(err).Msg("could not decode login ticket")
		http.Error(w, "could not decode login ticket", http.StatusBadRequest)
		return
	}

	if r.Method == http.MethodGet {
		e.handleTotpPrompt(w, r, ticket, "")
	} else if r.Method == http.MethodPost {
		e.handleTotpValidate(w, r, ticket)
	} else {
		http.Error(w, "not found", http.StatusNotFound)
	}
}

func (e *Env) handleTotpPrompt(w http.ResponseWriter, r *http.Request, loginTicket enrollment.LoginTicket, errorMessage string) {
	encodedTicket, err := loginTicket.Encode()
	if err != nil {
		log.Error().Err(err).Msg("could not encode login ticket")
		http.Error(w, "could not encode login ticket", http.StatusInternalServerError)
		return
	}

	params := &totpPromptParams{
		CSRFField:   csrf.TemplateField(r),
		Error:       errorMessage,
		LoginTicket: encodedTicket,
	}

	render.Render(w, "totp_prompt.gohtml", params)
}

func (e *Env) handleTotpValidate(w http.ResponseWriter, r *http.Request, data enrollment.LoginTicket) {
	totpCode := strings.TrimSpace(r.FormValue("totp-code"))
	redirectURI := data.RedirectURI

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

	if user.Disabled {
		log.Warn().Str("ip", util.FindTrueIP(r)).Str("username", user.Username).Msg("attempted login of disabled account")
		e.handleTotpPrompt(w, r, data, "Account is disabled")
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
	encodedTicket := r.FormValue(totpEnrollmentTicketFieldName)
	if encodedTicket == "" {
		log.Warn().Msg("no ticket in request")
		http.Error(w, "no enrollment ticket in request", http.StatusBadRequest)
		return
	}

	enrollmentTicket, err := enrollment.DecodeEnrollmentTicket(encodedTicket)
	if err != nil {
		log.Error().Err(err).Msg("could not decode enrollment ticket")
		http.Error(w, "enrollment ticket is not decodable", http.StatusBadRequest)
		return
	}

	if enrollmentTicket.Expiration.Before(time.Now()) {
		e.renderSetupPage(w, r, "TOTP Enrollment Has Expired")
		return
	}

	submittedCode := strings.TrimSpace(r.FormValue("totp-code"))
	if submittedCode == "" {
		e.renderSetupPage(w, r, "TOTP Code Can Not Be Blank")
		return
	}

	valid := totp.Validate(submittedCode, enrollmentTicket.Seed)
	if !valid {
		e.renderSetupPage(w, r, "Incorrect TOTP Code")
		return
	}

	user := session.GetUserFromRequest(r)
	if user == nil {
		http.Error(w, "you must be logged in to do this", http.StatusUnauthorized)
		return
	}
	if user.Id != enrollmentTicket.UserID {
		log.Error().Str("our_user_id", user.Id).Str("ticket_user_id", enrollmentTicket.UserID).Msg("user mismatch on ticket")
		http.Error(w, "this is not your enrollment ticket", http.StatusForbidden)
		return
	}

	err = e.Database.UpdateTOTPSeed(r.Context(), user.Id, enrollmentTicket.Seed)
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

	var err error
	var secret []byte

	if oldTicket := r.FormValue(totpEnrollmentTicketFieldName); oldTicket != "" {
		var decoded enrollment.EnrollmentTicket
		decoded, err = enrollment.DecodeEnrollmentTicket(oldTicket)
		if err != nil {
			log.Warn().Err(err).Msg("enrollment ticket already exists, but ignoring")
		} else {
			if decoded.UserID != u.Id {
				log.Warn().Str("our_user_id", u.Id).Str("ticket_user_id", decoded.UserID).Msg("ticket and user mismatch, ignoring")
			} else if decoded.Expiration.Before(time.Now()) {
				log.Warn().Time("expiration", decoded.Expiration).Msg("ticket has expired, ignoring")
			} else {
				secret, err = base32.StdEncoding.DecodeString(decoded.Seed)
				if err != nil {
					log.Warn().Err(err).Msg("could not decode already packaged seed")
				}
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

	ticket := enrollment.GenerateEnrollmentTicket(u.Id, seed.Secret())
	encoded, err := ticket.Encode()
	if err != nil {
		log.Error().Err(err).Msg("could not generate enrollment ticket")
		http.Error(w, "could not generate enrollment ticket", http.StatusInternalServerError)
		return
	}

	qrDataURL := fmt.Sprintf("data:image/png;base64,%s", base64.StdEncoding.EncodeToString(pngBytes))

	log.Debug().Str("totp_secret", seed.Secret()).Msg("generated secret")

	render.Render(w, "totp_enrollment.gohtml", &totpEnrollmentPageParams{
		Error:     errorMessage,
		CSRFField: csrf.TemplateField(r),
		//#nosec G203 -- contents are entirely generated server side
		QRCodeDataURL:    template.URL(qrDataURL),
		EnrollmentTicket: encoded,
	})

}
