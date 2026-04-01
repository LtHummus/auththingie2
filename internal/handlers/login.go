package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/lthummus/auththingie2/internal/config"
	"github.com/lthummus/auththingie2/internal/middlewares/session"
	"github.com/lthummus/auththingie2/internal/notices"
	"github.com/lthummus/auththingie2/internal/pwvalidate"
	"github.com/lthummus/auththingie2/internal/render"
	"github.com/lthummus/auththingie2/internal/totp"
	"github.com/lthummus/auththingie2/internal/trueip"

	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

type loginPageParams struct {
	RedirectURI    string
	Error          string
	Message        string
	EnablePasskeys bool
}

func getRedirectURIFromRequest(r *http.Request) string {
	redirectURI := ""
	if formRedirect := r.FormValue(redirectURLParam); formRedirect != "" {
		redirectURI = formRedirect
	}

	if queryRedirect := r.URL.Query().Get(redirectURLParam); queryRedirect != "" {
		redirectURI = queryRedirect
	}

	log.Debug().Str("redirect_uri", redirectURI).Msg("pulled redirect uri from request")

	return redirectURI
}

func getMessageFromRequest(r *http.Request) string {
	message := ""
	if formMessage := r.PostFormValue(loginMessageParam); formMessage != "" {
		message = formMessage
	}

	if queryMessage := r.URL.Query().Get(loginMessageParam); queryMessage != "" {
		if realMessage := validLoginMessages[queryMessage]; realMessage != "" {
			message = realMessage
		}
	}

	return message
}

func (e *Env) HandleLoginPage(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		e.handleLoginPost(w, r)
		return
	} else if r.Method == http.MethodGet {
		render.Render(w, "login.gohtml", &loginPageParams{
			RedirectURI:    getRedirectURIFromRequest(r),
			Message:        getMessageFromRequest(r),
			EnablePasskeys: !viper.GetBool(config.KeyPasskeysDisabled),
		})
	} else {
		http.Error(w, "not found", http.StatusNotFound)
	}
}

func (e *Env) handleLoginPost(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")
	redirectURL := getRedirectURIFromRequest(r)

	u, err := e.PasswordValidator.Validate(r.Context(), username, password, trueip.Find(r))
	if err != nil {
		if _, ok := errors.AsType[pwvalidate.PasswordValidatorError](err); !ok {
			// if there's not an auth error, just render something generic
			render.Render(w, "login.gohtml", &loginPageParams{
				Error:          "Server side error happened. Try again?",
				RedirectURI:    redirectURL,
				EnablePasskeys: !viper.GetBool(config.KeyPasskeysDisabled),
			})
			return
		}

		// can't use errors.AsType in a switch statement, so we have this instead :(
		if _, ok := errors.AsType[*pwvalidate.AccountLockedError](err); ok {
			render.Render(w, "login.gohtml", &loginPageParams{
				Error:          "Invalid username or password. This account has been locked due to multiple failures",
				RedirectURI:    redirectURL,
				EnablePasskeys: !viper.GetBool(config.KeyPasskeysDisabled),
			})
			return
		} else if _, ok := errors.AsType[*pwvalidate.IPBlockedError](err); ok {
			render.Render(w, "login.gohtml", &loginPageParams{
				Error:          "This IP has had too many login failures recently. Try again later",
				RedirectURI:    redirectURL,
				EnablePasskeys: !viper.GetBool(config.KeyPasskeysDisabled),
			})
			return
		} else if iupe, ok := errors.AsType[*pwvalidate.InvalidUsernamePasswordError](err); ok {
			render.Render(w, "login.gohtml", &loginPageParams{
				Error:          fmt.Sprintf("Invalid username or password. You have %d more attempts before the account is temporarily locked", iupe.AccountRemainingBeforeLocked),
				RedirectURI:    redirectURL,
				EnablePasskeys: !viper.GetBool(config.KeyPasskeysDisabled),
			})
			return
		} else if _, ok := errors.AsType[*pwvalidate.AccountDisabledError](err); ok {
			if u != nil && u.TOTPEnabled() {
				// do nothing, fall through so we do the disabled check post-TOTP
			} else {
				render.Render(w, "login.gohtml", &loginPageParams{
					Error:          "Account is disabled",
					RedirectURI:    redirectURL,
					EnablePasskeys: !viper.GetBool(config.KeyPasskeysDisabled),
				})
				return
			}
		} else {
			// adding this branch just in case I add an auth error and forget to handle it here
			render.Render(w, "login.gohtml", &loginPageParams{
				Error:          "Server side error happened. Try again?",
				RedirectURI:    redirectURL,
				EnablePasskeys: !viper.GetBool(config.KeyPasskeysDisabled),
			})
			return
		}
	}

	if u.TOTPEnabled() {
		loginTicket := totp.GenerateLoginTicket(u.Id, redirectURL)
		e.handleTotpPrompt(w, r, loginTicket, "")
		return
	}

	sess := session.GetSessionFromRequest(r)
	sess.PlaceUserInSession(u)

	err = session.WriteSession(w, r, sess)
	if err != nil {
		log.Error().Err(err).Msg("could not log user in")
		http.Error(w, "could not write session data", http.StatusInternalServerError)
		return
	}

	log.Info().Str("ip", trueip.Find(r)).Str("username", u.Username).Msg("successful login")

	if redirectURL == "" {
		redirectURL = "/"
	}

	if u.Admin && len(notices.GetMessages()) > 0 {
		v := url.Values{}
		v.Set("redirect_uri", redirectURL)
		http.Redirect(w, r, fmt.Sprintf("/admin/notices?%s", v.Encode()), http.StatusFound)
	} else {
		http.Redirect(w, r, redirectURL, http.StatusFound)
	}

}
