package handlers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/lthummus/auththingie2/internal/argon"
	"github.com/lthummus/auththingie2/internal/config"
	"github.com/lthummus/auththingie2/internal/loginlimit"
	"github.com/lthummus/auththingie2/internal/middlewares/session"
	"github.com/lthummus/auththingie2/internal/notices"
	"github.com/lthummus/auththingie2/internal/pwmigrate"
	"github.com/lthummus/auththingie2/internal/render"
	"github.com/lthummus/auththingie2/internal/totp"
	"github.com/lthummus/auththingie2/internal/trueip"

	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

// fakeArgonHash is a hash of an arbitrary string that we can check against later when logging in with a user that does
// not exist. We want a valid argon hash to check against so we don't leak user existence via timing. We generate one
// here to use because we want to generate one that uses the configured argon parameters
var fakeArgonHash string

func init() {
	var err error
	fakeArgonHash, err = argon.GenerateFromPassword("hello world this is my fake password")
	if err != nil {
		log.Fatal().Err(err).Msg("could not generate fake hash -- is your argon configuration ok?")
	}
}

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

func (e *Env) handleLoginFailureAndGetError(accountKey string, sourceIPKey string) string {
	errorMessage := "Invalid Username or Password"

	accountLocked := false

	remaining, err := e.LoginLimiter.MarkFailedAttempt(accountKey)
	if errors.Is(err, loginlimit.ErrAccountLocked) {
		accountLocked = true
		errorMessage = "Invalid Username or Password. This account has been locked due to multiple failures"
	} else if err != nil {
		log.Warn().Err(err).Str("account_key", accountKey).Msg("error when marking login failure")
		errorMessage = "An error happened attempting to log you in"
	} else {
		errorMessage = fmt.Sprintf("Invalid Username or Password. You have %d more attempts before the account is temporarily locked", remaining)
	}

	// mark IP address as failed as well, but slightly different semantics for errors
	remaining, err = e.LoginLimiter.MarkFailedAttempt(sourceIPKey)
	if errors.Is(err, loginlimit.ErrAccountLocked) && !accountLocked {
		errorMessage = "Invalid Username or Password. This IP address has failed login too many times. Try again later"
	} else if err != nil && !errors.Is(err, loginlimit.ErrAccountLocked) {
		log.Warn().Err(err).Str("source_ip_key", sourceIPKey).Msg("error when marking login failure")
		errorMessage = "An error happened attempting to log you in"
	}

	return errorMessage
}

func (e *Env) handleLoginPost(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")
	redirectURL := getRedirectURIFromRequest(r)

	sourceIPKey := fmt.Sprintf("ip|%s", trueip.Find(r))
	accountKey := fmt.Sprintf("username|%s", username)

	if e.LoginLimiter.IsAccountLocked(sourceIPKey) {
		render.Render(w, "login.gohtml", &loginPageParams{
			Error:          "This IP has had too many login failures recently. Try again later",
			RedirectURI:    redirectURL,
			EnablePasskeys: !viper.GetBool(config.KeyPasskeysDisabled),
		})
		return
	}

	if e.LoginLimiter.IsAccountLocked(accountKey) {
		render.Render(w, "login.gohtml", &loginPageParams{
			Error:          "This account is temporarily locked",
			RedirectURI:    redirectURL,
			EnablePasskeys: !viper.GetBool(config.KeyPasskeysDisabled),
		})
		return
	}

	u, err := e.Database.GetUserByUsername(r.Context(), username)
	if err != nil {
		log.Error().Err(err).Msg("could not query for user")
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}

	if u == nil {
		log.Error().Str("ip", trueip.Find(r)).Msg("invalid login")

		// do an argon validation even though it won't work because we want to consume some time so the existence of a user can't
		// be detected via timing
		_ = argon.ValidatePassword("aaaaaaaaaa", fakeArgonHash)

		errorMessage := e.handleLoginFailureAndGetError(accountKey, sourceIPKey)

		render.Render(w, "login.gohtml", &loginPageParams{
			Error:          errorMessage,
			RedirectURI:    redirectURL,
			EnablePasskeys: !viper.GetBool(config.KeyPasskeysDisabled),
		})
		return
	}

	err = u.CheckPassword(password)
	if err != nil {
		log.Error().Str("ip", trueip.Find(r)).Err(err).Msg("invalid login")

		errorMessage := e.handleLoginFailureAndGetError(accountKey, sourceIPKey)

		render.Render(w, "login.gohtml", &loginPageParams{
			Error:          errorMessage,
			RedirectURI:    redirectURL,
			EnablePasskeys: !viper.GetBool(config.KeyPasskeysDisabled),
		})
		return
	}

	if argon.NeedsMigration(u.PasswordHash) {
		go func() {
			pwmigrate.MigrateUser(context.Background(), u, password, e.Database)
		}()
	}

	e.LoginLimiter.MarkSuccessfulAttempt(sourceIPKey)
	e.LoginLimiter.MarkSuccessfulAttempt(accountKey)

	if u.TOTPEnabled() {
		loginTicket := totp.GenerateLoginTicket(u.Id, redirectURL)
		e.handleTotpPrompt(w, r, loginTicket, "")
		return
	}

	if u.Disabled {
		log.Warn().Str("ip", trueip.Find(r)).Str("username", u.Username).Msg("login of disabled account")
		render.Render(w, "login.gohtml", &loginPageParams{
			Error:          "Account is disabled",
			RedirectURI:    redirectURL,
			EnablePasskeys: !viper.GetBool(config.KeyPasskeysDisabled),
		})
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
