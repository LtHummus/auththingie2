package handlers

import (
	"context"
	"html/template"
	"net/http"

	"github.com/gorilla/csrf"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"

	"github.com/lthummus/auththingie2/argon"
	"github.com/lthummus/auththingie2/config"
	"github.com/lthummus/auththingie2/middlewares/session"
	"github.com/lthummus/auththingie2/pwmigrate"
	"github.com/lthummus/auththingie2/render"
	"github.com/lthummus/auththingie2/totp"
	"github.com/lthummus/auththingie2/util"
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
	CSRFField      template.HTML
	CSRFToken      string
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
	if formMessage := r.FormValue(loginMessageParam); formMessage != "" {
		message = formMessage
	}

	if queryMessage := r.URL.Query().Get(loginMessageParam); queryMessage != "" {
		message = queryMessage
	}

	return message
}

func (e *Env) HandleLoginPage(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		e.handleLoginPost(w, r)
		return
	} else if r.Method == http.MethodGet {
		render.Render(w, "login.gohtml", &loginPageParams{
			CSRFField:      csrf.TemplateField(r),
			CSRFToken:      csrf.Token(r),
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

	if e.AccountLocker != nil && e.AccountLocker.IsUserLocked(username) {
		render.Render(w, "login.gohtml", &loginPageParams{
			CSRFField:      csrf.TemplateField(r),
			CSRFToken:      csrf.Token(r),
			Error:          "Account is locked due to failures",
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
		log.Error().Str("ip", util.FindTrueIP(r)).Msg("invalid login")

		// do an argon validation even though it won't work because we want to consume some time so the existence of a user can't
		// be detected via timing
		_ = argon.ValidatePassword("aaaaaaaaaa", fakeArgonHash)
		if e.AccountLocker != nil {
			e.AccountLocker.RecordFailure(username)
		}

		render.Render(w, "login.gohtml", &loginPageParams{
			CSRFField:      csrf.TemplateField(r),
			CSRFToken:      csrf.Token(r),
			Error:          "Invalid Username or Password",
			RedirectURI:    redirectURL,
			EnablePasskeys: !viper.GetBool(config.KeyPasskeysDisabled),
		})
		return
	}

	err = u.CheckPassword(password)
	if err != nil {
		log.Error().Str("ip", util.FindTrueIP(r)).Err(err).Msg("invalid login")
		if e.AccountLocker != nil {
			e.AccountLocker.RecordFailure(username)
		}

		render.Render(w, "login.gohtml", &loginPageParams{
			CSRFField:      csrf.TemplateField(r),
			CSRFToken:      csrf.Token(r),
			Error:          "Invalid Username or Password",
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

	if u.TOTPEnabled() {
		loginTicket := totp.GenerateLoginTicket(u.Id, redirectURL)
		e.handleTotpPrompt(w, r, loginTicket, "")
		return
	}

	if u.Disabled {
		log.Warn().Str("ip", util.FindTrueIP(r)).Str("username", u.Username).Msg("login of disabled account")
		render.Render(w, "login.gohtml", &loginPageParams{
			CSRFField:      csrf.TemplateField(r),
			CSRFToken:      csrf.Token(r),
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

	log.Info().Str("ip", util.FindTrueIP(r)).Str("username", u.Username).Msg("successful login")

	if redirectURL == "" {
		redirectURL = "/"
	}

	http.Redirect(w, r, redirectURL, http.StatusFound)
}
