package handlers

import (
	"net/http"

	"github.com/spf13/viper"

	"github.com/lthummus/auththingie2/internal/config"
	"github.com/lthummus/auththingie2/internal/db"
	"github.com/lthummus/auththingie2/internal/loginlimit"
	"github.com/lthummus/auththingie2/internal/middlewares/securityheaders"
	"github.com/lthummus/auththingie2/internal/middlewares/session"
	"github.com/lthummus/auththingie2/internal/render"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/rs/zerolog/log"

	"github.com/lthummus/auththingie2/internal/rules"
)

type Env struct {
	Database     db.DB
	Analyzer     rules.Analyzer
	WebAuthn     *webauthn.WebAuthn
	LoginLimiter loginlimit.LoginLimiter
}

const (
	loginMessageNotLoggedIn             = "not_logged_in"
	loginMessageRuleRequiresSecondLogin = "reauth_required"
)

var validLoginMessages = map[string]string{
	loginMessageNotLoggedIn:             "You are not logged in. Please log in.",
	loginMessageRuleRequiresSecondLogin: "This matched rule requires you to login again",
}

func (e *Env) BuildRouter() http.Handler {
	log.Info().Msg("setting up listeners")

	mux := http.NewServeMux()

	mux.HandleFunc("/forward", e.HandleCheckRequest)
	mux.HandleFunc("/auth", e.HandleCheckRequest)
	mux.HandleFunc("/forbidden", e.HandleNotAllowed)
	mux.HandleFunc("/disabled", e.HandleAccountDisabled)

	mux.HandleFunc("/debug", e.HandleDebug)

	mux.HandleFunc("/login", e.HandleLoginPage)
	mux.HandleFunc("/logout", e.HandleLogout)

	mux.HandleFunc("/totp", e.HandleTOTPValidation)
	mux.HandleFunc("/enable_totp", e.HandleTOTPSetup)
	mux.HandleFunc("/disable_totp", e.HandleTOTPDisable)

	mux.HandleFunc("GET /admin/users/create", e.HandleCreateUserPage)
	mux.HandleFunc("POST /admin/users/create", e.HandleCreateUserPost)
	mux.HandleFunc("GET /admin/users/{userId}", e.RenderUserEditPage)
	mux.HandleFunc("POST /admin/users/{userId}", e.HandleEditUserSubmission)
	mux.HandleFunc("POST /admin/users/{userId}/totp_unenroll", e.HandleAdminUnenrollTOTP)
	mux.HandleFunc("POST /admin/users/{userId}/delete", e.HandleUserDelete)
	mux.HandleFunc("PATCH /admin/users/{userId}/tags", e.HandleUserPatchTagsModification)
	mux.HandleFunc("DELETE /admin/users/{userId}/tags/{tag}", e.HandleUserTagDelete)
	mux.HandleFunc("PATCH /admin/users/{userId}/disable", e.HandleUserDisableEnable)
	mux.HandleFunc("GET /admin/ruletest", e.HandleTestRule)
	mux.HandleFunc("GET /admin/notices", e.ShowNotices)
	mux.HandleFunc("GET /admin", e.HandleAdminPage)

	mux.HandleFunc("GET /edit_self", e.HandleSelfConfigGet)
	mux.HandleFunc("GET /edit_self/password", e.HandleSelfConfigPasswordGet)
	mux.HandleFunc("POST /edit_self/password", e.HandleSelfConfigPasswordPost)

	mux.HandleFunc("/webauthn/manage", e.HandleRenderWebAuthnManage)
	mux.HandleFunc("/webauthn/register", e.HandleWebAuthnBeginRegistration)
	mux.HandleFunc("/webauthn/finishregister", e.HandleWebAuthnFinishRegistration)
	mux.HandleFunc("/webauthn/discover", e.HandleWebAuthnBeginDiscoverableLogin)
	mux.HandleFunc("/webauthn/finishdiscover", e.HandleWebAuthnFinishDiscoverableLogin)
	mux.HandleFunc("/webauthn/keys/{keyId}", e.HandleWebAuthnEditKey)
	mux.HandleFunc("/webauthn/keys/{keyId}/edit", e.HandleWebAuthnEditKey)
	mux.HandleFunc("/webauthn/keys", e.GetEnrolledPasskeyKeyIDs)

	mux.Handle("/static/", render.StaticFSHandler())

	mux.HandleFunc("/", e.HandleIndex)

	sessionMiddleware := session.NewMiddleware(mux, e.Database)

	cop := http.NewCrossOriginProtection()
	cop.AddInsecureBypassPattern("/forward")
	cop.AddInsecureBypassPattern("/auth")
	cop.AddInsecureBypassPattern("/forbidden")
	cop.AddInsecureBypassPattern("/disabled")

	handler := cop.Handler(sessionMiddleware)

	if !viper.GetBool(config.DisableSecurityHeaders) {
		handler = securityheaders.NewSecurityHeadersMiddleware(handler)
	} else {
		log.Warn().Msg("not enabling security headers")
	}

	return handler
}
